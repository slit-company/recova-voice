from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import socket
import sys
import threading
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("g008_runner", ROOT / "run-g008-live-smoke.py")
assert SPEC and SPEC.loader
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

D = "a" * 64
REGISTER_OPERATION_UUID = "33333333-3333-4333-8333-333333333333"
UNREGISTER_OPERATION_UUID = "44444444-4444-4444-8444-444444444444"
STAGE_UUIDS = {
    "register": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "outbound_call": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "inbound_call": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    "unregister": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
}
ATTESTATION_PRIVATE_KEY = ec.derive_private_key(1, ec.SECP256R1())


@pytest.fixture(autouse=True)
def signed_authority_stub(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(runner, "load_execution_key", lambda: b"x" * 32)
    attestation_public = ATTESTATION_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path = tmp_path / "registration-attestation-public.der"
    public_path.write_bytes(attestation_public)
    public_path.chmod(0o444)
    monkeypatch.setattr(runner, "REGISTRATION_ATTESTATION_PUBLIC_KEY_PATH", public_path)

    def unwrap(_self, receipt, *, kind, expected):
        assert receipt["kind"] == kind
        payload = receipt["payload"]
        assert all(payload.get(key) == value for key, value in expected.items())
        return payload

    monkeypatch.setattr(runner.Runner, "_signed_payload", unwrap)


def config(tmp_path: Path) -> runner.Config:
    return runner.Config(
        organization_id=7,
        seal="11111111-1111-4111-8111-111111111111",
        nonce_digest=D,
        candidate_digest="b" * 64,
        gate_digest="c" * 64,
        destination_digest="d" * 64,
        envelope_uuid="22222222-2222-4222-8222-222222222222",
        request_digest="e" * 64,
        reserved_did_digest="6" * 64,
        reserved_caller_digest="7" * 64,
        policy_digest="8" * 64,
        live_start="2026-07-18T01:00:00Z",
        live_end="2026-07-18T01:04:00Z",
        account_id="account-1",
        application_id="application-1",
        run_id="run-1",
        attempt_id="attempt-1",
        authority_deadline="2026-07-18T01:01:00Z",
        idempotency_key="g008-once",
        route_evidence_handle="route-evidence-handle-v1",
        route_profile_digest="9" * 64,
        request_mode="diagnostic",
        answer_hook_url="https://hooks.invalid/answer",
        status_hook_url="https://hooks.invalid/status",
        execution_bundle_path=tmp_path / "execution-bundle.json",
    )


class FakeBarrier:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def wait(self, action: str, _deadline: float) -> None:
        self.calls.append(action)


class FakeSecrets:
    def __init__(self) -> None:
        self.erased = 0
        self.paths: dict[str, str] = {}
        for name, value in (("sip-username", b"caller"), ("owned-target", b"target")):
            descriptor, path = tempfile.mkstemp()
            os.write(descriptor, value)
            os.close(descriptor)
            os.chmod(path, 0o600)
            self.paths[name] = path

    def put(self, name: str, _value: bytes) -> str:
        return f"/tmp/{name}"

    def erase(self) -> None:
        self.erased += 1
        for path in self.paths.values():
            Path(path).unlink(missing_ok=True)


class FakeBroker:
    def __init__(self, *, fail_operation: str | None = None) -> None:
        self.proofs: list[dict] = []
        self.deadlines: list[float | None] = []
        self.fail_operation = fail_operation
        self.attestation_binding: tuple[str, str] | None = None

    def configure_attestation(self, key_id: str, public_key_sha256: str) -> None:
        self.attestation_binding = (key_id, public_key_sha256)

    def consume(self, proof: dict, deadline: float | None = None) -> dict:
        self.proofs.append(proof)
        self.deadlines.append(deadline)
        if proof["operation_kind"] == self.fail_operation:
            raise runner.RunnerError("broker failed")
        return {
            "status": "finalized",
            "registration_consumption": {
                "registration_gate_id": proof["registration_gate_id"],
                "operation_uuid": proof["operation_uuid"],
                "operation_kind": proof["operation_kind"],
                "request_digest": proof["request_digest"],
                "candidate_digest": proof["candidate_digest"],
                "gate_envelope_digest": proof["gate_envelope_digest"],
                "nonce_digest": proof["execution_nonce_digest"],
                "prior_register_gate_id": proof["prior_register_gate_id"],
                "prior_register_operation_uuid": proof["prior_register_operation_uuid"],
                "state": "started",
                "challenged": True,
                "transaction_count": 1,
                "retry_count": 0,
                "concurrency_count": 1,
            },
            "opaque_execution_attestation": "opaque-registration-attestation",
        }


class FakeApi:
    def __init__(
        self,
        *,
        fail_at: str | set[str] | None = None,
        fail_registration_operation: str | None = None,
        recovered: bool = False,
        fail_once: bool = False,
    ) -> None:
        self.calls: list[tuple[str, dict, bool]] = []
        self.deadlines: list[tuple[str, dict, float | None]] = []
        self.fail_at = {fail_at} if isinstance(fail_at, str) else (fail_at or set())
        self.fail_registration_operation = fail_registration_operation
        self.recovered = recovered
        self.fail_once = fail_once
        self.failed_paths: set[str] = set()

    @staticmethod
    def signed(kind: str, payload: dict) -> dict:
        return {"kind": kind, "payload": {"kind": kind, **payload}}

    def post(
        self,
        path: str,
        payload: dict,
        *,
        facade: bool = False,
        deadline: float | None = None,
    ) -> dict:
        self.deadlines.append((path, payload, deadline))
        self.calls.append((path, payload, facade))
        if path in self.fail_at or (
            path == "/registration/begin"
            and payload["operation_kind"] == self.fail_registration_operation
        ):
            if not self.fail_once or path not in self.failed_paths:
                self.failed_paths.add(path)
                raise runner.RunnerError("simulated")
        if path == "/execution/nonce/consume":
            return self.signed("nonce_consumption", {**payload, "state": "consumed", "pre_existing": False})
        if path == "/execution/seal":
            public_der = ATTESTATION_PRIVATE_KEY.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return self.signed("execution_seal", {
                **payload,
                "state": "sealed",
                "pre_existing": False,
                "registration_attestation_key_id": "registration-attestation-v1",
                "registration_attestation_public_key_sha256": hashlib.sha256(public_der).hexdigest(),
            })
        if path == "/execution/stage/start":
            stage = payload["stage"]
            return self.signed(
                "stage_start",
                {**payload, "stage_uuid": STAGE_UUIDS[stage], "state": "started", "recovered": self.recovered},
            )
        if path == "/execution/stage/status":
            stage = payload["stage"]
            receipt = {
                **payload,
                "stage_uuid": STAGE_UUIDS[stage],
                "state": "succeeded",
                "terminal_class": {
                    "register": "registered",
                    "outbound_call": "call_completed",
                    "inbound_call": "inbound_bound",
                    "unregister": "unregistered",
                }[stage],
            }
            if stage in {"register", "unregister"}:
                receipt.update(
                    registration_gate_id=9,
                    registration_operation_uuid=(
                        REGISTER_OPERATION_UUID if stage == "register" else UNREGISTER_OPERATION_UUID
                    ),
                )
            else:
                started = 1_000 if stage == "outbound_call" else 3_000
                receipt.update(
                    provider_call_id_digest=("1" if stage == "outbound_call" else "2") * 64,
                    status_artifact_digest="3" * 64,
                    cdr_artifact_digest="4" * 64,
                    human_rx_artifact_digest="5" * 64,
                    human_rx_acknowledgement_artifact_digest="6" * 64,
                    human_tx_artifact_digest="7" * 64,
                    human_tx_acknowledgement_artifact_digest="8" * 64,
                    started_monotonic_ms=started,
                    ended_monotonic_ms=started + 1_000,
                    retry_count=0,
                    concurrency_count=1,
                    billed_duration_ms=900,
                    human_rx_duration_ms=500,
                    human_rx_acknowledgement="redacted_heard",
                    human_tx_duration_ms=400,
                    human_tx_acknowledgement="redacted_spoke",
                    terminal_status="terminal",
                )
            return self.signed("stage_status", receipt)
        if path == "/registration/begin":
            operation = payload["operation_kind"]
            return {
                "operation_kind": operation,
                "opaque_authorization": f"opaque-{operation}",
                "registration_gate_id": 9,
                "operation_uuid": REGISTER_OPERATION_UUID if operation == "register" else UNREGISTER_OPERATION_UUID,
            }
        if path == "/registration/finalize":
            authorization = next(
                item for prior_path, item, _ in reversed(self.calls)
                if prior_path == "/registration/begin"
            )
            operation = authorization["operation_kind"]
            return {
                "registration_gate_id": 9,
                "operation_uuid": (
                    REGISTER_OPERATION_UUID
                    if operation == "register"
                    else UNREGISTER_OPERATION_UUID
                ),
                "operation_kind": operation,
                "outcome": "succeeded",
                "recovered": False,
            }
        if path in {
            runner.OUTBOUND_ROUTE_TEMPLATE.format(account_id="account-1"),
            runner.INBOUND_ROUTE,
        }:
            return {"context": {"redacted_context_id": path.rsplit("/", 1)[-1]}}
        if path == "/v1/g008/calls/hangup":
            context_digest = hashlib.sha256(runner.canonical(payload["context"])).hexdigest()
            return self.signed("hangup", {**config_binding(payload), "context_digest": context_digest, "state": "terminated"})
        if path == "/containment":
            context_digest = hashlib.sha256(runner.canonical(payload["context"])).hexdigest()
            return self.signed("context_containment", {**config_binding(payload), "context_digest": context_digest, "state": "contained"})
        if path == "/execution/contain":
            return self.signed("execution_containment", {**config_binding(payload), "state": "contained"})
        if path == "/execution/finalize-evidence":
            return self.signed("final_execution_evidence", {**payload, "state": "completed"})
        raise AssertionError(path)


def config_binding(payload: dict) -> dict:
    keys = {
        "organization_id", "execution_seal_uuid", "execution_nonce_digest",
        "candidate_digest", "gate_envelope_digest",
    }
    return {key: payload[key] for key in keys}


def test_exact_four_stages_two_calls_and_two_broker_transactions(tmp_path: Path) -> None:
    api = FakeApi()
    broker = FakeBroker()
    barrier = FakeBarrier()
    subject = runner.Runner(config(tmp_path), api, barrier, FakeSecrets(), broker)

    subject.run()

    starts = [payload for path, payload, _ in api.calls if path == "/execution/stage/start"]
    assert [(item["stage"], item["ordinal"]) for item in starts] == list(runner.STAGES)
    traffic = [
        payload for path, payload, _ in api.calls
        if path in {
            runner.OUTBOUND_ROUTE_TEMPLATE.format(account_id="account-1"),
            runner.INBOUND_ROUTE,
        }
    ]
    assert len(traffic) == 2
    inbound = traffic[1]
    assert inbound["retry_count"] == 0
    assert inbound["concurrency_count"] == 1
    assert inbound["call_deadline_seconds"] == 60
    assert subject.provider_call_attempts == 2
    assert subject.contingency_used is False
    assert traffic[0]["time_limit_seconds"] == 60
    assert barrier.calls == ["ack_outbound", "ack_inbound"]
    assert [proof["operation_kind"] for proof in broker.proofs] == ["register", "unregister"]
    assert not [path for path, _, _ in api.calls if path == "/registration/consume"]
    assert not [path for path, _, _ in api.calls if path == "/registration/finalize"]
    assert runner.REGISTRATION_ATTESTATION_DOMAIN == (
        "recova.onnuri.smoke.registration.execution.v1"
    )
    assert "const DOMAIN = 'recova.onnuri.smoke.registration.execution.v1';" in (
        ROOT / "registration-sip-attestor.js"
    ).read_text()
    assert [proof["ordinal"] for proof in broker.proofs] == [1, 4]
    assert broker.proofs[1]["prior_register_operation_uuid"] == REGISTER_OPERATION_UUID
    assert len(subject.stage_receipts) == 4
    starts_with_deadlines = [
        (payload["stage"], deadline)
        for path, payload, deadline in api.deadlines
        if path == "/execution/stage/start"
    ]
    assert all(deadline is not None for _, deadline in starts_with_deadlines)
    deadline_by_stage = dict(starts_with_deadlines)
    assert broker.deadlines == [
        deadline_by_stage["register"],
        deadline_by_stage["unregister"],
    ]
    for stage, deadline in starts_with_deadlines:
        assert all(
            operation_deadline == deadline
            for path, payload, operation_deadline in api.deadlines
            if payload.get("stage") == stage and path == "/execution/stage/status"
        )
    for operation in ("register", "unregister"):
        assert next(
            deadline
            for path, payload, deadline in api.deadlines
            if path == "/registration/begin" and payload["operation_kind"] == operation
        ) == deadline_by_stage[operation]


def test_recovered_stage_is_fatal_and_never_executes_action(tmp_path: Path) -> None:
    api = FakeApi(recovered=True)
    invoked = False

    def action(_deadline):
        nonlocal invoked
        invoked = True
        return {}

    subject = runner.Runner(config(tmp_path), api, FakeBarrier(), FakeSecrets(), FakeBroker())
    with pytest.raises(runner.RunnerError, match="stage_recovery_rejected"):
        subject._stage("outbound_call", 2, action)
    assert invoked is False
    assert sum(path == "/execution/stage/start" for path, _, _ in api.calls) == 1


def test_failure_after_registration_uses_only_authorized_unregistration_stage(tmp_path: Path) -> None:
    api = FakeApi(fail_at=runner.INBOUND_ROUTE)
    secrets = FakeSecrets()
    broker = FakeBroker()
    subject = runner.Runner(config(tmp_path), api, FakeBarrier(), secrets, broker)

    with pytest.raises(runner.RunnerError, match="simulated"):
        subject.run()

    paths = [path for path, _, _ in api.calls]
    starts = [payload for path, payload, _ in api.calls if path == "/execution/stage/start"]
    assert "/registration/emergency-unregister" not in paths
    assert [(item["stage"], item["ordinal"]) for item in starts] == list(runner.STAGES)
    assert [proof["operation_kind"] for proof in broker.proofs] == ["register", "unregister"]
    assert "/v1/g008/calls/hangup" in paths
    assert "/execution/contain" in paths
    assert subject.contained is True
    assert subject.runtime_started is False
    assert secrets.erased == 1
    assert not config(tmp_path).execution_bundle_path.exists()


@pytest.mark.parametrize(
    ("failure", "expected_stages", "expected_transactions"),
    [
        ("register", [("register", 1)], []),
        (
            "outbound",
            [("register", 1), ("outbound_call", 2), ("unregister", 4)],
            ["register", "unregister"],
        ),
        (
            "inbound",
            [("register", 1), ("outbound_call", 2), ("inbound_call", 3), ("unregister", 4)],
            ["register", "unregister"],
        ),
        (
            "unregister",
            list(runner.STAGES),
            ["register"],
        ),
    ],
)
def test_stage_failures_never_issue_an_extra_registration_transaction(
    tmp_path: Path, failure: str, expected_stages: list[tuple[str, int]], expected_transactions: list[str]
) -> None:
    fail_at = {
        "outbound": runner.OUTBOUND_ROUTE_TEMPLATE.format(account_id="account-1"),
        "inbound": runner.INBOUND_ROUTE,
    }.get(failure)
    api = FakeApi(
        fail_at=fail_at,
        fail_registration_operation=failure if failure in {"register", "unregister"} else None,
    )
    subject = runner.Runner(config(tmp_path), api, FakeBarrier(), FakeSecrets(), FakeBroker())

    with pytest.raises(runner.RunnerError, match="simulated"):
        subject.run()

    paths = [path for path, _, _ in api.calls]
    starts = [payload for path, payload, _ in api.calls if path == "/execution/stage/start"]
    transactions = [proof["operation_kind"] for proof in subject.broker.proofs]
    assert "/registration/emergency-unregister" not in paths
    assert [(item["stage"], item["ordinal"]) for item in starts] == expected_stages
    assert transactions == expected_transactions
    assert len(transactions) == len(set(transactions))


def test_broker_register_failure_is_local_containment_only(tmp_path: Path) -> None:
    api = FakeApi()
    subject = runner.Runner(
        config(tmp_path), api, FakeBarrier(), FakeSecrets(), FakeBroker(fail_operation="register")
    )

    with pytest.raises(runner.RunnerError, match="broker failed"):
        subject.run()

    starts = [payload for path, payload, _ in api.calls if path == "/execution/stage/start"]
    assert [(item["stage"], item["ordinal"]) for item in starts] == [("register", 1)]
    assert [proof["operation_kind"] for proof in subject.broker.proofs] == ["register"]


@pytest.mark.parametrize("cleanup_endpoint", ["/v1/g008/calls/hangup", "/containment", "/execution/contain"])
def test_cleanup_obligations_are_independent_and_secret_erasure_is_outermost(
    tmp_path: Path, cleanup_endpoint: str
) -> None:
    api = FakeApi(fail_at={runner.INBOUND_ROUTE, cleanup_endpoint})
    secrets = FakeSecrets()
    subject = runner.Runner(config(tmp_path), api, FakeBarrier(), secrets, FakeBroker())
    with pytest.raises(BaseException):
        subject.run()
    paths = [path for path, _, _ in api.calls]
    assert "/registration/emergency-unregister" not in paths
    assert "/v1/g008/calls/hangup" in paths
    assert "/containment" in paths
    assert "/execution/contain" in paths
    assert secrets.erased == 1


def test_register_and_broker_reject_missing_or_crossed_deadlines(tmp_path: Path) -> None:
    subject = runner.Runner(config(tmp_path), FakeApi(), FakeBarrier(), FakeSecrets(), FakeBroker())
    subject.stage_uuids["register"] = STAGE_UUIDS["register"]
    with pytest.raises(runner.RunnerError, match="deadline_missing"):
        subject._registration("register", None)
    for operation in ("register", "unregister"):
        with pytest.raises(runner.RunnerError, match="deadline"):
            runner.TransactionBroker(connector=lambda *_args, **_kwargs: None).consume(
                proof(operation), __import__("time").monotonic() - 1
            )


def test_secret_erasure_failure_is_retained_after_other_cleanup(tmp_path: Path) -> None:
    class FailingSecrets(FakeSecrets):
        def erase(self) -> None:
            super().erase()
            raise runner.RunnerError("erase failed")

    api = FakeApi(fail_at=runner.INBOUND_ROUTE)
    secrets = FailingSecrets()
    subject = runner.Runner(config(tmp_path), api, FakeBarrier(), secrets, FakeBroker())
    with pytest.raises(runner.RunnerError, match="erase failed"):
        subject.run()
    assert secrets.erased == 1
    paths = [path for path, _, _ in api.calls]
    assert "/registration/emergency-unregister" not in paths
    assert "/execution/contain" in paths


def test_execution_bundle_is_required_canonical_durable_and_exclusive(tmp_path: Path) -> None:
    assert runner.EXECUTION_BUNDLE_PATH == Path("/run/g008-output/execution-bundle.json")

    subject = runner.Runner(config(tmp_path), FakeApi(), FakeBarrier(), FakeSecrets(), FakeBroker())
    subject.run()
    raw = config(tmp_path).execution_bundle_path.read_bytes()
    bundle = json.loads(raw)
    assert runner.canonical(bundle) == raw
    assert bundle["schema_version"] == "recova-g008-execution-bundle-v2"
    assert len(bundle["stages"]) == 4
    assert bundle["nonce"]["payload"]["kind"] == "nonce_consumption"
    assert bundle["seal"]["payload"]["stages"] == [stage for stage, _ in runner.STAGES]
    assert bundle["seal"]["payload"]["stage_deadline_seconds"] == 60
    assert all(
        receipt["payload"]["stage_deadline_seconds"] == 60
        for receipt in bundle["stages"]
    )
    assert bundle["final"]["kind"] == "final_execution_evidence"
    with pytest.raises(runner.RunnerError, match="execution_bundle_export_failed"):
        runner.write_exclusive(config(tmp_path).execution_bundle_path, raw)


def proof(operation: str = "register") -> dict:
    unregister = operation == "unregister"
    return {
        "candidate_digest": "b" * 64,
        "execution_nonce_digest": D,
        "execution_seal_uuid": "11111111-1111-4111-8111-111111111111",
        "gate_envelope_digest": "c" * 64,
        "opaque_authorization": "opaque",
        "operation_kind": operation,
        "operation_uuid": UNREGISTER_OPERATION_UUID if unregister else REGISTER_OPERATION_UUID,
        "ordinal": 4 if unregister else 1,
        "organization_id": 7,
        "prior_register_gate_id": 9 if unregister else None,
        "prior_register_operation_uuid": REGISTER_OPERATION_UUID if unregister else None,
        "registration_gate_id": 9,
        "request_digest": "e" * 64,
        "schema_version": runner.REGISTRATION_HANDOFF_SCHEMA,
        "stage": operation,
    }


def broker_receipt(value: dict) -> dict:
    claims = dict.fromkeys(runner.ATTESTATION_CLAIM_KEYS)
    claims.update(
        authorization_nonce_digest=value["execution_nonce_digest"],
        candidate_digest=value["candidate_digest"],
        gate_envelope_digest=value["gate_envelope_digest"],
        operation_kind=value["operation_kind"],
        operation_uuid=value["operation_uuid"],
        organization_id=value["organization_id"],
        prior_register_gate_id=value["prior_register_gate_id"],
        prior_register_operation_uuid=value["prior_register_operation_uuid"],
        registration_gate_id=value["registration_gate_id"],
        request_digest=value["request_digest"],
        outcome="succeeded",
        retry_count=0,
        transaction_count=1,
        transport="udp",
        verification_domain=runner.REGISTRATION_ATTESTATION_DOMAIN,
    )
    unsigned = {
        "algorithm": "ES256",
        "claims": claims,
        "key_id": "registration-attestation-v1",
        "verification_domain": runner.REGISTRATION_ATTESTATION_DOMAIN,
    }
    der_signature = ATTESTATION_PRIVATE_KEY.sign(
        runner.canonical(unsigned), ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(der_signature)
    signature = base64.urlsafe_b64encode(
        r.to_bytes(32, "big") + s.to_bytes(32, "big")
    ).rstrip(b"=").decode()
    attestation = {**unsigned, "signature": signature}
    opaque = base64.urlsafe_b64encode(runner.canonical(attestation)).rstrip(b"=").decode()
    return {
        "schema_version": runner.BROKER_RECEIPT_SCHEMA,
        "status": "finalized",
        "operation_kind": value["operation_kind"],
        "operation_uuid": value["operation_uuid"],
        "candidate_digest": value["candidate_digest"],
        "gate_envelope_digest": value["gate_envelope_digest"],
        "execution_nonce_digest": value["execution_nonce_digest"],
        "outcome": "succeeded",
        "registration_consumption": {
            "registration_gate_id": value["registration_gate_id"],
            "operation_uuid": value["operation_uuid"],
            "operation_kind": value["operation_kind"],
            "request_digest": value["request_digest"],
            "candidate_digest": value["candidate_digest"],
            "gate_envelope_digest": value["gate_envelope_digest"],
            "nonce_digest": value["execution_nonce_digest"],
            "prior_register_gate_id": value["prior_register_gate_id"],
            "prior_register_operation_uuid": value["prior_register_operation_uuid"],
            "state": "started",
            "challenged": True,
            "transaction_count": 1,
            "retry_count": 0,
            "concurrency_count": 1,
        },
        "opaque_execution_attestation": opaque,
        "execution_attestation_sha256": hashlib.sha256(opaque.encode()).hexdigest(),
    }


def connector_for(response: bytes, captured: list[bytes]):
    def connector(address, timeout):
        assert address == (runner.BROKER_HOST, runner.BROKER_PORT)
        assert 0 < timeout <= 60
        client, server = socket.socketpair()

        def serve() -> None:
            chunks = bytearray()
            while True:
                chunk = server.recv(8192)
                if not chunk:
                    break
                chunks.extend(chunk)
            captured.append(bytes(chunks))
            if response:
                server.sendall(response)
            server.close()

        threading.Thread(target=serve).start()
        return client

    return connector


def configured_broker(connector) -> runner.TransactionBroker:
    broker = runner.TransactionBroker(connector=connector)
    public_der = ATTESTATION_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    broker.configure_attestation(
        "registration-attestation-v1", hashlib.sha256(public_der).hexdigest()
    )
    return broker


def test_broker_control_is_one_canonical_line_half_closed_and_one_shot() -> None:
    value = proof()
    response = runner.canonical(broker_receipt(value)) + b"\n"
    captured: list[bytes] = []
    broker = configured_broker(connector_for(response, captured))

    receipt = broker.consume(value, __import__("time").monotonic() + 60)

    assert receipt["status"] == "finalized"
    assert len(captured) == 1
    assert captured[0].endswith(b"\n") and captured[0].count(b"\n") == 1
    request = json.loads(captured[0][:-1])
    assert runner.canonical(request) == captured[0][:-1]
    assert request == {
        "schema_version": runner.BROKER_CONTROL_SCHEMA,
        "action": "consume",
        "proof": value,
    }
    with pytest.raises(runner.RunnerError, match="replay"):
        broker.consume(value, __import__("time").monotonic() + 60)


@pytest.mark.parametrize("mutation", ["close", "mismatch", "noncanonical", "second-line"])
def test_broker_rejects_close_mismatch_and_noncanonical_or_multiple_responses(mutation: str) -> None:
    value = proof()
    receipt = broker_receipt(value)
    if mutation == "close":
        encoded = b""
    elif mutation == "mismatch":
        receipt["operation_uuid"] = UNREGISTER_OPERATION_UUID
        encoded = runner.canonical(receipt) + b"\n"
    elif mutation == "noncanonical":
        encoded = json.dumps(receipt, indent=2).encode() + b"\n"
    else:
        encoded = runner.canonical(receipt) + b"\n{}\n"
    broker = configured_broker(connector_for(encoded, []))
    with pytest.raises(runner.RunnerError, match="transaction_broker"):
        broker.consume(value, __import__("time").monotonic() + 60)


@pytest.mark.parametrize(
    "mutation",
    [
        "status", "digest", "claim-binding", "consumption-binding",
        "signature-bit-flip", "key-mismatch", "verification-domain",
    ],
)
def test_broker_rejects_state_digest_binding_and_signature_mismatch(mutation: str) -> None:
    value = proof()
    receipt = broker_receipt(value)
    if mutation == "status":
        receipt["status"] = "pending"
    elif mutation == "digest":
        receipt["execution_attestation_sha256"] = "0" * 64
    elif mutation == "consumption-binding":
        receipt["registration_consumption"]["nonce_digest"] = "0" * 64
    else:
        opaque = receipt["opaque_execution_attestation"]
        decoded = base64.urlsafe_b64decode(opaque + "=" * (-len(opaque) % 4))
        attestation = json.loads(decoded)
        if mutation == "claim-binding":
            attestation["claims"]["candidate_digest"] = "0" * 64
        elif mutation == "key-mismatch":
            attestation["key_id"] = "registration-attestation-other"
        elif mutation == "verification-domain":
            attestation["verification_domain"] = "recova.onnuri.smoke.registration.v1"
            attestation["claims"]["verification_domain"] = (
                "recova.onnuri.smoke.registration.v1"
            )
        else:
            signature = bytearray(base64.urlsafe_b64decode(
                attestation["signature"] + "=" * (-len(attestation["signature"]) % 4)
            ))
            signature[0] ^= 1
            attestation["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        opaque = base64.urlsafe_b64encode(runner.canonical(attestation)).rstrip(b"=").decode()
        receipt["opaque_execution_attestation"] = opaque
        receipt["execution_attestation_sha256"] = hashlib.sha256(opaque.encode()).hexdigest()
    encoded = runner.canonical(receipt) + b"\n"
    broker = configured_broker(connector_for(encoded, []))
    with pytest.raises(runner.RunnerError, match="transaction_broker"):
        broker.consume(value, __import__("time").monotonic() + 60)


def test_broker_endpoint_is_exact_private_control_address() -> None:
    with pytest.raises(runner.RunnerError, match="endpoint_rejected"):
        runner.TransactionBroker("127.0.0.1", runner.BROKER_PORT)
    with pytest.raises(runner.RunnerError, match="endpoint_rejected"):
        runner.TransactionBroker(runner.BROKER_HOST, runner.BROKER_PORT + 1)


def execution_request() -> dict:
    return {
        "schema_version": runner.EXECUTION_REQUEST_SCHEMA,
        "organization_id": 7,
        "execution_seal_uuid": "11111111-1111-4111-8111-111111111111",
        "execution_nonce_digest": D,
        "candidate_digest": "b" * 64,
        "gate_envelope_digest": "c" * 64,
        "destination_hmac_digest": "d" * 64,
        "gate_envelope_uuid": "22222222-2222-4222-8222-222222222222",
        "request_digest": "e" * 64,
        "reserved_inbound_did_digest": "6" * 64,
        "reserved_inbound_caller_digest": "7" * 64,
        "policy_digest": "8" * 64,
        "live_window_start": "2026-07-18T01:00:00Z",
        "live_window_end": "2026-07-18T01:04:00Z",
        "account_id": "account-1",
        "application_id": "application-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "authority_deadline": "2026-07-18T01:01:00Z",
        "idempotency_key": "g008-once",
        "route_evidence_handle": "route-evidence-handle-v1",
        "route_profile_digest": "9" * 64,
        "request_mode": "diagnostic",
        "answer_hook_url": "https://hooks.invalid/answer",
        "status_hook_url": "https://hooks.invalid/status",
        "contingency_direction": None,
    }


def request_environment(tmp_path: Path, payload: bytes) -> dict[str, str]:
    path = tmp_path / "request"
    path.write_bytes(payload)
    path.chmod(0o600)
    return {
        "G008_EXECUTION_REQUEST_FILE": str(path),
        "G008_EXECUTION_REQUEST_SHA256": hashlib.sha256(payload).hexdigest(),
    }


@pytest.mark.parametrize("mutation", ["extra", "missing", "schema", "noncanonical", "digest"])
def test_execution_request_rejects_schema_extras_canonical_and_digest_mismatch(
    tmp_path: Path, mutation: str
) -> None:
    request = execution_request()
    if mutation == "extra":
        request["unexpected"] = True
    elif mutation == "missing":
        del request["candidate_digest"]
    elif mutation == "schema":
        request["schema_version"] = "recova-g008-execution-request-v0"
    payload = (
        json.dumps(request, indent=2).encode()
        if mutation == "noncanonical"
        else runner.canonical(request)
    )
    environment = request_environment(tmp_path, payload)
    if mutation == "digest":
        environment["G008_EXECUTION_REQUEST_SHA256"] = "0" * 64
    with pytest.raises(runner.RunnerError, match="execution_request"):
        runner.Config.load(environment)


def test_execution_request_loads_exact_contract_and_fixed_endpoints(tmp_path: Path) -> None:
    payload = runner.canonical(execution_request())
    loaded = runner.Config.load(request_environment(tmp_path, payload))

    assert loaded.account_id == "account-1"
    assert loaded.execution_bundle_path == runner.EXECUTION_BUNDLE_PATH
    assert runner.KEYSET_PATH == Path("/opt/g008/trusted/phase_c_live_preflight_v1.json")
    assert runner.F12_BASE_URL == "https://f12-ingress:8443/api/v1/internal/onnuri-smoke"
    source = (ROOT / "run-g008-live-smoke.py").read_text()
    assert "metadata.google.internal" not in source
    assert "secretmanager.googleapis.com" not in source
    assert "G008_OUTBOUND_PATH" not in source
    assert "G008_INBOUND_PATH" not in source
    assert "contingency_direction" in source


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("route_evidence_handle", None),
        ("route_profile_digest", None),
        ("request_mode", "legacy"),
        ("route_evidence_handle", "a" * 64),
        ("route_evidence_handle", {"route_chain": "raw-authority"}),
    ],
)
def test_execution_request_rejects_non_diagnostic_or_nonopaque_route_authority_before_client_creation(
    tmp_path: Path, field: str, value: object
) -> None:
    request = execution_request()
    if value is None:
        del request[field]
    else:
        request[field] = value
    with pytest.raises(runner.RunnerError, match="execution_request"):
        runner.Config.load(request_environment(tmp_path, runner.canonical(request)))


def test_outbound_facade_payload_is_exact_diagnostic_and_redacts_route_authority(
    tmp_path: Path,
) -> None:
    api = FakeApi()
    subject = runner.Runner(config(tmp_path), api, FakeBarrier(), FakeSecrets(), FakeBroker())
    subject.stage_uuids["outbound_call"] = STAGE_UUIDS["outbound_call"]

    subject._call("outbound", __import__("time").monotonic() + 60)

    payload = next(
        payload
        for path, payload, facade in api.calls
        if path == runner.OUTBOUND_ROUTE_TEMPLATE.format(account_id="account-1") and facade
    )
    assert payload == {
        "contract_version": "recova-jambonz-facade-v1",
        "organization_id": 7,
        "application_id": "application-1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "direction": "outbound",
        "authority_deadline": "2026-07-18T01:01:00Z",
        "idempotency_key": "g008-once",
        "candidate_digest": "b" * 64,
        "gate_envelope_digest": "c" * 64,
        "request_mode": "diagnostic",
        "route_evidence_handle": "route-evidence-handle-v1",
        "route_profile_digest": "9" * 64,
        "from_address": "caller",
        "to_address": "target",
        "answer_hook_url": "https://hooks.invalid/answer",
        "status_hook_url": "https://hooks.invalid/status",
        "ring_timeout_seconds": 30,
        "time_limit_seconds": 60,
    }
    rendered = json.dumps(payload)
    assert "dispatch_capability" not in rendered
    assert "route_chain" not in rendered
    assert "raw-authority" not in rendered


def test_contingency_is_operator_authorized_direction_bound_and_limited(tmp_path: Path) -> None:
    api = FakeApi(fail_at=runner.OUTBOUND_ROUTE_TEMPLATE.format(account_id="account-1"), fail_once=True)
    barrier = FakeBarrier()
    authorized = config(tmp_path)
    object.__setattr__(authorized, "contingency_direction", "outbound")
    subject = runner.Runner(authorized, api, barrier, FakeSecrets(), FakeBroker())

    subject.run()

    traffic = [
        path for path, _, _ in api.calls
        if path in {runner.OUTBOUND_ROUTE_TEMPLATE.format(account_id="account-1"), runner.INBOUND_ROUTE}
    ]
    assert len(traffic) == 3
    assert traffic == [runner.OUTBOUND_ROUTE_TEMPLATE.format(account_id="account-1")] * 2 + [runner.INBOUND_ROUTE]
    assert barrier.calls == ["authorize_contingency_outbound", "ack_outbound", "ack_inbound"]
    assert subject.provider_call_attempts == 3
    assert subject.contingency_used is True


def test_contingency_after_success_automatic_retry_and_fourth_call_are_rejected(tmp_path: Path) -> None:
    subject = runner.Runner(config(tmp_path), FakeApi(), FakeBarrier(), FakeSecrets(), FakeBroker())
    subject.stage_uuids["outbound_call"] = STAGE_UUIDS["outbound_call"]
    with pytest.raises(runner.RunnerError, match="contingency_rejected"):
        subject._call("outbound", __import__("time").monotonic() + 60, contingency=True)
    subject.mandatory_call_failures.add("outbound")
    with pytest.raises(runner.RunnerError, match="automatic_retry_rejected"):
        subject._call("outbound", __import__("time").monotonic() + 60)
    subject.provider_call_attempts = 3
    with pytest.raises(runner.RunnerError, match="provider_call_budget_rejected"):
        subject._call("outbound", __import__("time").monotonic() + 60, contingency=True)


@pytest.mark.parametrize(
    "mutation",
    ["concurrency", "deadline", "overlap"],
)
def test_call_receipts_reject_concurrency_overlong_or_overlapping_calls(tmp_path: Path, mutation: str) -> None:
    subject = runner.Runner(config(tmp_path), FakeApi(), FakeBarrier(), FakeSecrets(), FakeBroker())
    subject.stage_uuids["outbound_call"] = STAGE_UUIDS["outbound_call"]
    receipt = {
        **config_binding({**subject.config.binding()}),
        "stage": "outbound_call", "ordinal": 2,
        "stage_uuid": STAGE_UUIDS["outbound_call"], "stage_deadline_seconds": 60,
        "state": "succeeded", "terminal_class": "call_completed",
        "provider_call_id_digest": "1" * 64, "status_artifact_digest": "2" * 64,
        "cdr_artifact_digest": "3" * 64, "human_rx_artifact_digest": "4" * 64,
        "human_rx_acknowledgement_artifact_digest": "5" * 64,
        "human_tx_artifact_digest": "6" * 64, "human_tx_acknowledgement_artifact_digest": "7" * 64,
        "started_monotonic_ms": 1_000, "ended_monotonic_ms": 2_000,
        "retry_count": 0, "concurrency_count": 1, "billed_duration_ms": 900,
        "human_rx_duration_ms": 500, "human_rx_acknowledgement": "redacted_heard",
        "human_tx_duration_ms": 400, "human_tx_acknowledgement": "redacted_spoke",
        "terminal_status": "terminal",
    }
    if mutation == "concurrency":
        receipt["concurrency_count"] = 2
    elif mutation == "deadline":
        receipt["ended_monotonic_ms"] = 61_001
    else:
        subject.call_intervals.append((500, 1_500))
    with pytest.raises(runner.RunnerError, match="call_stage_evidence_rejected"):
        subject._accept_stage_receipt("outbound_call", 2, receipt)
