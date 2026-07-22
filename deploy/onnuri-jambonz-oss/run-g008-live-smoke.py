#!/usr/bin/env python3
"""Fail-closed, one-shot G008 live-smoke coordinator.

The coordinator never receives a phone/SIP value through argv or environment and
never writes one outside its private tmpfs.  Its observable output is restricted
to the state labels in REDACTED_LABELS.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

SCHEMA_VERSION = "recova-g008-execution-seal-v1"
EXECUTION_REQUEST_SCHEMA = "recova-g008-execution-request-v1"
LEGACY_STAGES = (("register", 1), ("outbound_call", 2), ("inbound_call", 3), ("unregister", 4))
IP_TO_IP_STAGES = (("outbound_call", 1), ("inbound_call", 2))
SIP_MODES = {"registration", "ip_to_ip"}
PEER_PORT = 5060
PEER_TRANSPORT = "udp"
STAGES = LEGACY_STAGES
KEYSET_PATH = Path("/opt/g008/trusted/phase_c_live_preflight_v1.json")
TRUSTED_KEYSET_SHA256 = "00645f3af8230c742951c12f17a713afde209de12182cd6e3722ac59445507aa"
EXECUTION_KEY_ID = "recova-g008-authority-v1"
EXECUTION_KEY_SHA256 = "977e114e74aae8a837e41665a800e5b545ccd201883223569b95a566c1e9667d"
BROKER_HOST = "172.32.0.2"
BROKER_PORT = 8079
BROKER_CONTROL_SCHEMA = "recova-g008-transaction-broker-control-v1"
BROKER_RECEIPT_SCHEMA = "recova-g008-transaction-broker-receipt-v1"
REGISTRATION_HANDOFF_SCHEMA = "recova-g008-registration-handoff-v1"
REGISTRATION_ATTESTATION_DOMAIN = "recova.onnuri.smoke.registration.execution.v1"
REGISTRATION_ATTESTATION_PUBLIC_KEY_PATH = Path(
    "/run/secrets/g008-registration-attestation-es256-public-key"
)
STAGE_DEADLINE_SECONDS = 60
F12_BASE_URL = "https://f12-ingress:8443/api/v1/internal/onnuri-smoke"
FACADE_BASE_URL = "http://facade:8080"
OUTBOUND_ROUTE_TEMPLATE = "/v1/jambonz-contract/accounts/{account_id}/calls"
INBOUND_ROUTE = "/v1/g008/inbound/arm"
EXECUTION_BUNDLE_PATH = Path("/run/g008-output/execution-bundle.json")
BROKER_RECEIPT_KEYS = {
    "schema_version", "status", "operation_kind", "operation_uuid",
    "candidate_digest", "gate_envelope_digest", "execution_nonce_digest",
    "outcome", "registration_consumption", "opaque_execution_attestation",
    "execution_attestation_sha256",
}
ATTESTATION_CLAIM_KEYS = {
    "accepted_expires_seconds", "authorization_nonce_digest", "candidate_digest",
    "challenge_response_wire_digest", "challenge_status", "completed_at",
    "deregistered", "final_response_wire_digest", "final_status",
    "gate_envelope_digest", "initial_request_wire_digest", "operation_kind",
    "operation_uuid", "organization_id", "outcome", "prior_register_gate_id",
    "prior_register_operation_uuid", "registration_gate_id", "request_digest",
    "response_count", "retry_count", "retry_request_wire_digest",
    "sip_transaction_binding_digest", "started_at", "transaction_count",
    "transport", "upstream_endpoint_digest", "verification_domain",
    "wire_request_count",
}
BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
PATH_RE = re.compile(r"/[A-Za-z0-9._~/-]{1,255}\Z")
MAX_AF_UNIX_PATH_BYTES = 100
REDACTED_LABELS = {
    "sealed", "running", "contained", "completed", "failed",
    "register_started", "register_succeeded", "outbound_call_started",
    "outbound_call_succeeded", "inbound_call_started", "inbound_call_succeeded",
    "unregister_started", "unregister_succeeded", "evidence_finalized",
}


class RunnerError(RuntimeError):
    pass


def label(value: str) -> None:
    if value not in REDACTED_LABELS:
        raise RunnerError("non_redacted_log_rejected")
    print(value, flush=True)


def required(env: dict[str, str], name: str) -> str:
    value = env.get(name, "")
    if not value or value != value.strip():
        raise RunnerError("configuration_rejected")
    return value


def digest(env: dict[str, str], name: str) -> str:
    value = required(env, name)
    if DIGEST_RE.fullmatch(value) is None:
        raise RunnerError("configuration_rejected")
    return value


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def load_execution_key() -> bytes:
    raw = KEYSET_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != TRUSTED_KEYSET_SHA256:
        raise RunnerError("trusted_keyset_rejected")
    keyset = json.loads(raw)
    if canonical(keyset) != raw or set(keyset) != {"keys", "schema_version"}:
        raise RunnerError("trusted_keyset_rejected")
    matches = [
        entry for entry in keyset["keys"]
        if entry.get("role") == "authority"
        and entry.get("key_id") == EXECUTION_KEY_ID
        and entry.get("public_key_sha256") == EXECUTION_KEY_SHA256
        and entry.get("algorithm") == "Ed25519"
    ]
    if len(matches) != 1:
        raise RunnerError("trusted_keyset_rejected")
    encoded = matches[0].get("public_key_base64url")
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (TypeError, ValueError) as exc:
        raise RunnerError("trusted_keyset_rejected") from exc
    if len(key) != 32 or hashlib.sha256(key).hexdigest() != EXECUTION_KEY_SHA256:
        raise RunnerError("trusted_keyset_rejected")
    return key


def write_exclusive(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise RunnerError("execution_bundle_export_failed") from exc
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def read_private(path: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        mode = metadata.st_mode & 0o777
        if not stat.S_ISREG(metadata.st_mode) or mode & 0o077:
            raise RunnerError("private_file_mode_rejected")
        value = os.read(descriptor, 65537)
        if not value or len(value) > 65536:
            raise RunnerError("private_file_rejected")
        return value.rstrip(b"\r\n")
    finally:
        os.close(descriptor)


class SecretFiles:
    def __init__(self, directory: str) -> None:
        self.directory = Path(directory)
        self.paths: dict[str, str] = {}

    def put(self, name: str, value: bytes) -> str:
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        if (self.directory.stat().st_mode & 0o777) != 0o700:
            raise RunnerError("secret_directory_mode_rejected")
        path = self.directory / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o400)
        try:
            os.write(descriptor, value)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.paths[name] = str(path)
        return str(path)


    def erase(self) -> None:
        failures: list[Exception] = []
        for path in self.paths.values():
            try:
                size = os.stat(path, follow_symlinks=False).st_size
                os.chmod(path, 0o600, follow_symlinks=False)
                descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
                try:
                    os.write(descriptor, b"\0" * size)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.unlink(path)
            except FileNotFoundError:
                pass
            except Exception as exc:
                failures.append(exc)
        self.paths.clear()
        try:
            shutil.rmtree(self.directory)
        except FileNotFoundError:
            pass
        except Exception as exc:
            failures.append(exc)
        if failures:
            raise ExceptionGroup("secret_erasure_failures", failures)


class JsonClient:
    def __init__(self, context: ssl.SSLContext, endpoint_credential: bytes) -> None:
        if (
            not endpoint_credential
            or len(endpoint_credential) > 4096
            or b"\r" in endpoint_credential
            or b"\n" in endpoint_credential
        ):
            raise RunnerError("endpoint_credential_rejected")
        try:
            self.endpoint_credential = endpoint_credential.decode("ascii")
        except UnicodeDecodeError as exc:
            raise RunnerError("endpoint_credential_rejected") from exc
        self.context = context

    def post(self, path: str, payload: dict[str, Any], *, facade: bool = False, deadline: float | None = None) -> dict[str, Any]:
        if PATH_RE.fullmatch(path) is None or ".." in path:
            raise RunnerError("api_path_rejected")
        base = FACADE_BASE_URL if facade else F12_BASE_URL
        headers = {"Content-Type": "application/json"}
        if not facade:
            headers["X-Recova-Onnuri-Endpoint-Credential"] = self.endpoint_credential
        request = urllib.request.Request(
            base + path,
            data=canonical(payload),
            headers=headers,
            method="POST",
        )
        timeout = 5.0 if deadline is None else deadline - time.monotonic()
        if timeout <= 0:
            raise RunnerError("call_deadline_exceeded")
        try:
            kwargs = {"timeout": min(timeout, 5.0)}
            if not facade:
                kwargs["context"] = self.context
            with urllib.request.urlopen(request, **kwargs) as response:
                result = json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RunnerError("api_request_failed") from exc
        if not isinstance(result, dict):
            raise RunnerError("api_response_rejected")
        return result

    def wait_ready(self, deadline: float) -> None:
        while time.monotonic() < deadline:
            try:
                if self.post("/ready", {}).get("ready") is True:
                    return
            except RunnerError:
                pass
            time.sleep(1)
        raise RunnerError("authority_unavailable")


class TransactionBroker:
    """One-shot canonical control client for the isolated registration broker."""

    def __init__(
        self,
        host: str = BROKER_HOST,
        port: int = BROKER_PORT,
        connector: Callable[..., socket.socket] = socket.create_connection,
    ) -> None:
        if host != BROKER_HOST or port != BROKER_PORT:
            raise RunnerError("transaction_broker_endpoint_rejected")
        self.host = host
        self.port = port
        self._connect = connector
        self._consumed: set[str] = set()
        self._attestation_key_id: str | None = None
        self._attestation_public_key: ec.EllipticCurvePublicKey | None = None

    def configure_attestation(self, key_id: str, public_key_sha256: str) -> None:
        if self._attestation_public_key is not None:
            raise RunnerError("transaction_broker_attestation_key_reconfigured")
        if (
            not isinstance(key_id, str)
            or re.fullmatch(r"registration-attestation-[A-Za-z0-9._-]{1,96}", key_id) is None
            or not isinstance(public_key_sha256, str)
            or DIGEST_RE.fullmatch(public_key_sha256) is None
        ):
            raise RunnerError("transaction_broker_attestation_key_rejected")
        try:
            descriptor = os.open(
                REGISTRATION_ATTESTATION_PUBLIC_KEY_PATH,
                os.O_RDONLY | os.O_NOFOLLOW,
            )
            try:
                metadata = os.fstat(descriptor)
                if metadata.st_mode & 0o222 or not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("public key file is not immutable")
                encoded = os.read(descriptor, 4097)
                if not encoded or len(encoded) > 4096:
                    raise ValueError("public key file size invalid")
            finally:
                os.close(descriptor)
            try:
                public_key = serialization.load_pem_public_key(encoded)
            except ValueError:
                public_key = serialization.load_der_public_key(encoded)
            if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
                public_key.curve, ec.SECP256R1
            ):
                raise ValueError("wrong key type")
            public_der = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (OSError, TypeError, ValueError) as exc:
            raise RunnerError("transaction_broker_attestation_key_rejected") from exc
        if hashlib.sha256(public_der).hexdigest() != public_key_sha256:
            raise RunnerError("transaction_broker_attestation_key_rejected")
        self._attestation_key_id = key_id
        self._attestation_public_key = public_key

    @staticmethod
    def _decode_attestation(value: str) -> tuple[dict[str, Any], bytes]:
        if not isinstance(value, str) or BASE64URL_RE.fullmatch(value) is None:
            raise RunnerError("transaction_broker_attestation_rejected")
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            attestation = json.loads(raw)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise RunnerError("transaction_broker_attestation_rejected") from exc
        if not isinstance(attestation, dict) or canonical(attestation) != raw:
            raise RunnerError("transaction_broker_attestation_rejected")
        if set(attestation) != {
            "algorithm", "claims", "key_id", "signature", "verification_domain",
        }:
            raise RunnerError("transaction_broker_attestation_rejected")
        signature = attestation["signature"]
        if (
            attestation["algorithm"] != "ES256"
            or attestation["verification_domain"] != REGISTRATION_ATTESTATION_DOMAIN
            or not isinstance(attestation["key_id"], str)
            or not isinstance(signature, str)
            or BASE64URL_RE.fullmatch(signature) is None
        ):
            raise RunnerError("transaction_broker_attestation_rejected")
        try:
            signature_bytes = base64.urlsafe_b64decode(
                signature + "=" * (-len(signature) % 4)
            )
        except ValueError as exc:
            raise RunnerError("transaction_broker_attestation_rejected") from exc
        if len(signature_bytes) != 64:
            raise RunnerError("transaction_broker_attestation_rejected")
        unsigned = {
            "algorithm": attestation["algorithm"],
            "claims": attestation["claims"],
            "key_id": attestation["key_id"],
            "verification_domain": attestation["verification_domain"],
        }
        return attestation, canonical(unsigned)

    def _verify_attestation_signature(self, attestation: dict[str, Any], unsigned: bytes) -> None:
        try:
            if (
                self._attestation_public_key is None
                or self._attestation_key_id is None
                or attestation["key_id"] != self._attestation_key_id
            ):
                raise ValueError("sealed attestation key mismatch")
            raw_signature = base64.urlsafe_b64decode(
                attestation["signature"] + "=" * (-len(attestation["signature"]) % 4)
            )
            r = int.from_bytes(raw_signature[:32], "big")
            s = int.from_bytes(raw_signature[32:], "big")
            self._attestation_public_key.verify(
                encode_dss_signature(r, s),
                unsigned,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise RunnerError("transaction_broker_attestation_rejected") from exc

    def _verify_receipt(
        self, receipt: dict[str, Any], proof: dict[str, Any]
    ) -> dict[str, Any]:
        if set(receipt) != BROKER_RECEIPT_KEYS:
            raise RunnerError("transaction_broker_receipt_rejected")
        expected = {
            "schema_version": BROKER_RECEIPT_SCHEMA,
            "status": "finalized",
            "operation_kind": proof["operation_kind"],
            "operation_uuid": proof["operation_uuid"],
            "candidate_digest": proof["candidate_digest"],
            "gate_envelope_digest": proof["gate_envelope_digest"],
            "execution_nonce_digest": proof["execution_nonce_digest"],
            "outcome": "succeeded",
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise RunnerError("transaction_broker_receipt_rejected")
        consumption = receipt["registration_consumption"]
        expected_consumption = {
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
        }
        if not isinstance(consumption, dict) or consumption != expected_consumption:
            raise RunnerError("transaction_broker_receipt_rejected")
        opaque = receipt["opaque_execution_attestation"]
        if (
            not isinstance(receipt["execution_attestation_sha256"], str)
            or DIGEST_RE.fullmatch(receipt["execution_attestation_sha256"]) is None
            or not isinstance(opaque, str)
            or hashlib.sha256(opaque.encode()).hexdigest()
            != receipt["execution_attestation_sha256"]
        ):
            raise RunnerError("transaction_broker_receipt_rejected")
        attestation, unsigned = self._decode_attestation(opaque)
        self._verify_attestation_signature(attestation, unsigned)
        claims = attestation["claims"]
        if not isinstance(claims, dict) or set(claims) != ATTESTATION_CLAIM_KEYS:
            raise RunnerError("transaction_broker_attestation_rejected")
        claim_bindings = {
            "authorization_nonce_digest": proof["execution_nonce_digest"],
            "candidate_digest": proof["candidate_digest"],
            "gate_envelope_digest": proof["gate_envelope_digest"],
            "operation_kind": proof["operation_kind"],
            "operation_uuid": proof["operation_uuid"],
            "organization_id": proof["organization_id"],
            "prior_register_gate_id": proof["prior_register_gate_id"],
            "prior_register_operation_uuid": proof["prior_register_operation_uuid"],
            "registration_gate_id": proof["registration_gate_id"],
            "request_digest": proof["request_digest"],
            "outcome": "succeeded",
            "retry_count": 0,
            "transaction_count": 1,
            "transport": "udp",
            "verification_domain": REGISTRATION_ATTESTATION_DOMAIN,
        }
        if any(claims.get(key) != value for key, value in claim_bindings.items()):
            raise RunnerError("transaction_broker_attestation_rejected")
        return receipt

    def consume(
        self, proof: dict[str, Any], deadline: float | None = None
    ) -> dict[str, Any]:
        operation = proof.get("operation_kind")
        if operation not in {"register", "unregister"} or operation in self._consumed:
            raise RunnerError("transaction_broker_replay_rejected")
        self._consumed.add(operation)
        request = {
            "schema_version": BROKER_CONTROL_SCHEMA,
            "action": "consume",
            "proof": proof,
        }
        if deadline is None:
            raise RunnerError("transaction_broker_deadline_rejected")
        timeout = deadline - time.monotonic()
        if timeout <= 0 or timeout > STAGE_DEADLINE_SECONDS:
            raise RunnerError("transaction_broker_deadline_rejected")
        try:
            connection = self._connect((self.host, self.port), timeout=timeout)
            with connection:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RunnerError("transaction_broker_deadline_rejected")
                connection.settimeout(remaining)
                connection.sendall(canonical(request) + b"\n")
                connection.shutdown(socket.SHUT_WR)
                response = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RunnerError("transaction_broker_deadline_rejected")
                    connection.settimeout(remaining)
                    chunk = connection.recv(8192)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > 32768:
                        raise RunnerError("transaction_broker_receipt_rejected")
        except (OSError, TimeoutError) as exc:
            raise RunnerError("transaction_broker_unavailable") from exc
        raw = bytes(response)
        if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise RunnerError("transaction_broker_receipt_rejected")
        try:
            receipt = json.loads(raw[:-1])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RunnerError("transaction_broker_receipt_rejected") from exc
        if not isinstance(receipt, dict) or canonical(receipt) != raw[:-1]:
            raise RunnerError("transaction_broker_receipt_rejected")
        return self._verify_receipt(receipt, proof)



class Barrier:
    """Single-use local control surface; duplicate/wrong/out-of-order ACKs fail closed."""

    def __init__(self, path: str, credential: bytes) -> None:
        encoded_path = os.fsencode(path)
        if len(encoded_path) > MAX_AF_UNIX_PATH_BYTES:
            path_digest = hashlib.sha256(encoded_path).hexdigest()
            path = f"/tmp/g008-{path_digest}.sock"
        self.path = path
        self.credential = credential
        self.used: set[str] = set()

    def wait(self, expected: str, deadline: float) -> None:
        if expected in self.used:
            raise RunnerError("duplicate_barrier_rejected")
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(self.path)
            os.chmod(self.path, 0o600)
            server.listen(1)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunnerError("stage_deadline_exceeded")
            server.settimeout(remaining)
            connection, _ = server.accept()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RunnerError("stage_deadline_exceeded")
            connection.settimeout(remaining)
            with connection:
                message = connection.recv(65537)
                try:
                    parsed = json.loads(message)
                    action = parsed["action"]
                    supplied = parsed["credential"].encode()
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise RunnerError("barrier_rejected") from exc
                if set(parsed) != {"action", "credential"}:
                    raise RunnerError("barrier_rejected")
                if action != expected or action in self.used:
                    raise RunnerError("barrier_rejected")
                if not hmac.compare_digest(supplied, self.credential):
                    raise RunnerError("barrier_rejected")
                self.used.add(action)
                connection.sendall(b'{"state":"accepted"}')
        finally:
            server.close()
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass


@dataclass(frozen=True)
class Config:
    organization_id: int
    seal: str
    nonce_digest: str
    candidate_digest: str
    gate_digest: str
    destination_digest: str
    owned_target_sha256: str
    envelope_uuid: str
    request_digest: str
    reserved_did_digest: str
    reserved_caller_digest: str
    policy_digest: str
    live_start: str
    live_end: str
    account_id: str
    application_id: str
    run_id: str
    attempt_id: str
    authority_deadline: str
    idempotency_key: str
    route_evidence_handle: str
    route_profile_digest: str
    request_mode: str
    answer_hook_url: str
    status_hook_url: str
    sip_mode: str = "registration"
    source_external_ip: str | None = None
    peer_binding_digest: str | None = None
    contingency_direction: str | None = None
    execution_bundle_path: Path = EXECUTION_BUNDLE_PATH

    @classmethod
    def load(cls, env: dict[str, str]) -> "Config":
        raw = read_private(required(env, "G008_EXECUTION_REQUEST_FILE"))
        expected_digest = digest(env, "G008_EXECUTION_REQUEST_SHA256")
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_digest):
            raise RunnerError("execution_request_digest_rejected")
        try:
            request = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RunnerError("execution_request_rejected") from exc
        fields = {
            "schema_version", "organization_id", "execution_seal_uuid",
            "execution_nonce_digest", "candidate_digest", "gate_envelope_digest",
            "destination_hmac_digest", "owned_target_sha256", "gate_envelope_uuid", "request_digest",
            "reserved_inbound_did_digest", "reserved_inbound_caller_digest",
            "policy_digest", "live_window_start", "live_window_end", "account_id",
            "application_id", "run_id", "attempt_id", "authority_deadline",
            "idempotency_key", "route_evidence_handle", "route_profile_digest",
            "request_mode", "answer_hook_url", "status_hook_url", "contingency_direction",
            "sip_mode", "source_external_ip", "peer_binding_digest",
        }
        if (
            not isinstance(request, dict)
            or set(request) != fields
            or canonical(request) != raw
            or request.get("schema_version") != EXECUTION_REQUEST_SCHEMA
        ):
            raise RunnerError("execution_request_rejected")
        try:
            organization_id = request["organization_id"]
            if type(organization_id) is not int or organization_id <= 0:
                raise ValueError
            for name in (
                "execution_nonce_digest", "candidate_digest", "gate_envelope_digest",
                "destination_hmac_digest", "owned_target_sha256", "request_digest",
                "reserved_inbound_did_digest", "reserved_inbound_caller_digest",
                "policy_digest",
            ):
                if not isinstance(request[name], str) or DIGEST_RE.fullmatch(request[name]) is None:
                    raise ValueError
            for name in ("execution_seal_uuid", "gate_envelope_uuid"):
                value = request[name]
                if not isinstance(value, str) or str(uuid.UUID(value)) != value:
                    raise ValueError
            for name in (
                "live_window_start", "live_window_end", "account_id", "application_id",
                "run_id", "attempt_id", "authority_deadline", "idempotency_key",
                "answer_hook_url", "status_hook_url",
            ):
                value = request[name]
                if not isinstance(value, str) or not value or value != value.strip():
                    raise ValueError
            if (
                request["request_mode"] != "diagnostic"
                or not isinstance(request["route_evidence_handle"], str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~-]{15,254}", request["route_evidence_handle"]) is None
                or DIGEST_RE.fullmatch(request["route_evidence_handle"]) is not None
                or not isinstance(request["route_profile_digest"], str)
                or DIGEST_RE.fullmatch(request["route_profile_digest"]) is None
            ):
                raise ValueError
            if request["sip_mode"] not in SIP_MODES:
                raise ValueError
            source_external_ip = request["source_external_ip"]
            peer_binding_digest = request["peer_binding_digest"]
            if request["sip_mode"] == "registration":
                if source_external_ip is not None or peer_binding_digest is not None:
                    raise ValueError
            else:
                parsed_source = ipaddress.ip_address(source_external_ip)
                if parsed_source.version != 4 or not parsed_source.is_global:
                    raise ValueError
                if not isinstance(peer_binding_digest, str) or DIGEST_RE.fullmatch(peer_binding_digest) is None:
                    raise ValueError
            if request["contingency_direction"] not in {None, "outbound", "inbound"}:
                raise ValueError
        except (KeyError, TypeError, ValueError) as exc:
            raise RunnerError("execution_request_rejected") from exc
        return cls(
            organization_id, request["execution_seal_uuid"],
            request["execution_nonce_digest"], request["candidate_digest"],
            request["gate_envelope_digest"], request["destination_hmac_digest"],
            request["owned_target_sha256"], request["gate_envelope_uuid"], request["request_digest"],
            request["reserved_inbound_did_digest"],
            request["reserved_inbound_caller_digest"], request["policy_digest"],
            request["live_window_start"], request["live_window_end"],
            request["account_id"], request["application_id"], request["run_id"],
            request["attempt_id"], request["authority_deadline"],
            request["idempotency_key"], request["route_evidence_handle"],
            request["route_profile_digest"], request["request_mode"],
            request["answer_hook_url"], request["status_hook_url"],
            request["sip_mode"], request["source_external_ip"], request["peer_binding_digest"],
            request["contingency_direction"],
        )

    def binding(self) -> dict[str, Any]:
        return {
            "organization_id": self.organization_id,
            "execution_seal_uuid": self.seal,
            "execution_nonce_digest": self.nonce_digest,
            "candidate_digest": self.candidate_digest,
            "gate_envelope_digest": self.gate_digest,
        }

    def stages(self) -> tuple[tuple[str, int], ...]:
        return LEGACY_STAGES if self.sip_mode == "registration" else IP_TO_IP_STAGES

    def peer_binding(self) -> dict[str, Any]:
        if self.sip_mode != "ip_to_ip" or self.source_external_ip is None:
            raise RunnerError("peer_binding_unavailable")
        return {
            **self.binding(),
            "source_external_ip": self.source_external_ip,
            "peer_cidr": f"{self.source_external_ip}/32",
            "peer_port": PEER_PORT,
            "peer_transport": PEER_TRANSPORT,
            "owned_target_sha256": self.owned_target_sha256,
            "peer_binding_digest": self.peer_binding_digest,
        }


def validate_owned_target_binding(config: Config, secret_files: SecretFiles) -> None:
    try:
        read_private(secret_files.paths["sip-username"])
        owned_target = read_private(secret_files.paths["owned-target"])
        peer_material = canonical(
            {
                "source_external_ip": config.source_external_ip,
                "peer_cidr": f"{config.source_external_ip}/32" if config.source_external_ip else None,
                "peer_port": PEER_PORT,
                "peer_transport": PEER_TRANSPORT,
                "owned_target_sha256": config.owned_target_sha256,
            }
        )
        authority_deadline = datetime.fromisoformat(
            config.authority_deadline.replace("Z", "+00:00")
        )
        if (
            authority_deadline.tzinfo is None
            or authority_deadline.utcoffset() is None
            or config.request_mode != "diagnostic"
            or not hmac.compare_digest(
                hashlib.sha256(owned_target).hexdigest(), config.owned_target_sha256
            )
            or (
                config.sip_mode == "ip_to_ip"
                and not hmac.compare_digest(
                    hashlib.sha256(peer_material).hexdigest(), config.peer_binding_digest or ""
                )
            )
        ):
            raise ValueError
    except (KeyError, TypeError, UnicodeDecodeError, ValueError) as exc:
        raise RunnerError("owned_target_binding_rejected") from exc

class Runner:
    def __init__(
        self,
        config: Config,
        api: JsonClient,
        barrier: Barrier,
        secret_files: SecretFiles,
        broker: TransactionBroker,
    ) -> None:
        self.config = config
        self.api = api
        self.barrier = barrier
        self.execution_key = load_execution_key()
        self.secret_files = secret_files
        self.broker = broker
        self.register_completed = False
        self.runtime_started = False
        self.peer_attached = False
        self.contained = False
        self.active_calls: list[dict[str, Any]] = []
        self.registration_attestation: str | None = None
        self.stage_receipts: list[dict[str, Any]] = []
        self.containment_receipt: dict[str, Any] | None = None

        self.call_intervals: list[tuple[int, int]] = []
        self.provider_call_ids: set[str] = set()
        self.provider_call_attempts = 0
        self.contingency_used = False
        self.mandatory_call_failures: set[str] = set()
        self.register_receipt: dict[str, Any] | None = None
        self.stages_attempted: set[str] = set()
        self.stage_uuids: dict[str, str] = {}

    def _signed_payload(
        self,
        receipt: dict[str, Any],
        *,
        kind: str,
        expected: dict[str, Any],
    ) -> dict[str, Any]:
        if set(receipt) != {"payload", "signature"}:
            raise RunnerError("signed_evidence_rejected")
        payload = receipt["payload"]
        signature = receipt["signature"]
        if not isinstance(payload, dict) or not isinstance(signature, dict):
            raise RunnerError("signed_evidence_rejected")
        if set(signature) != {"algorithm", "key_id", "value"}:
            raise RunnerError("signed_evidence_rejected")
        if signature["algorithm"] != "Ed25519" or signature["key_id"] != EXECUTION_KEY_ID:
            raise RunnerError("signed_evidence_rejected")
        if payload.get("kind") != kind or any(payload.get(key) != value for key, value in expected.items()):
            raise RunnerError("signed_evidence_rejected")
        try:
            encoded = base64.b64decode(signature["value"], validate=True)
            Ed25519PublicKey.from_public_bytes(self.execution_key).verify(encoded, canonical(payload))
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise RunnerError("signed_evidence_rejected") from exc
        return payload

    def _record_signed_stage(self, name: str, receipt: dict[str, Any]) -> None:
        if receipt.get("payload", {}).get("stage") != name:
            raise RunnerError("stage_receipt_binding_rejected")
        self.stage_receipts.append(receipt)

    def _stage(
        self,
        name: str,
        ordinal: int,
        action: Callable[[float | None], dict[str, Any]],
        *,
        allow_recovery: bool = False,
    ) -> None:
        if name in self.stages_attempted:
            raise RunnerError("duplicate_stage_rejected")
        self.stages_attempted.add(name)
        binding = self.config.binding()
        stage_deadline = time.monotonic() + STAGE_DEADLINE_SECONDS
        start = self.api.post(
            "/execution/stage/start",
            {
                **binding,
                "stage": name,
                "ordinal": ordinal,
                "stage_deadline_seconds": STAGE_DEADLINE_SECONDS,
            },
            deadline=stage_deadline,
        )
        start_payload = self._signed_payload(
            start,
            kind="stage_start",
            expected={
                **binding,
                "stage": name,
                "ordinal": ordinal,
                "stage_deadline_seconds": STAGE_DEADLINE_SECONDS,
            },
        )
        stage_uuid = start_payload.get("stage_uuid")
        try:
            if str(uuid.UUID(str(stage_uuid))) != stage_uuid:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise RunnerError("stage_start_rejected") from exc
        self.stage_uuids[name] = stage_uuid
        if start_payload.get("state") != "started" or (
            start_payload.get("recovered") is not False and not allow_recovery
        ):
            raise RunnerError("stage_recovery_rejected")
        label(f"{name}_started")
        action(stage_deadline)
        status_deadline = stage_deadline
        while time.monotonic() < status_deadline:
            try:
                receipt = self.api.post(
                    "/execution/stage/status",
                    {
                        **binding,
                        "stage": name,
                        "ordinal": ordinal,
                        "stage_deadline_seconds": STAGE_DEADLINE_SECONDS,
                    },
                    deadline=status_deadline,
                )
                payload = self._signed_payload(
                    receipt,
                    kind="stage_status",
                    expected={
                        **binding,
                        "stage": name,
                        "ordinal": ordinal,
                        "stage_uuid": stage_uuid,
                        "stage_deadline_seconds": STAGE_DEADLINE_SECONDS,
                    },
                )
            except RunnerError:
                time.sleep(min(0.1, max(0, status_deadline - time.monotonic())))
                continue
            if payload.get("state") == "succeeded":
                self._accept_stage_receipt(name, ordinal, payload)
                self._record_signed_stage(name, receipt)
                label(f"{name}_succeeded")
                return
            if payload.get("state") not in {"pending", "started"}:
                raise RunnerError("stage_status_rejected")
            time.sleep(min(0.1, max(0, status_deadline - time.monotonic())))
        if name in {"outbound_call", "inbound_call"}:
            self._hangup_active(stage_deadline, self.active_calls[-1:])
        raise RunnerError("stage_status_unavailable")

    def _accept_stage_receipt(self, name: str, ordinal: int, receipt: dict[str, Any]) -> None:
        expected = {
            **self.config.binding(),
            "stage": name,
            "ordinal": ordinal,
            "stage_deadline_seconds": STAGE_DEADLINE_SECONDS,
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise RunnerError("stage_receipt_binding_rejected")
        if receipt.get("stage_uuid") != self.stage_uuids.get(name):
            raise RunnerError("stage_receipt_binding_rejected")
        terminal_class = {
            "register": "registered",
            "outbound_call": "call_completed",
            "inbound_call": "inbound_bound",
            "unregister": "unregistered",
        }[name]
        if receipt.get("state") != "succeeded" or receipt.get("terminal_class") != terminal_class:
            raise RunnerError("stage_receipt_terminal_rejected")
        if name in {"outbound_call", "inbound_call"}:
            call_id = receipt.get("provider_call_id_digest")
            started = receipt.get("started_monotonic_ms")
            ended = receipt.get("ended_monotonic_ms")
            required_digests = (
                "provider_call_id_digest", "status_artifact_digest", "cdr_artifact_digest",
                "human_rx_artifact_digest", "human_rx_acknowledgement_artifact_digest",
                "human_tx_artifact_digest", "human_tx_acknowledgement_artifact_digest",
            )
            if (
                any(not isinstance(receipt.get(field), str) or DIGEST_RE.fullmatch(receipt[field]) is None for field in required_digests)
                or call_id in self.provider_call_ids
                or type(started) is not int
                or type(ended) is not int
                or not 0 < ended - started <= 60_000
                or (self.call_intervals and started < self.call_intervals[-1][1])
                or receipt.get("retry_count") != 0
                or receipt.get("concurrency_count") != 1
                or type(receipt.get("billed_duration_ms")) is not int
                or not 0 <= receipt["billed_duration_ms"] <= ended - started
                or type(receipt.get("human_rx_duration_ms")) is not int
                or not 0 < receipt["human_rx_duration_ms"] <= ended - started
                or receipt.get("human_rx_acknowledgement") != "redacted_heard"
                or type(receipt.get("human_tx_duration_ms")) is not int
                or not 0 < receipt["human_tx_duration_ms"] <= ended - started
                or receipt.get("human_tx_acknowledgement") != "redacted_spoke"
                or receipt["human_rx_artifact_digest"] == receipt["human_tx_artifact_digest"]
                or receipt["human_rx_acknowledgement_artifact_digest"]
                == receipt["human_tx_acknowledgement_artifact_digest"]
                or receipt.get("terminal_status") != "terminal"
            ):
                raise RunnerError("call_stage_evidence_rejected")
            self.provider_call_ids.add(call_id)
            self.call_intervals.append((started, ended))
        if name == "register":
            gate_id = receipt.get("registration_gate_id")
            operation_uuid = receipt.get("registration_operation_uuid")
            if not isinstance(gate_id, int) or gate_id <= 0:
                raise RunnerError("registration_receipt_rejected")
            try:
                if str(uuid.UUID(str(operation_uuid))) != operation_uuid:
                    raise ValueError
            except (TypeError, ValueError) as exc:
                raise RunnerError("registration_receipt_rejected") from exc
            broker_registration = {
                "registration_gate_id": gate_id,
                "operation_uuid": operation_uuid,
            }
            if self.register_receipt is not None and self.register_receipt != broker_registration:
                raise RunnerError("registration_receipt_binding_rejected")
            self.register_receipt = broker_registration

    def _registration(self, operation: str, deadline: float | None = None) -> dict[str, Any]:
        ordinal = 1 if operation == "register" else 4
        if deadline is None:
            raise RunnerError("registration_deadline_missing")
        stage_uuid = self.stage_uuids.get(operation)
        if stage_uuid is None:
            raise RunnerError("registration_stage_linkage_missing")
        payload: dict[str, Any] = {
            **self.config.binding(), "envelope_uuid": self.config.envelope_uuid,
            "operation_kind": operation, "request_digest": self.config.request_digest,
            "nonce_digest": self.config.nonce_digest,
            "execution_stage_uuid": stage_uuid, "execution_stage": operation,
            "execution_stage_ordinal": ordinal,
        }
        if operation == "unregister":
            if self.register_receipt is None:
                raise RunnerError("unregister_linkage_missing")
            payload.update(
                prior_register_gate_id=self.register_receipt["registration_gate_id"],
                prior_register_operation_uuid=self.register_receipt["operation_uuid"],
            )
        authorization = self.api.post("/registration/begin", payload, deadline=deadline)
        operation_uuid = authorization.get("operation_uuid")
        gate_id = authorization.get("registration_gate_id")
        try:
            if str(uuid.UUID(str(operation_uuid))) != operation_uuid:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise RunnerError("registration_authority_rejected") from exc
        if (
            authorization.get("operation_kind") != operation
            or not isinstance(gate_id, int)
            or gate_id <= 0
        ):
            raise RunnerError("registration_authority_rejected")
        opaque = authorization.get("opaque_authorization")
        if not isinstance(opaque, str) or not opaque:
            raise RunnerError("registration_authority_rejected")
        if operation == "register":
            self.register_receipt = {
                "registration_gate_id": gate_id,
                "operation_uuid": operation_uuid,
            }
        proof = {
            **self.config.binding(),
            "schema_version": REGISTRATION_HANDOFF_SCHEMA,
            "stage": operation,
            "ordinal": ordinal,
            "operation_kind": operation,
            "request_digest": self.config.request_digest,
            "registration_gate_id": gate_id,
            "operation_uuid": operation_uuid,
            "prior_register_gate_id": payload.get("prior_register_gate_id"),
            "prior_register_operation_uuid": payload.get("prior_register_operation_uuid"),
            "opaque_authorization": opaque,
        }
        receipt = self.broker.consume(proof, deadline)
        opaque_attestation = receipt.get("opaque_execution_attestation")
        if not isinstance(opaque_attestation, str) or not opaque_attestation:
            raise RunnerError("registration_attestation_missing")
        if operation == "register":
            self.registration_attestation = opaque_attestation
            self.register_completed = True
        return receipt

    def _unregister_after_registered_failure(self) -> None:
        if not self.register_completed or "unregister" in self.stages_attempted:
            return
        self._stage("unregister", 4, lambda deadline: self._registration("unregister", deadline))

    def _attach_peer(self, deadline: float | None) -> dict[str, Any]:
        if deadline is None or self.config.sip_mode != "ip_to_ip" or self.peer_attached:
            raise RunnerError("peer_attach_rejected")
        binding = self.config.peer_binding()
        acknowledgement = self.api.post(
            "/v1/g008/ip-peer/attach",
            {**binding, "retry_count": 0, "concurrency_count": 1, "deadline_seconds": 60},
            facade=True,
            deadline=deadline,
        )
        self._signed_payload(
            acknowledgement,
            kind="ip_peer_attachment",
            expected={**binding, "state": "attached"},
        )
        self.peer_attached = True
        return acknowledgement

    def _detach_peer(self, deadline: float) -> None:
        if not self.peer_attached:
            return
        binding = self.config.peer_binding()
        acknowledgement = self.api.post(
            "/v1/g008/ip-peer/detach", binding, facade=True, deadline=deadline
        )
        self._signed_payload(
            acknowledgement,
            kind="ip_peer_detachment",
            expected={**binding, "state": "detached"},
        )
        self.peer_attached = False


    def _call(self, direction: str, deadline: float | None, *, contingency: bool = False) -> dict[str, Any]:
        if deadline is None:
            raise RunnerError("call_deadline_missing")
        stage_uuid = self.stage_uuids.get(f"{direction}_call")
        if stage_uuid is None:
            raise RunnerError("call_stage_linkage_missing")
        if self.provider_call_attempts >= 3:
            raise RunnerError("provider_call_budget_rejected")
        if contingency:
            if (
                self.contingency_used
                or self.config.contingency_direction != direction
                or direction not in self.mandatory_call_failures
            ):
                raise RunnerError("contingency_rejected")
            self.contingency_used = True
        elif direction in self.mandatory_call_failures:
            raise RunnerError("automatic_retry_rejected")
        self.provider_call_attempts += 1
        if direction == "outbound":
            try:
                from_address = read_private(self.secret_files.paths["sip-username"]).decode("utf-8")
                to_address = read_private(self.secret_files.paths["owned-target"]).decode("utf-8")
            except (KeyError, UnicodeDecodeError) as exc:
                raise RunnerError("outbound_private_input_rejected") from exc
            path = OUTBOUND_ROUTE_TEMPLATE.format(account_id=self.config.account_id)
            payload = {
                "contract_version": "recova-jambonz-facade-v1",
                "organization_id": self.config.organization_id,
                "application_id": self.config.application_id,
                "run_id": self.config.run_id,
                "attempt_id": self.config.attempt_id,
                "direction": "outbound",
                "authority_deadline": self.config.authority_deadline,
                "idempotency_key": self.config.idempotency_key,
                "candidate_digest": self.config.candidate_digest,
                "gate_envelope_digest": self.config.gate_digest,
                "request_mode": "diagnostic",
                "route_evidence_handle": self.config.route_evidence_handle,
                "route_profile_digest": self.config.route_profile_digest,
                "from_address": from_address,
                "to_address": to_address,
                "answer_hook_url": self.config.answer_hook_url,
                "status_hook_url": self.config.status_hook_url,
                "ring_timeout_seconds": 30,
                "time_limit_seconds": STAGE_DEADLINE_SECONDS,
            }
        else:
            path = INBOUND_ROUTE
            payload = {
                **self.config.binding(),
                "execution_stage_uuid": stage_uuid,
                "reserved_inbound_did_digest": self.config.reserved_did_digest,
                "reserved_inbound_caller_digest": self.config.reserved_caller_digest,
                "direction": "inbound",
                "retry_count": 0,
                "concurrency_count": 1,
                "call_deadline_seconds": STAGE_DEADLINE_SECONDS,
            }
        response = self.api.post(
            path,
            payload,
            facade=True,
            deadline=deadline - 5,
        )
        context = response.get("context")
        if not isinstance(context, dict):
            raise RunnerError(f"{direction}_context_rejected")
        self.active_calls.append(context)
        self.barrier.wait(f"ack_{direction}", deadline - 5)
        return response

    def _mandatory_call(self, direction: str, deadline: float | None) -> dict[str, Any]:
        try:
            return self._call(direction, deadline)
        except RunnerError:
            self.mandatory_call_failures.add(direction)
            if self.config.contingency_direction != direction or deadline is None:
                raise
            self.barrier.wait(f"authorize_contingency_{direction}", deadline - 5)
            return self._call(direction, deadline, contingency=True)

    def _outbound(self, deadline: float | None) -> dict[str, Any]:
        return self._mandatory_call("outbound", deadline)

    def _inbound(self, deadline: float | None) -> dict[str, Any]:
        return self._mandatory_call("inbound", deadline)

    def _hangup_active(self, deadline: float, contexts: list[dict[str, Any]] | None = None) -> None:
        binding = self.config.binding()
        for context in self.active_calls if contexts is None else contexts:
            acknowledgement = self.api.post(
                "/v1/g008/calls/hangup",
                {**binding, "context": context, "deadline_seconds": max(1, int(deadline - time.monotonic()))},
                facade=True,
                deadline=deadline,
            )
            context_digest = hashlib.sha256(canonical(context)).hexdigest()
            self._signed_payload(
                acknowledgement,
                kind="hangup",
                expected={**binding, "context_digest": context_digest, "state": "terminated"},
            )

    def _contain(self) -> None:
        if self.contained:
            return
        binding = self.config.binding()
        deadline = time.monotonic() + 10
        failures: list[Exception] = []
        for context in self.active_calls:
            try:
                self._hangup_active(deadline, [context])
            except Exception as exc:
                failures.append(exc)
            try:
                acknowledgement = self.api.post(
                    "/containment",
                    {"context": context, "category": "containment_required", **binding},
                    deadline=deadline,
                )
                context_digest = hashlib.sha256(canonical(context)).hexdigest()
                self._signed_payload(
                    acknowledgement,
                    kind="context_containment",
                    expected={**binding, "context_digest": context_digest, "state": "contained"},
                )
            except Exception as exc:
                failures.append(exc)
        try:
            self._detach_peer(deadline)
        except Exception as exc:
            failures.append(exc)
        try:
            acknowledgement = self.api.post(
                "/execution/contain",
                {**binding, "containment_class": "verified_terminal"},
                deadline=deadline,
            )
            self._signed_payload(
                acknowledgement,
                kind="execution_containment",
                expected={**binding, "state": "contained"},
            )
            self.containment_receipt = acknowledgement

        except Exception as exc:
            failures.append(exc)
        if failures:
            raise ExceptionGroup("containment_failures", failures)
        self.contained = True
        label("contained")

    def _execute(self) -> None:
        binding = self.config.binding()
        stages = self.config.stages()
        nonce_request = {**binding, "trusted_keyset_digest": TRUSTED_KEYSET_SHA256}
        consumed = self.api.post("/execution/nonce/consume", nonce_request)
        nonce_payload = self._signed_payload(
            consumed,
            kind="nonce_consumption",
            expected={**nonce_request, "state": "consumed", "pre_existing": False},
        )
        if set(nonce_payload) != {"kind", *nonce_request, "state", "pre_existing"}:
            raise RunnerError("nonce_consumption_schema_rejected")
        seal_request = {
            **binding,
            "schema_version": SCHEMA_VERSION,
            "destination_hmac_digest": self.config.destination_digest,
            "stages": [stage for stage, _ordinal in stages],
            "retry_count": 0,
            "concurrency_count": 1,
            "call_deadline_seconds": STAGE_DEADLINE_SECONDS,
            "stage_deadline_seconds": STAGE_DEADLINE_SECONDS,
            "live_window_starts_at": self.config.live_start,
            "live_window_expires_at": self.config.live_end,
            "reserved_inbound_did_digest": self.config.reserved_did_digest,
            "reserved_inbound_caller_digest": self.config.reserved_caller_digest,
            "policy_digest": self.config.policy_digest,
            "trusted_keyset_digest": TRUSTED_KEYSET_SHA256,
        }
        seal = self.api.post("/execution/seal", seal_request)
        seal_payload = self._signed_payload(
            seal,
            kind="execution_seal",
            expected={**seal_request, "state": "sealed", "pre_existing": False},
        )
        seal_fields = {
            "kind", *seal_request, "state", "pre_existing",
            "registration_attestation_key_id",
            "registration_attestation_public_key_sha256",
        }
        if set(seal_payload) != seal_fields:
            raise RunnerError("execution_seal_schema_rejected")
        if self.config.sip_mode == "registration":
            self.broker.configure_attestation(
                seal_payload["registration_attestation_key_id"],
                seal_payload["registration_attestation_public_key_sha256"],
            )
        label("sealed")
        self.runtime_started = True
        try:
            if self.config.sip_mode == "registration":
                self._stage("register", 1, lambda deadline: self._registration("register", deadline))
            else:
                self._attach_peer(time.monotonic() + STAGE_DEADLINE_SECONDS)
            outbound_ordinal = 2 if self.config.sip_mode == "registration" else 1
            inbound_ordinal = 3 if self.config.sip_mode == "registration" else 2
            self._stage("outbound_call", outbound_ordinal, self._outbound)
            self._stage("inbound_call", inbound_ordinal, self._inbound)
            if self.config.sip_mode == "registration":
                self._stage("unregister", 4, lambda deadline: self._registration("unregister", deadline))
            if (
                not 2 <= self.provider_call_attempts <= 3
                or len(self.provider_call_ids) != 2
                or len(self.call_intervals) != 2
            ):
                raise RunnerError("provider_call_budget_rejected")
            self._contain()
            if self.containment_receipt is None:
                raise RunnerError("execution_containment_missing")
            signed = self.api.post(
                "/execution/finalize-evidence",
                {
                    **binding,
                    "trusted_keyset_digest": TRUSTED_KEYSET_SHA256,
                    "stage_receipts": self.stage_receipts,
                    "containment_receipt": self.containment_receipt,
                    "containment_verified": True,
                },
            )

            payload = self._signed_payload(
                signed,
                kind="final_execution_evidence",
                expected={
                    **binding,
                    "state": "completed",
                    "trusted_keyset_digest": TRUSTED_KEYSET_SHA256,
                    "containment_verified": True,
                    "containment_receipt": self.containment_receipt,
                },
            )
            if payload.get("stage_receipts") != self.stage_receipts or len(self.stage_receipts) != len(stages):
                raise RunnerError("execution_evidence_binding_rejected")
            bundle = {
                "schema_version": "recova-g008-execution-bundle-v2",
                "trusted_keyset_digest": TRUSTED_KEYSET_SHA256,
                "nonce": consumed,
                "seal": seal,
                "stages": self.stage_receipts,
                "containment": self.containment_receipt,
                "final": signed,
            }
            bundle_bytes = canonical(bundle)
            write_exclusive(self.config.execution_bundle_path, bundle_bytes)
            exported = self.config.execution_bundle_path.read_bytes()
            if exported != bundle_bytes:
                raise RunnerError("execution_bundle_export_failed")
            label("evidence_finalized")
            label("completed")
        finally:
            cleanup_failures: list[Exception] = []
            try:
                self._unregister_after_registered_failure()
            except Exception as exc:
                cleanup_failures.append(exc)
            if not self.contained:
                try:
                    self._contain()
                except Exception as exc:
                    cleanup_failures.append(exc)
            self.runtime_started = False
            if cleanup_failures:
                raise ExceptionGroup("execution_cleanup_failures", cleanup_failures)

    def run(self) -> None:
        try:
            self._execute()
        finally:
            self.secret_files.erase()


def main(env: dict[str, str] | None = None) -> int:
    environ = dict(os.environ if env is None else env)
    secret_files: SecretFiles | None = None
    try:
        secret_files = SecretFiles(required(environ, "G008_SECRET_DIR"))
        config = Config.load(environ)
        private_inputs: dict[str, bytes] = {}
        for env_name, file_name in (
            ("G008_SIP_USERNAME_FILE", "sip-username"),
            ("G008_SIP_PASSWORD_FILE", "sip-password"),
            ("G008_SIP_REALM_FILE", "sip-realm"),
            ("G008_OWNED_TARGET_FILE", "owned-target"),
            ("G008_EXECUTION_NONCE_FILE", "execution-nonce"),
            ("G008_OPERATOR_CREDENTIAL_FILE", "operator-credential"),
        ):
            value = read_private(required(environ, env_name))
            private_inputs[file_name] = value
            secret_files.put(file_name, value)
        if not hmac.compare_digest(
            hashlib.sha256(private_inputs["execution-nonce"]).hexdigest(),
            config.nonce_digest,
        ):
            raise RunnerError("nonce_digest_rejected")
        validate_owned_target_binding(config, secret_files)
        ca_path = required(environ, "G008_F12_CLIENT_CA_CERTIFICATE_FILE")
        certificate_path = required(environ, "G008_F12_CLIENT_CERTIFICATE_FILE")
        key_path = required(environ, "G008_F12_CLIENT_KEY_FILE")
        endpoint_credential = read_private(
            required(environ, "G008_F12_ENDPOINT_CREDENTIAL_FILE")
        )
        read_private(ca_path)
        read_private(certificate_path)
        read_private(key_path)
        context = ssl.create_default_context(cafile=ca_path)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(certificate_path, key_path)
        api = JsonClient(context, endpoint_credential)
        smoke_runner = Runner(
            config,
            api,
            Barrier(
                required(environ, "G008_BARRIER_SOCKET"),
                private_inputs["operator-credential"],
            ),
            secret_files,
            TransactionBroker(),
        )
        api.wait_ready(time.monotonic() + 60)
        secret_files = None
        smoke_runner.run()
        return 0
    except Exception:
        if secret_files is not None:
            secret_files.erase()
        label("failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
