import asyncio
import json
import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import api.services as api_services

telephony_pkg = types.ModuleType("api.services.telephony")
telephony_pkg.__path__ = ["api/services/telephony"]
sys.modules.setdefault("api.services.telephony", telephony_pkg)
setattr(api_services, "telephony", telephony_pkg)

import api.services.telephony.admission as admission_module
import api.services.telephony.cdr as cdr_module
import api.services.telephony.ops_alerts as ops_alerts_module
from api.services.telephony.admission import (
    TelephonyAdmissionController,
    TelephonyAdmissionRequest,
)
from api.services.telephony.cdr import (
    TelephonyFailureCategory,
    live_readiness_eligible,
    record_rejected_call,
)
from api.services.telephony.evidence_markers import (
    build_trusted_live_validation_markers,
    extract_telephony_evidence_markers,
    strip_untrusted_evidence_fields,
)
from api.services.telephony.ops_alerts import (
    TelephonyOpsAlert,
    TelephonyOpsAlertSeverity,
    TelephonyOpsAlertSink,
    TelephonyOpsAlertType,
)


class _FakeRedis:
    def __init__(self):
        self.hashes = {}
        self.strings = {}
        self.zsets = {}

    async def eval(self, script, numkeys, *args):
        keys = list(args[:numkeys])
        argv = list(args[numkeys:])
        if "payload_start" in script:
            return self._eval_acquire(keys, argv)
        return self._eval_release(keys)

    async def get(self, key):
        return self.strings.get(key)

    def _eval_acquire(self, keys, argv):
        slot_key, workflow_key = keys
        slot_id = argv[3]
        dimension_count = int(argv[4])
        if slot_key in self.hashes:
            return [1, self.hashes[slot_key]["slot_id"], "existing"]

        dimension_args = argv[5 : 5 + (dimension_count * 2)]
        dimensions = [
            (dimension_args[index], int(dimension_args[index + 1]))
            for index in range(0, len(dimension_args), 2)
        ]
        for key, limit in dimensions:
            if len(self.zsets.get(key, set())) >= limit:
                return [0, "", key]

        for key, _limit in dimensions:
            self.zsets.setdefault(key, set()).add(slot_id)

        payload_args = argv[5 + (dimension_count * 2) :]
        payload = {
            payload_args[index]: payload_args[index + 1]
            for index in range(0, len(payload_args), 2)
        }
        self.hashes[slot_key] = payload
        if workflow_key:
            self.strings[workflow_key] = slot_key
        return [1, slot_id, "acquired"]

    def _eval_release(self, keys):
        slot_key = keys[0]
        payload = self.hashes.get(slot_key)
        if not payload:
            return [0, "", "", "", "", "", "", "", "", ""]

        slot_id = payload["slot_id"]
        for key in json.loads(payload["dimensions"]):
            self.zsets.get(key, set()).discard(slot_id)
        del self.hashes[slot_key]
        workflow_run_id = payload.get("workflow_run_id") or ""
        if workflow_run_id:
            self.strings.pop(f"telephony_admission:workflow_run:{workflow_run_id}", None)
        return [
            1,
            slot_id,
            payload["call_attempt_id"],
            payload["provider"],
            payload["organization_id"],
            payload["direction"],
            workflow_run_id,
            payload.get("telephony_configuration_id", ""),
            payload.get("telephony_phone_number_id", ""),
            payload.get("contract_version", ""),
        ]


def test_admission_acquire_is_idempotent_and_release_is_idempotent(monkeypatch):
    async def run():
        recorded_events = AsyncMock()
        monkeypatch.setattr(
            admission_module, "record_telephony_event", recorded_events
        )
        controller = TelephonyAdmissionController(
            redis_client=_FakeRedis(), alert_sink=SimpleNamespace(emit=AsyncMock())
        )

        request = TelephonyAdmissionRequest(
            provider="jambonz",
            organization_id=42,
            direction="inbound",
            workflow_run_id=777,
        )

        first = await controller.acquire(request)
        second = await controller.acquire(request)
        released = await controller.release(workflow_run_id=777, reason="completed")
        released_again = await controller.release(
            workflow_run_id=777, reason="completed"
        )

        assert first.allowed is True
        assert second.allowed is True
        assert second.existing is True
        assert second.slot_id == first.slot_id
        assert released is True
        assert released_again is False
        assert recorded_events.await_count == 2

    asyncio.run(run())


def test_record_rejected_call_redacts_payload_and_keeps_attempt_identity(monkeypatch):
    async def run():
        mock_db = SimpleNamespace(
            record_telephony_call_event=AsyncMock(return_value=SimpleNamespace(id=1)),
            upsert_telephony_cdr=AsyncMock(return_value=SimpleNamespace(id=2)),
        )
        monkeypatch.setattr(cdr_module, "db_client", mock_db)

        await record_rejected_call(
            provider="jambonz",
            direction="inbound",
            failure_category=TelephonyFailureCategory.SIGNATURE_FAILED,
            call_attempt_id="inbound:jambonz:attempt-1",
            provider_call_id="provider-call-secret",
            from_number="01012345678",
            to_number="07012345678",
            provider_payload={"signature": "secret", "nested": {"To": "07012345678"}},
        )

        event_kwargs = mock_db.record_telephony_call_event.await_args.kwargs
        cdr_kwargs = mock_db.upsert_telephony_cdr.await_args.kwargs
        assert event_kwargs["call_attempt_id"] == "inbound:jambonz:attempt-1"
        assert cdr_kwargs["call_attempt_id"] == "inbound:jambonz:attempt-1"
        assert event_kwargs["provider_call_id_hash"] != "provider-call-secret"
        assert event_kwargs["to_number_hash"] is not None
        assert event_kwargs["to_number_masked"].endswith("5678")
        assert event_kwargs["provider_payload_redacted"]["signature"] == "[redacted]"
        assert event_kwargs["provider_payload_redacted"]["nested"]["To"] == "[redacted]"

    asyncio.run(run())


def test_contract_fixtures_never_count_as_live_readiness():
    assert not live_readiness_eligible(
        SimpleNamespace(is_contract_fixture=True, live_trunk_validated=True)
    )
    assert not live_readiness_eligible(
        SimpleNamespace(is_contract_fixture=False, live_trunk_validated=False)
    )
    assert live_readiness_eligible(
        SimpleNamespace(is_contract_fixture=False, live_trunk_validated=True)
    )



def test_evidence_markers_strip_untrusted_live_validation_injection():
    markers = extract_telephony_evidence_markers(
        {
            "provider": "jambonz",
            "contract_version": "jambonz_contract_v1",
            "is_contract_fixture": True,
            "live_trunk_validated": True,
            "live_validation_source": "simulator",
            "live_validation_evidence_id": "fake-live-proof",
        },
        trusted_context={
            "telephony_configuration_id": 55,
            "telephony_phone_number_id": 902,
            "call_attempt_id": "inbound:jambonz:attempt-1",
        },
    )

    assert markers.provider == "jambonz"
    assert markers.contract_version == "jambonz_contract_v1"
    assert markers.is_contract_fixture is True
    assert markers.live_trunk_validated is False
    assert markers.live_validation_source is None
    assert markers.live_validation_evidence_id is None
    assert markers.telephony_configuration_id == 55
    assert markers.telephony_phone_number_id == 902
    assert markers.call_attempt_id == "inbound:jambonz:attempt-1"


def test_evidence_markers_accept_only_approved_live_validation_sources():
    rejected = build_trusted_live_validation_markers(
        provider="jambonz",
        live_validation_source="simulator",
        live_validation_evidence_id="fake-live-proof",
    )
    accepted = build_trusted_live_validation_markers(
        provider="jambonz",
        live_validation_source="operator_attestation",
        live_validation_evidence_id="ops-attestation-123",
    )

    assert rejected.live_trunk_validated is False
    assert accepted.live_trunk_validated is True
    assert accepted.live_validation_source == "operator_attestation"


def test_strip_untrusted_evidence_fields_removes_customer_marker_inputs():
    assert strip_untrusted_evidence_fields(
        {
            "phone_number": "+821012345678",
            "live_trunk_validated": True,
            "live_validation_source": "operator_attestation",
            "is_contract_fixture": False,
            "contract_version": "jambonz_contract_v1",
        }
    ) == {"phone_number": "+821012345678"}


def test_status_cdr_ignores_live_validation_from_context_and_callback(monkeypatch):
    async def run():
        mock_db = SimpleNamespace(
            record_telephony_call_event=AsyncMock(return_value=SimpleNamespace(id=1)),
            upsert_telephony_cdr=AsyncMock(return_value=SimpleNamespace(id=2)),
        )
        monkeypatch.setattr(cdr_module, "db_client", mock_db)

        workflow_run = SimpleNamespace(
            id=501,
            workflow_id=33,
            campaign_id=None,
            queued_run_id=None,
            mode="jambonz",
            call_type="outbound",
            workflow=SimpleNamespace(organization_id=11),
            initial_context={
                "provider": "jambonz",
                "direction": "outbound",
                "telephony_configuration_id": 55,
                "from_phone_number_id": 902,
                "telephony_call_attempt_id": "outbound:jambonz:attempt-1",
                "live_trunk_validated": True,
                "live_validation_source": "simulator",
                "live_validation_evidence_id": "fake-live-proof",
            },
            gathered_context={},
        )
        status = SimpleNamespace(
            status="completed",
            call_id="jb-call-secret",
            from_number="+827012345678",
            to_number="+821012345678",
            duration="42",
            extra={
                "contract_version": "jambonz_contract_v1",
                "is_contract_fixture": True,
                "live_trunk_validated": True,
                "live_validation_source": "simulator",
                "live_validation_evidence_id": "callback-fake-proof",
            },
        )

        await cdr_module.record_status_event_and_terminal_cdr(workflow_run, status)

        event_kwargs = mock_db.record_telephony_call_event.await_args.kwargs
        cdr_kwargs = mock_db.upsert_telephony_cdr.await_args.kwargs
        assert event_kwargs["live_trunk_validated"] is False
        assert cdr_kwargs["live_trunk_validated"] is False
        assert cdr_kwargs["is_contract_fixture"] is True
        assert cdr_kwargs["contract_version"] == "jambonz_contract_v1"
        assert cdr_kwargs["artifact_payload"]["evidence_markers"][
            "live_trunk_validated"
        ] is False

    asyncio.run(run())

def test_alert_sink_dedupes_and_never_pages_contract_simulator(monkeypatch):
    async def run():
        mock_db = SimpleNamespace(upsert_telephony_ops_alert=AsyncMock())
        monkeypatch.setattr(ops_alerts_module, "db_client", mock_db)
        sink = TelephonyOpsAlertSink(sink_name="db")

        await sink.emit(
            TelephonyOpsAlert(
                alert_type=TelephonyOpsAlertType.CONTRACT_SIMULATOR_REGRESSION,
                severity=TelephonyOpsAlertSeverity.CRITICAL,
                summary="Contract simulator status regression",
                provider="jambonz",
                source="contract_simulator",
                is_contract_fixture=True,
                details={"phone_number": "07012345678", "call_id": "secret"},
                dedupe_components=("status",),
            )
        )

        kwargs = mock_db.upsert_telephony_ops_alert.await_args.kwargs
        assert kwargs["should_page_live_ops"] is False
        assert kwargs["is_contract_fixture"] is True
        assert kwargs["details_redacted"]["phone_number"] == "[redacted]"
        assert kwargs["details_redacted"]["call_id"] == "[redacted]"
        assert "contract_simulator_regression" in kwargs["dedupe_key"]

    asyncio.run(run())
