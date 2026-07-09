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

from api.services.telephony.admission import (
    TelephonyAdmissionController,
    TelephonyAdmissionRequest,
)
from api.services.telephony.cdr import (
    TelephonyFailureCategory,
    live_readiness_eligible,
    record_rejected_call,
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
            "api.services.telephony.admission.record_telephony_event", recorded_events
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
        monkeypatch.setattr("api.services.telephony.cdr.db_client", mock_db)

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


def test_alert_sink_dedupes_and_never_pages_contract_simulator(monkeypatch):
    async def run():
        mock_db = SimpleNamespace(upsert_telephony_ops_alert=AsyncMock())
        monkeypatch.setattr("api.services.telephony.ops_alerts.db_client", mock_db)
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
