from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest


class _FakeFormRequest:
    def __init__(self, form_data: dict):
        self._form_data = form_data
        self.headers = {}
        self.url = "https://api.example.com/api/v1/telephony/status"

    async def form(self):
        return self._form_data


class _FakeJsonRequest:
    def __init__(self, json_data: dict):
        self._json_data = json_data
        self.headers = {"content-type": "application/json"}
        self.url = "https://api.example.com/api/v1/telephony/status"

    async def body(self):
        import json

        return json.dumps(self._json_data).encode()

    async def json(self):
        return self._json_data


@pytest.mark.asyncio
async def test_twilio_status_callback_log_redacts_raw_numbers_before_signature():
    from api.services.telephony.providers.twilio.routes import (
        handle_twilio_status_callback,
    )

    raw_to = "+821012345678"
    raw_from = "+82200000000"
    callback_data = {
        "CallSid": "CA123",
        "CallStatus": "ringing",
        "To": raw_to,
        "From": raw_from,
        "nested": {"phone_number": raw_to},
    }
    workflow_run = SimpleNamespace(id=100, workflow_id=33)
    workflow = SimpleNamespace(id=33, organization_id=11)
    provider = SimpleNamespace(
        verify_inbound_signature=AsyncMock(return_value=True),
        parse_status_callback=Mock(
            return_value={
                "call_id": "CA123",
                "status": "ringing",
                "from_number": raw_from,
                "to_number": raw_to,
                "extra": callback_data,
            }
        ),
    )

    with (
        patch("api.services.telephony.providers.twilio.routes.logger") as logger,
        patch("api.services.telephony.providers.twilio.routes.db_client") as mock_db,
        patch(
            "api.services.telephony.providers.twilio.routes.get_telephony_provider_for_run",
            new=AsyncMock(return_value=provider),
        ),
        patch(
            "api.services.telephony.providers.twilio.routes._process_status_update",
            new=AsyncMock(),
        ),
    ):
        mock_db.get_workflow_run_by_id = AsyncMock(return_value=workflow_run)
        mock_db.get_workflow_by_id = AsyncMock(return_value=workflow)

        response = await handle_twilio_status_callback(
            100, _FakeFormRequest(callback_data)
        )

    assert response == {"status": "success"}
    logged = " ".join(str(call.args) for call in logger.info.call_args_list)
    assert raw_to not in logged
    assert raw_from not in logged
    assert "[redacted]" in logged


def test_normalized_inbound_log_summary_redacts_raw_numbers():
    from api.routes.telephony import _normalized_inbound_data_for_logs

    raw_to = "+821012345678"
    raw_from = "+82200000000"
    normalized_data = SimpleNamespace(
        provider="twilio",
        call_id="CA123",
        from_number=raw_from,
        to_number=raw_to,
        direction="inbound",
        call_status="ringing",
        account_id="ACSECRET",
        from_country="KR",
        to_country="KR",
        raw_data={
            "From": raw_from,
            "To": raw_to,
            "AccountSid": "ACSECRET",
            "nested": {"phone_number": raw_to},
        },
    )

    logged = _normalized_inbound_data_for_logs(normalized_data)

    assert raw_to not in str(logged)
    assert raw_from not in str(logged)
    assert "ACSECRET" not in str(logged)
    assert logged["from_number"] == "[redacted]"
    assert logged["to_number"] == "[redacted]"
    assert logged["account_id"] == "[redacted]"
    assert logged["raw_data"]["From"] == "[redacted]"
    assert logged["raw_data"]["To"] == "[redacted]"
    assert logged["raw_data"]["AccountSid"] == "[redacted]"
    assert logged["raw_data"]["nested"]["phone_number"] == "[redacted]"


@pytest.mark.asyncio
async def test_vobiz_ring_callback_persists_redacted_raw_data():
    from api.services.telephony.providers.vobiz.routes import (
        handle_vobiz_ring_callback,
    )

    raw_to = "+821012345678"
    raw_from = "+82200000000"
    callback_data = {
        "call_uuid": "call-123",
        "from": raw_from,
        "to": raw_to,
        "destination_number": raw_to,
        "status": "ringing",
    }
    workflow_run = SimpleNamespace(
        id=100,
        workflow_id=33,
        logs={"telephony_status_callbacks": []},
    )

    with patch(
        "api.services.telephony.providers.vobiz.routes.db_client"
    ) as mock_db:
        mock_db.get_workflow_run_by_id = AsyncMock(return_value=workflow_run)
        mock_db.update_workflow_run = AsyncMock()

        response = await handle_vobiz_ring_callback(
            100, _FakeJsonRequest(callback_data)
        )

    assert response == {"status": "success"}
    logs = mock_db.update_workflow_run.await_args.kwargs["logs"][
        "telephony_status_callbacks"
    ]
    raw_data = logs[0]["raw_data"]
    assert raw_to not in str(raw_data)
    assert raw_from not in str(raw_data)
    assert raw_data["from"] == "[redacted]"
    assert raw_data["to"] == "[redacted]"
    assert raw_data["destination_number"] == "[redacted]"


@pytest.mark.asyncio
async def test_vobiz_hangup_parsed_log_redacts_raw_numbers():
    from api.services.telephony.providers.vobiz.routes import (
        handle_vobiz_hangup_callback,
    )

    raw_to = "+821012345678"
    raw_from = "+82200000000"
    callback_data = {
        "call_uuid": "call-123",
        "from": raw_from,
        "to": raw_to,
        "destination_number": raw_to,
        "status": "completed",
    }
    parsed_data = {
        "call_id": "call-123",
        "status": "completed",
        "from_number": raw_from,
        "to_number": raw_to,
        "direction": "outbound",
        "duration": "31",
        "extra": callback_data,
    }
    workflow_run = SimpleNamespace(id=100, workflow_id=33)
    workflow = SimpleNamespace(id=33, organization_id=11)
    provider = SimpleNamespace(
        PROVIDER_NAME="vobiz",
        parse_status_callback=Mock(return_value=parsed_data),
    )

    with (
        patch("api.services.telephony.providers.vobiz.routes.logger") as logger,
        patch("api.services.telephony.providers.vobiz.routes.db_client") as mock_db,
        patch(
            "api.services.telephony.providers.vobiz.routes.get_telephony_provider_for_run",
            new=AsyncMock(return_value=provider),
        ),
        patch(
            "api.services.telephony.providers.vobiz.routes._process_status_update",
            new=AsyncMock(),
        ),
    ):
        mock_db.get_workflow_run_by_id = AsyncMock(return_value=workflow_run)
        mock_db.get_workflow_by_id = AsyncMock(return_value=workflow)

        response = await handle_vobiz_hangup_callback(
            100, _FakeJsonRequest(callback_data)
        )

    assert response == {"status": "success"}
    logged = " ".join(str(call.args) for call in logger.debug.call_args_list)
    assert raw_to not in logged
    assert raw_from not in logged
    assert "[redacted]" in logged


@pytest.mark.asyncio
async def test_cloudonix_cdr_log_redacts_raw_numbers():
    from api.services.telephony.providers.cloudonix.routes import handle_cloudonix_cdr

    raw_to = "+821012345678"
    raw_from = "+82200000000"
    cdr_data = {
        "domain": "voice.example.com",
        "session": {"token": "call-123"},
        "disposition": "ANSWER",
        "from": raw_from,
        "to": raw_to,
        "destination_number": raw_to,
        "duration": 30,
        "billsec": 20,
    }
    workflow_run = SimpleNamespace(id=100)

    with (
        patch("api.services.telephony.providers.cloudonix.routes.logger") as logger,
        patch(
            "api.services.telephony.providers.cloudonix.routes.db_client"
        ) as mock_db,
        patch(
            "api.services.telephony.providers.cloudonix.routes._process_status_update",
            new=AsyncMock(),
        ),
    ):
        mock_db.get_workflow_run_by_call_id = AsyncMock(return_value=workflow_run)

        response = await handle_cloudonix_cdr(_FakeJsonRequest(cdr_data))

    assert response == {"status": "success"}
    logged = " ".join(str(call.args) for call in logger.info.call_args_list)
    assert raw_to not in logged
    assert raw_from not in logged
    assert "[redacted]" in logged
