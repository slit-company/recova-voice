from datetime import UTC, datetime
from types import SimpleNamespace

from api.services.reports.run_report import build_run_report_csv


def test_preview_run_report_csv_sanitizes_provider_context():
    run = SimpleNamespace(
        id=501,
        campaign_id=None,
        workflow_id=33,
        definition_id=44,
        created_at=datetime(2026, 5, 22, 10, 30, tzinfo=UTC),
        initial_context={
            "telephony_preview": True,
            "preview_session_id": 123,
            "phone_number": "+82****5678",
            "provider": "twilio",
            "telephony_configuration_id": 901,
        },
        gathered_context={
            "provider": "twilio",
            "call_id": "CA123",
            "mapped_call_disposition": "interested",
            "call_tags": ["preview"],
            "extracted_variables": {
                "safe_value": "ok",
                "provider_call_id": "CA123",
                "account_sid": "ACSECRET",
            },
        },
        cost_info={"call_duration_seconds": 42},
        public_access_token=None,
    )

    csv_text = build_run_report_csv([run]).getvalue()

    assert "+82****5678" in csv_text
    assert "safe_value" in csv_text
    assert "ok" in csv_text
    assert "CA123" not in csv_text
    assert "ACSECRET" not in csv_text
    assert "provider_call_id" not in csv_text
    assert "account_sid" not in csv_text
    assert "telephony_configuration_id" not in csv_text
