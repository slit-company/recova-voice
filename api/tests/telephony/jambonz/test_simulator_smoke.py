from api.services.telephony.providers.jambonz.simulator_smoke import (
    run_jambonz_contract_smoke,
)


def test_jambonz_contract_smoke_passes_without_live_carrier():
    result = run_jambonz_contract_smoke()

    assert result.passed is True
    assert {check.name for check in result.checks} >= {
        "signed_inbound_fixture_verifies",
        "replay_guard_rejects_duplicate_nonce",
        "simulator_live_validation_injection_stripped",
        "operator_attestation_counts_as_live",
        "signed_cdr_fixture_verifies_and_is_terminal",
    }
    assert all(check.passed for check in result.checks)
