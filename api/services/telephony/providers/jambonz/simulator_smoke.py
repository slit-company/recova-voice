"""Supplier-independent Jambonz contract smoke checks.

These checks intentionally avoid databases, Redis, live SIP trunks, and a running
Jambonz instance. They prove the local Recova contract fixtures still enforce the
pre-carrier trust boundary before a real Korean SIP/070 supplier is connected.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from api.services.telephony.evidence_markers import (
    build_trusted_live_validation_markers,
    extract_telephony_evidence_markers,
)
from api.services.telephony.providers.jambonz.contract import (
    JAMBONZ_REPLAY_TOLERANCE_SECONDS,
    JambonzContractSimulator,
    JambonzReplayGuard,
    canonical_json,
    verify_signed_payload,
)


@dataclass(frozen=True)
class JambonzContractSmokeCheck:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class JambonzContractSmokeResult:
    passed: bool
    checks: list[JambonzContractSmokeCheck]

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "checks": [asdict(check) for check in self.checks],
        }


def run_jambonz_contract_smoke() -> JambonzContractSmokeResult:
    """Run local smoke checks for the Jambonz contract trust boundary."""

    simulator = JambonzContractSimulator()
    checks: list[JambonzContractSmokeCheck] = []

    payload, headers, body = simulator.inbound()
    signed_now = _signed_now(headers)
    checks.append(
        _check(
            "signed_inbound_fixture_verifies",
            verify_signed_payload(
                simulator.webhook_secret, body, headers, now=signed_now
            ),
            "Signed inbound contract fixture verifies with the fixture secret.",
        )
    )

    replay_guard = JambonzReplayGuard()
    replay_now = _signed_now(headers)
    checks.append(
        _check(
            "replay_guard_accepts_first_nonce",
            verify_signed_payload(
                simulator.webhook_secret,
                body,
                headers,
                replay_guard=replay_guard,
                now=replay_now,
                replay_scope="smoke",
            ),
            "First signed callback with a nonce is accepted.",
        )
    )
    checks.append(
        _check(
            "replay_guard_rejects_duplicate_nonce",
            not verify_signed_payload(
                simulator.webhook_secret,
                body,
                headers,
                replay_guard=replay_guard,
                now=replay_now,
                replay_scope="smoke",
            ),
            "Second callback with the same nonce is rejected as replay.",
        )
    )

    checks.append(
        _check(
            "expired_signature_rejected",
            not verify_signed_payload(
                simulator.webhook_secret,
                body,
                headers,
                now=signed_now + JAMBONZ_REPLAY_TOLERANCE_SECONDS + 2,
            ),
            "Callback outside timestamp tolerance is rejected.",
        )
    )

    malformed_payload, malformed_headers, malformed_body = simulator.malformed_signature()
    checks.append(
        _check(
            "malformed_signature_rejected",
            not verify_signed_payload(
                simulator.webhook_secret,
                malformed_body,
                malformed_headers,
                now=_signed_now(malformed_headers),
            ),
            f"Malformed signature for call {malformed_payload.get('call_id')} is rejected.",
        )
    )

    inbound_markers = extract_telephony_evidence_markers(
        payload,
        headers,
        trusted_context={
            "provider": "jambonz",
            "telephony_configuration_id": 901,
            "telephony_phone_number_id": 902,
            "inventory_id": 903,
            "call_attempt_id": "inbound:jambonz:smoke",
        },
    )
    checks.append(
        _check(
            "fixture_markers_do_not_count_as_live",
            inbound_markers.is_contract_fixture
            and not inbound_markers.live_trunk_validated
            and not _live_readiness_eligible(inbound_markers),
            "Contract fixtures are tagged as fixtures and excluded from live readiness.",
        )
    )

    injected_payload, _, _ = simulator.status_live_validation_injection()
    injected_markers = extract_telephony_evidence_markers(
        injected_payload,
        trusted_context={
            "provider": "jambonz",
            "telephony_configuration_id": 901,
            "telephony_phone_number_id": 902,
            "inventory_id": 903,
            "call_attempt_id": "outbound:jambonz:smoke",
        },
    )
    checks.append(
        _check(
            "simulator_live_validation_injection_stripped",
            not injected_markers.live_trunk_validated
            and injected_markers.live_validation_source is None
            and injected_markers.live_validation_evidence_id is None,
            "Simulator/callback live-validation claims are stripped unless trusted.",
        )
    )

    trusted_markers = build_trusted_live_validation_markers(
        provider="jambonz",
        live_validation_source="operator_attestation",
        live_validation_evidence_id="real-route-cdr-001",
        contract_version="jambonz_contract_v1",
        telephony_configuration_id=901,
        telephony_phone_number_id=902,
        inventory_id=903,
        call_attempt_id="outbound:jambonz:real-route-001",
    )
    checks.append(
        _check(
            "operator_attestation_counts_as_live",
            trusted_markers.live_trunk_validated
            and not trusted_markers.is_contract_fixture
            and _live_readiness_eligible(trusted_markers),
            "Approved operator attestation can produce live-readiness markers.",
        )
    )

    cdr_payload, cdr_headers, cdr_body = simulator.cdr()
    checks.append(
        _check(
            "signed_cdr_fixture_verifies_and_is_terminal",
            verify_signed_payload(
                simulator.webhook_secret,
                cdr_body,
                cdr_headers,
                now=_signed_now(cdr_headers),
            )
            and cdr_payload.get("event_type") == "cdr"
            and cdr_payload.get("duration_seconds", 0) > 0,
            "Signed CDR fixture verifies and carries terminal duration evidence.",
        )
    )

    checks.append(
        _check(
            "canonical_json_is_stable",
            canonical_json(payload) == canonical_json(json.loads(canonical_json(payload))),
            "Canonical JSON remains deterministic for signature verification.",
        )
    )

    return JambonzContractSmokeResult(
        passed=all(check.passed for check in checks),
        checks=checks,
    )


def _check(name: str, passed: bool, detail: str) -> JambonzContractSmokeCheck:
    return JambonzContractSmokeCheck(name=name, passed=bool(passed), detail=detail)


def _signed_now(headers: dict[str, str]) -> int:
    return int(headers["x-recova-jambonz-timestamp"])


def _live_readiness_eligible(markers: Any) -> bool:
    return bool(
        not getattr(markers, "is_contract_fixture", True)
        and getattr(markers, "live_trunk_validated", False)
    )


__all__ = [
    "JambonzContractSmokeCheck",
    "JambonzContractSmokeResult",
    "run_jambonz_contract_smoke",
]
