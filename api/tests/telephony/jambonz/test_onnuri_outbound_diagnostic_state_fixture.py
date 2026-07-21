from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.schemas.onnuri_smoke import (
    ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT,
    ONNURI_OUTBOUND_DIAGNOSTIC_OPERATIONS,
    OutboundDiagnosticState,
    OutboundDiagnosticTransitionRequest,
)


def _state(product: list[str]) -> OutboundDiagnosticState:
    return OutboundDiagnosticState(
        dispatch=product[0],
        signaling=product[1],
        answer=product[2],
        media=product[3],
        terminal=product[4],
    )


def test_fixture_nodes_and_edges_reference_declared_axis_values() -> None:
    fixture = ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT
    axes = fixture["axes"]
    nodes = {tuple(node) for node in fixture["nodes"]}

    assert fixture["schema_version"] == "recova-onnuri-outbound-diagnostic-v1"
    assert fixture["limits"] == {
        "max_attempts": 3,
        "max_concurrency": 1,
        "max_duration_seconds": 60,
        "automatic_retries": 0,
    }
    for node in nodes:
        assert len(node) == 5
        assert all(value in axes[axis] for axis, value in zip(axes, node))
        assert _state(list(node)).model_dump() == dict(zip(axes, node))
    for edge in fixture["edges"]:
        assert tuple(edge["from"]) in nodes
        assert tuple(edge["to"]) in nodes
        assert edge["operation"] in ONNURI_OUTBOUND_DIAGNOSTIC_OPERATIONS
    assert set(fixture["open_terminal_operations"]) <= ONNURI_OUTBOUND_DIAGNOSTIC_OPERATIONS


def test_fixture_has_exact_answered_media_products_and_terminal_transitions() -> None:
    fixture = ONNURI_OUTBOUND_DIAGNOSTIC_CONTRACT
    edges = {
        (edge["operation"], tuple(edge["from"])): tuple(edge["to"])
        for edge in fixture["edges"]
    }
    answered = ("stock_accepted", "final_2xx", "answered", "unknown", "open")

    assert {
        edges[(operation, answered)]
        for operation in (
            "record_media_zero_matching_packets",
            "record_media_one_way_packets",
            "record_media_bidirectional_packets",
        )
    } == {
        ("stock_accepted", "final_2xx", "answered", "none", "answered_no_matching_rtp"),
        ("stock_accepted", "final_2xx", "answered", "rtp_one_way", "answered_rtp_one_way"),
        ("stock_accepted", "final_2xx", "answered", "rtp_bidirectional", "completed"),
    }
    rejected = ("stock_accepted", "final_3xx_6xx", "not_answered", "unknown", "open")
    assert edges[("record_media_not_applicable", rejected)] == (
        "stock_accepted", "final_3xx_6xx", "not_answered", "not_applicable", "carrier_rejected"
    )


def test_invalid_complements_are_rejected_by_closed_state_model() -> None:
    invalid_products = (
        ("stock_accepted", "final_2xx", "answered", "not_applicable", "completed"),
        ("stock_accepted", "final_3xx_6xx", "not_answered", "none", "carrier_rejected"),
        ("stock_accepted", "final_2xx", "unknown", "unknown", "completed"),
    )
    for product in invalid_products:
        with pytest.raises(ValidationError, match="state_unlisted"):
            _state(list(product))


def test_transition_request_rejects_unlisted_operation() -> None:
    with pytest.raises(ValidationError, match="operation_unlisted"):
        OutboundDiagnosticTransitionRequest(
            attempt_uuid="attempt", organization_id=1, operation="retry_automatically",
            expected=_state(["not_submitted", "unknown", "unknown", "unknown", "open"]),
            provenance_digest="a" * 64, event_idempotency_key="event-idempotency-1",
        )
