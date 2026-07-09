"""Canonical telephony evidence marker extraction and trust-boundary helpers."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

APPROVED_LIVE_VALIDATION_SOURCES = frozenset(
    {"live_validation_tool", "operator_attestation"}
)

# Fields callers must never accept from customer/template/campaign/generic payloads.
UNTRUSTED_EVIDENCE_INPUT_KEYS = frozenset(
    {
        "contract_version",
        "jambonz_contract_version",
        "is_contract_fixture",
        "live_trunk_validated",
        "live_validation_source",
        "live_validation_evidence_id",
        "telephony_evidence",
        "evidence_markers",
        "jambonz_contract_v1",
    }
)

_CONTRACT_VERSION_KEYS = ("contract_version", "jambonz_contract_version")
_PROVIDER_KEYS = ("provider",)
_CONFIG_ID_KEYS = ("telephony_configuration_id",)
_PHONE_ID_KEYS = ("telephony_phone_number_id", "from_phone_number_id")
_INVENTORY_ID_KEYS = ("inventory_id",)
_CALL_ATTEMPT_ID_KEYS = ("call_attempt_id", "telephony_call_attempt_id")
_FIXTURE_KEYS = ("is_contract_fixture",)
_LIVE_VALIDATED_KEYS = ("live_trunk_validated",)
_LIVE_SOURCE_KEYS = ("live_validation_source",)
_LIVE_EVIDENCE_KEYS = ("live_validation_evidence_id",)
_CONTRACT_MODE_HEADER = "x-recova-contract-mode"
_CONTRACT_MODE_FIXTURE = "contract_fixture"


@dataclass(frozen=True)
class TelephonyEvidenceMarkers:
    """Sanitized marker context attached to telephony events/CDRs/alerts."""

    provider: str | None = None
    contract_version: str | None = None
    is_contract_fixture: bool = False
    live_trunk_validated: bool = False
    live_validation_source: str | None = None
    live_validation_evidence_id: str | None = None
    telephony_configuration_id: int | None = None
    telephony_phone_number_id: int | None = None
    inventory_id: int | None = None
    call_attempt_id: str | None = None

    def with_identity(self, **values: Any) -> "TelephonyEvidenceMarkers":
        """Return a copy with trusted internal identity fields overlaid."""

        return replace(
            self,
            provider=_coerce_str(values.get("provider"), max_length=64) or self.provider,
            telephony_configuration_id=_coerce_int(
                values.get("telephony_configuration_id")
            )
            if values.get("telephony_configuration_id") is not None
            else self.telephony_configuration_id,
            telephony_phone_number_id=_coerce_int(
                values.get("telephony_phone_number_id", values.get("from_phone_number_id"))
            )
            if values.get("telephony_phone_number_id", values.get("from_phone_number_id"))
            is not None
            else self.telephony_phone_number_id,
            inventory_id=_coerce_int(values.get("inventory_id"))
            if values.get("inventory_id") is not None
            else self.inventory_id,
            call_attempt_id=_coerce_str(
                values.get("call_attempt_id", values.get("telephony_call_attempt_id")),
                max_length=128,
            )
            or self.call_attempt_id,
        )

    def as_context(self) -> dict[str, Any]:
        """Return workflow context keys expected by existing telephony code."""

        payload: dict[str, Any] = {
            "is_contract_fixture": self.is_contract_fixture,
            "live_trunk_validated": self.live_trunk_validated,
        }
        if self.provider:
            payload["provider"] = self.provider
        if self.contract_version:
            payload["contract_version"] = self.contract_version
        if self.live_validation_source:
            payload["live_validation_source"] = self.live_validation_source
        if self.live_validation_evidence_id:
            payload["live_validation_evidence_id"] = self.live_validation_evidence_id
        if self.telephony_configuration_id is not None:
            payload["telephony_configuration_id"] = self.telephony_configuration_id
        if self.telephony_phone_number_id is not None:
            payload["telephony_phone_number_id"] = self.telephony_phone_number_id
            # Compatibility for existing call lifecycle code.
            payload["from_phone_number_id"] = self.telephony_phone_number_id
        if self.inventory_id is not None:
            payload["inventory_id"] = self.inventory_id
        if self.call_attempt_id:
            payload["call_attempt_id"] = self.call_attempt_id
            # Compatibility for existing admission/CDR code.
            payload["telephony_call_attempt_id"] = self.call_attempt_id
        return payload

    def as_record_kwargs(self) -> dict[str, Any]:
        """Return kwargs accepted by TelephonyEventRecord/TelephonyTerminalCDR."""

        return {
            "contract_version": self.contract_version,
            "is_contract_fixture": self.is_contract_fixture,
            "live_trunk_validated": self.live_trunk_validated,
            "live_validation_source": self.live_validation_source,
            "live_validation_evidence_id": self.live_validation_evidence_id,
            "inventory_id": self.inventory_id,
            "call_attempt_id": self.call_attempt_id,
        }

    def as_alert_kwargs(self) -> dict[str, Any]:
        """Return alert kwargs that preserve simulator/live trust boundaries."""

        return {
            "source": "contract_simulator" if self.is_contract_fixture else "runtime",
            "is_contract_fixture": self.is_contract_fixture,
            "contract_version": self.contract_version,
            "live_trunk_validated": self.live_trunk_validated,
            "live_validation_source": self.live_validation_source,
            "live_validation_evidence_id": self.live_validation_evidence_id,
            "telephony_configuration_id": self.telephony_configuration_id,
            "telephony_phone_number_id": self.telephony_phone_number_id,
            "inventory_id": self.inventory_id,
            "call_attempt_id": self.call_attempt_id,
        }

    def as_artifact_payload(self) -> dict[str, Any]:
        """Return marker context suitable for event/CDR artifact payloads."""

        return {"evidence_markers": self.to_dict(include_false=True)}

    def to_dict(self, *, include_false: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        for key in (
            "provider",
            "contract_version",
            "is_contract_fixture",
            "live_trunk_validated",
            "live_validation_source",
            "live_validation_evidence_id",
            "telephony_configuration_id",
            "telephony_phone_number_id",
            "inventory_id",
            "call_attempt_id",
        ):
            value = getattr(self, key)
            if value is None:
                continue
            if value is False and not include_false:
                continue
            payload[key] = value
        return payload


def extract_telephony_evidence_markers(
    *untrusted_sources: Any,
    trusted_context: Mapping[str, Any] | None = None,
    allow_live_validation: bool = False,
) -> TelephonyEvidenceMarkers:
    """Extract markers while ignoring untrusted live-readiness claims.

    ``untrusted_sources`` may be customer variables, simulator payloads, provider
    callbacks, or provider responses. They can contribute contract fixture labels
    and contract versions, but never ``live_trunk_validated=true``. Live readiness
    is accepted only from ``trusted_context`` when ``allow_live_validation`` is
    true, the source is approved, and an evidence id is present.
    """

    trusted = trusted_context or {}
    source_maps = _collect_mappings(*untrusted_sources)
    trusted_maps = _collect_mappings(trusted)
    all_maps = [*trusted_maps, *source_maps]

    provider = _first_str(trusted_maps, _PROVIDER_KEYS, max_length=64) or _first_str(
        source_maps, _PROVIDER_KEYS, max_length=64
    )
    contract_version = _first_str(
        trusted_maps, _CONTRACT_VERSION_KEYS, max_length=64
    ) or _first_str(source_maps, _CONTRACT_VERSION_KEYS, max_length=64)

    is_contract_fixture = _any_truthy(all_maps, _FIXTURE_KEYS) or _has_contract_fixture_header(
        all_maps
    )

    telephony_configuration_id = _first_int(trusted_maps, _CONFIG_ID_KEYS)
    telephony_phone_number_id = _first_int(trusted_maps, _PHONE_ID_KEYS)
    inventory_id = _first_int(trusted_maps, _INVENTORY_ID_KEYS)
    call_attempt_id = _first_str(trusted_maps, _CALL_ATTEMPT_ID_KEYS, max_length=128)

    live_validation_source = None
    live_validation_evidence_id = None
    live_trunk_validated = False
    if allow_live_validation:
        source = _first_str(trusted_maps, _LIVE_SOURCE_KEYS, max_length=64)
        evidence_id = _first_str(trusted_maps, _LIVE_EVIDENCE_KEYS, max_length=128)
        live_requested = _any_truthy(trusted_maps, _LIVE_VALIDATED_KEYS)
        if live_requested and source in APPROVED_LIVE_VALIDATION_SOURCES and evidence_id:
            live_trunk_validated = True
            live_validation_source = source
            live_validation_evidence_id = evidence_id

    return TelephonyEvidenceMarkers(
        provider=provider,
        contract_version=contract_version,
        is_contract_fixture=is_contract_fixture,
        live_trunk_validated=live_trunk_validated,
        live_validation_source=live_validation_source,
        live_validation_evidence_id=live_validation_evidence_id,
        telephony_configuration_id=telephony_configuration_id,
        telephony_phone_number_id=telephony_phone_number_id,
        inventory_id=inventory_id,
        call_attempt_id=call_attempt_id,
    )


def build_trusted_live_validation_markers(
    *,
    provider: str,
    live_validation_source: str,
    live_validation_evidence_id: str,
    contract_version: str | None = None,
    telephony_configuration_id: int | None = None,
    telephony_phone_number_id: int | None = None,
    inventory_id: int | None = None,
    call_attempt_id: str | None = None,
) -> TelephonyEvidenceMarkers:
    """Construct markers for approved tooling/operator attestation paths only."""

    return extract_telephony_evidence_markers(
        trusted_context={
            "provider": provider,
            "contract_version": contract_version,
            "live_trunk_validated": True,
            "live_validation_source": live_validation_source,
            "live_validation_evidence_id": live_validation_evidence_id,
            "telephony_configuration_id": telephony_configuration_id,
            "telephony_phone_number_id": telephony_phone_number_id,
            "inventory_id": inventory_id,
            "call_attempt_id": call_attempt_id,
        },
        allow_live_validation=True,
    )


def strip_untrusted_evidence_fields(context: Mapping[str, Any] | None) -> dict[str, Any]:
    """Remove evidence marker keys from customer/campaign/template variables."""

    if not context:
        return {}
    return {
        str(key): value
        for key, value in context.items()
        if str(key) not in UNTRUSTED_EVIDENCE_INPUT_KEYS
    }


def inventory_id_from_phone_row(phone_row: Any) -> int | None:
    metadata = getattr(phone_row, "extra_metadata", None) or {}
    if isinstance(metadata, Mapping):
        return _coerce_int(metadata.get("inventory_id"))
    return None


def _collect_mappings(*sources: Any) -> list[Mapping[str, Any]]:
    collected: list[Mapping[str, Any]] = []
    for source in sources:
        if isinstance(source, Mapping):
            collected.append(source)
            for nested_key in ("telephony_evidence", "evidence_markers", "data"):
                nested = source.get(nested_key)
                if isinstance(nested, Mapping):
                    collected.extend(_collect_mappings(nested))
            jambonz_nested = source.get("jambonz_contract_v1")
            if isinstance(jambonz_nested, Mapping):
                collected.extend(_collect_mappings(jambonz_nested))
        elif source is not None:
            attrs = {
                key: getattr(source, key)
                for key in (
                    "provider",
                    "contract_version",
                    "jambonz_contract_version",
                    "is_contract_fixture",
                    "live_trunk_validated",
                    "live_validation_source",
                    "live_validation_evidence_id",
                    "telephony_configuration_id",
                    "telephony_phone_number_id",
                    "from_phone_number_id",
                    "inventory_id",
                    "call_attempt_id",
                    "telephony_call_attempt_id",
                )
                if hasattr(source, key)
            }
            if attrs:
                collected.append(attrs)
    return collected


def _first_value(maps: list[Mapping[str, Any]], keys: tuple[str, ...]) -> Any:
    for mapping in maps:
        for key in keys:
            if key in mapping and mapping[key] not in (None, ""):
                return mapping[key]
    return None


def _first_str(
    maps: list[Mapping[str, Any]], keys: tuple[str, ...], *, max_length: int
) -> str | None:
    return _coerce_str(_first_value(maps, keys), max_length=max_length)


def _first_int(maps: list[Mapping[str, Any]], keys: tuple[str, ...]) -> int | None:
    return _coerce_int(_first_value(maps, keys))


def _any_truthy(maps: list[Mapping[str, Any]], keys: tuple[str, ...]) -> bool:
    for mapping in maps:
        for key in keys:
            if key in mapping and _coerce_bool(mapping[key]):
                return True
    return False


def _has_contract_fixture_header(maps: list[Mapping[str, Any]]) -> bool:
    for mapping in maps:
        for key, value in mapping.items():
            if str(key).lower() == _CONTRACT_MODE_HEADER and value == _CONTRACT_MODE_FIXTURE:
                return True
    return False


def _coerce_str(value: Any, *, max_length: int) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:max_length]


def _coerce_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return False
