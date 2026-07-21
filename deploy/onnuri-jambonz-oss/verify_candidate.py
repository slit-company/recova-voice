#!/usr/bin/env python3
"""Compatibility entry point for the current G008 candidate verifier."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import verify_candidate_manifest as verifier
class _BaseVerifierCompatibility:
    review_payload_digest = staticmethod(verifier.review_payload_digest)
    validate_manifest = staticmethod(verifier.validate_manifest)


g009 = _BaseVerifierCompatibility()
SUPPORT_EVIDENCE = (
    ("oci_license_reference", "oci_license_sha256"),
    ("notices_reference", "notices_sha256"),
    ("sbom_reference", "sbom_sha256"),
    ("vulnerability_reference", "vulnerability_sha256"),
    ("vulnerability_acceptance_reference", "vulnerability_acceptance_sha256"),
    ("network_archive_reference", "network_archive_sha256"),
    ("network_archive_record_reference", "network_archive_record_sha256"),
)

canonical_json = verifier.canonical_json
review_payload_digest = verifier.review_payload_digest
SUPPORT_IMAGES = verifier.SUPPORT_IMAGES
BINDING_FIELDS = [
    "tenant_digest",
    "account_digest",
    "envelope_digest",
    "candidate_digest",
    "operation",
    "prior_receipt_digest",
]
OPERATIONS = [
    {
        "operation": "register",
        "challenge_aware": True,
        "max_wire_transmissions": 2,
        "automatic_retry": False,
        "max_concurrency": 1,
        "terminal_deadline_seconds": 32,
        "causal_predecessor": "authority_receipt_digest",
    },
    {
        "operation": "unregister",
        "challenge_aware": True,
        "max_wire_transmissions": 2,
        "automatic_retry": False,
        "max_concurrency": 1,
        "terminal_deadline_seconds": 32,
        "causal_predecessor": "register_receipt_digest",
    },
]
SIGNING = {
    "dispatch": {
        "algorithm": "ES256",
        "key_id": "dispatch-es256",
        "trust_domain": "recova.dispatch",
    },
    "media": {
        "algorithm": "ES256",
        "key_id": "media-es256",
        "trust_domain": "recova.media",
    },
}


def validate_manifest(data: Any, as_of: datetime) -> list[str]:
    return verifier.validate_manifest(data, as_of)


def validate_evidence(
    data: Any,
    bundle_root: Path,
    errors: list[str],
    as_of: datetime | None = None,
) -> None:
    verifier.validate_evidence(data, bundle_root, errors, as_of)


def main() -> int:
    return verifier.main()


if __name__ == "__main__":
    raise SystemExit(main())