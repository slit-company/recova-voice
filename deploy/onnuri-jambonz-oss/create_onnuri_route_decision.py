#!/usr/bin/env python3
"""Create an unsigned route-decision payload; signing is an external role duty."""
from __future__ import annotations

import argparse
from pathlib import Path

from api.services.telephony import onnuri_route_receipts as receipts


def load(path: str):
    return receipts.decode_canonical_route_json(Path(path).read_bytes())


def main() -> int:
    p = argparse.ArgumentParser()
    for name in ("--provider-fact-packet", "--provider-fact-packet-signatures", "--restricted-inventory-adapter", "--trusted-keyset", "--revocations", "--as-of", "--request-digest", "--candidate-digest", "--route-profile-digest", "--receipt-id", "--expires-at", "--adapter-challenge-nonce", "--approved-root-locator-digest", "--inventory-locator-digest", "--inventory-version", "--output"):
        p.add_argument(name, required=True)
    a = p.parse_args()
    consumed: set[tuple[str, str, str, str]] = set()
    def consume_replay(**value):
        token = (value["key_id"], value["challenge_nonce"], value["audience"], value["signature_sha256"])
        if token in consumed:
            raise receipts.ReceiptError("route_adapter_replay")
        consumed.add(token)
    try:
        value = receipts.create_decision(provider_fact_packet=load(a.provider_fact_packet), provider_fact_packet_signatures=load(a.provider_fact_packet_signatures), restricted_inventory_adapter=Path(a.restricted_inventory_adapter).read_bytes(), trusted_keyset=load(a.trusted_keyset), revocations=load(a.revocations), as_of_utc=a.as_of, request_digest=a.request_digest, candidate_digest=a.candidate_digest, route_profile_digest=a.route_profile_digest, receipt_id=a.receipt_id, expires_at_utc=a.expires_at, adapter_challenge_nonce=a.adapter_challenge_nonce, approved_root_locator_digest=a.approved_root_locator_digest, inventory_locator_digest=a.inventory_locator_digest, inventory_version=a.inventory_version, replay_consumer=consume_replay)
        Path(a.output).write_bytes(receipts.canonical_json(value))
    except receipts.ReceiptError as exc:
        p.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
