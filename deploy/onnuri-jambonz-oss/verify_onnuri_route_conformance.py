#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from api.services.telephony import onnuri_route_receipts as receipts


def load(path: str):
    return receipts.decode_canonical_route_json(Path(path).read_bytes())


def main() -> int:
    p = argparse.ArgumentParser()
    for name in ("--route-conformance", "--route-conformance-signatures", "--route-decision", "--route-decision-signatures", "--provider-fact-packet", "--provider-fact-packet-signatures", "--trusted-keyset", "--revocations", "--as-of"):
        p.add_argument(name, required=True)
    a = p.parse_args()
    try:
        receipts.verify_conformance(route_conformance=load(a.route_conformance), route_conformance_signatures=load(a.route_conformance_signatures), route_decision=load(a.route_decision), route_decision_signatures=load(a.route_decision_signatures), provider_fact_packet=load(a.provider_fact_packet), provider_fact_packet_signatures=load(a.provider_fact_packet_signatures), trusted_keyset=load(a.trusted_keyset), revocations=load(a.revocations), as_of_utc=a.as_of)
    except receipts.ReceiptError as exc:
        p.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
