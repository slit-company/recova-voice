from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import seal_candidate as sealer

IMMUTABLE = "example.invalid/image@sha256:" + "0" * 64


class CandidateSealerTests(unittest.TestCase):
    def mappings(self) -> list[str]:
        return [f"{name}={IMMUTABLE}" for name in sorted(sealer.SUPPORT_IMAGES)]

    def test_accepts_exact_g009_and_g008_derivative_support_images(self) -> None:
        self.assertEqual(set(sealer.support_image_mappings(self.mappings())), sealer.SUPPORT_IMAGES)

    def test_rejects_missing_extra_duplicate_and_mutable_support_images(self) -> None:
        cases = [
            self.mappings()[:-1],
            self.mappings() + [f"unexpected={IMMUTABLE}"],
            self.mappings() + [self.mappings()[0]],
            [entry if not entry.startswith("postgres=") else "postgres=example.invalid/postgres:latest" for entry in self.mappings()],
        ]
        for mappings in cases:
            with self.subTest(mappings=mappings), self.assertRaises(sealer.Refusal):
                sealer.support_image_mappings(mappings)

    def test_support_contract_names_do_not_replace_g009_images(self) -> None:
        self.assertTrue({"mariadb", "redis", "facade"}.issubset(sealer.SUPPORT_IMAGES))
        self.assertTrue({"recova-backend", "postgres", "recova-redis", "f12-ingress"}.issubset(sealer.SUPPORT_IMAGES))

    def test_license_key_and_entitlement_prohibitions_remain_fail_closed(self) -> None:
        forbidden = (
            b"runtime_license_key_required: true",
            b"activation_service_required: true",
            b"trial_or_paid_entitlement_used: true",
            b"commercial_image_used: true",
            b"circumvention_used: true",
        )
        for value in forbidden:
            with self.subTest(value=value), self.assertRaises(sealer.Refusal):
                sealer.clean_text(value, "contract")


if __name__ == "__main__":
    unittest.main()
