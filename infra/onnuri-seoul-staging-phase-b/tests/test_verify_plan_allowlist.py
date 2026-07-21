from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from verify_plan_allowlist import PolicyError, validate  # noqa: E402


ROOT = Path(__file__).parent
POLICY = json.loads((ROOT / "allowlist.json").read_text(encoding="utf-8"))


def resource(entry: dict[str, str]) -> dict[str, str]:
    return dict(entry)


def managed_resources() -> list[dict[str, str]]:
    return [resource(entry) for entry in POLICY["resources"]]


def changes(action: str) -> list[dict[str, object]]:
    return [
        {**resource(entry), "change": {"actions": [action]}}
        for entry in POLICY["resources"]
    ]


def planned_values() -> dict[str, object]:
    return {"root_module": {"resources": managed_resources()}}


class VerifyPlanAllowlistTests(unittest.TestCase):
    def test_accepts_complete_create_plan(self) -> None:
        plan = {"resource_changes": changes("create"), "planned_values": planned_values()}
        self.assertEqual(validate(plan, POLICY), "create")

    def test_accepts_clean_drift_plan(self) -> None:
        plan = {"resource_changes": [], "planned_values": planned_values()}
        self.assertEqual(validate(plan, POLICY), "drift-clean")

    def test_accepts_destroy_only_when_planned_values_are_empty(self) -> None:
        plan = {"resource_changes": changes("delete"), "planned_values": {"root_module": {}}}
        self.assertEqual(validate(plan, POLICY), "destroy")

    def test_rejects_destroy_that_retains_planned_resource(self) -> None:
        plan = {"resource_changes": changes("delete"), "planned_values": planned_values()}
        with self.assertRaisesRegex(PolicyError, "DESTROY_PLANNED_VALUES"):
            validate(plan, POLICY)

    def test_rejects_unknown_action(self) -> None:
        plan = {"resource_changes": changes("update"), "planned_values": planned_values()}
        with self.assertRaisesRegex(PolicyError, "RESOURCE_CHANGE_ACTION"):
            validate(plan, POLICY)

    def test_rejects_extra_resource(self) -> None:
        plan = {"resource_changes": changes("create"), "planned_values": planned_values()}
        plan["resource_changes"].append(
            {
                "address": "google_compute_route.unapproved",
                "mode": "managed",
                "type": "google_compute_route",
                "name": "unapproved",
                "change": {"actions": ["create"]},
            }
        )
        with self.assertRaisesRegex(PolicyError, "RESOURCE_CHANGE_ADDRESS"):
            validate(plan, POLICY)


if __name__ == "__main__":
    unittest.main()
