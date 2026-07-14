#!/usr/bin/env python3
"""Validate a Terraform plan JSON against the Phase B four-resource contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    """Raised when a plan does not match the offline Phase B contract."""


def load_json(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as source:
            return json.load(source)
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"JSON_READ: {path}: {error}") from error


def resource_identity(resource: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        resource.get("address"),
        resource.get("mode"),
        resource.get("type"),
        resource.get("name"),
    )


def planned_resources(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, dict):
        raise PolicyError("PLANNED_VALUES_SHAPE")
    root_module = value.get("root_module")
    if root_module is None:
        return []
    if not isinstance(root_module, dict):
        raise PolicyError("PLANNED_VALUES_ROOT_MODULE")

    def collect(module: dict[str, Any]) -> list[dict[str, Any]]:
        resources = module.get("resources", [])
        children = module.get("child_modules", [])
        if not isinstance(resources, list) or not isinstance(children, list):
            raise PolicyError("PLANNED_VALUES_MODULE_SHAPE")
        collected: list[dict[str, Any]] = []
        for resource in resources:
            if not isinstance(resource, dict):
                raise PolicyError("PLANNED_VALUES_RESOURCE_SHAPE")
            collected.append(resource)
        for child in children:
            if not isinstance(child, dict):
                raise PolicyError("PLANNED_VALUES_CHILD_MODULE")
            collected.extend(collect(child))
        return collected

    return collect(root_module)


def classify_plan(changes: list[dict[str, Any]], allowed_addresses: set[str]) -> str:
    if not changes:
        return "drift-clean"
    actions: list[str] = []
    addresses: set[str] = set()
    for change in changes:
        if not isinstance(change, dict):
            raise PolicyError("RESOURCE_CHANGE_SHAPE")
        address = change.get("address")
        if not isinstance(address, str) or address not in allowed_addresses:
            raise PolicyError("RESOURCE_CHANGE_ADDRESS")
        if address in addresses:
            raise PolicyError("RESOURCE_CHANGE_DUPLICATE")
        addresses.add(address)
        change_data = change.get("change")
        if not isinstance(change_data, dict) or not isinstance(change_data.get("actions"), list):
            raise PolicyError("RESOURCE_CHANGE_ACTIONS")
        current_actions = change_data["actions"]
        if len(current_actions) != 1 or not isinstance(current_actions[0], str):
            raise PolicyError("RESOURCE_CHANGE_ACTIONS")
        actions.append(current_actions[0])
    if addresses != allowed_addresses:
        raise PolicyError("RESOURCE_CHANGE_SET")
    if all(action == "create" for action in actions):
        return "create"
    if all(action == "delete" for action in actions):
        return "destroy"
    raise PolicyError("RESOURCE_CHANGE_ACTION")


def validate(plan: Any, policy: Any) -> str:
    if not isinstance(plan, dict) or not isinstance(policy, dict):
        raise PolicyError("DOCUMENT_SHAPE")
    resources = policy.get("resources")
    accepted_actions = policy.get("accepted_actions")
    planned_value_rules = policy.get("planned_values")
    if (
        policy.get("schema_version") != 1
        or not isinstance(resources, list)
        or not isinstance(accepted_actions, dict)
        or not isinstance(planned_value_rules, dict)
    ):
        raise PolicyError("POLICY_SHAPE")

    expected_identities = {resource_identity(resource) for resource in resources if isinstance(resource, dict)}
    if len(expected_identities) != len(resources) or any(not all(identity) for identity in expected_identities):
        raise PolicyError("POLICY_RESOURCES")
    allowed_addresses = {identity[0] for identity in expected_identities}

    changes = plan.get("resource_changes", [])
    if not isinstance(changes, list):
        raise PolicyError("RESOURCE_CHANGES_SHAPE")
    plan_kind = classify_plan(changes, allowed_addresses)
    expected_action = accepted_actions.get(plan_kind)
    if plan_kind == "drift-clean":
        if expected_action != []:
            raise PolicyError("POLICY_ACTIONS")
    elif expected_action not in (["create"], ["delete"]):
        raise PolicyError("POLICY_ACTIONS")

    actual_planned = planned_resources(plan.get("planned_values"))
    actual_identities = {resource_identity(resource) for resource in actual_planned}
    if len(actual_identities) != len(actual_planned):
        raise PolicyError("PLANNED_VALUES_DUPLICATE")
    expected_planned_rule = planned_value_rules.get(plan_kind)
    if expected_planned_rule == "exact_allowlist":
        if actual_identities != expected_identities:
            raise PolicyError("PLANNED_VALUES_SET")
    elif expected_planned_rule == "empty":
        # Terraform destroy plans must not retain a planned managed resource.
        if actual_planned:
            raise PolicyError("DESTROY_PLANNED_VALUES")
    else:
        raise PolicyError("POLICY_PLANNED_VALUES")
    return plan_kind


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--allowlist", type=Path, default=Path(__file__).with_name("allowlist.json"))
    args = parser.parse_args()
    try:
        kind = validate(load_json(args.plan), load_json(args.allowlist))
    except PolicyError as error:
        print(f"REJECT: {error}")
        return 1
    print(f"ACCEPT: {kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
