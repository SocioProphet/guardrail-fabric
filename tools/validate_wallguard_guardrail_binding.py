#!/usr/bin/env python3
"""Validate WallGuard guardrail binding fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "wallguard-guardrail-binding.v0.1.schema.json"
VALID = ROOT / "tests" / "fixtures" / "wallguard-guardrail-binding" / "allow.valid.json"
INVALIDS = [
    ROOT / "tests" / "fixtures" / "wallguard-guardrail-binding" / "deny-degraded-to-allow.invalid.json",
    ROOT / "tests" / "fixtures" / "wallguard-guardrail-binding" / "authority-mutated.invalid.json",
]

REQUIRED = {
    "schemaVersion",
    "recordType",
    "binding_id",
    "source_system",
    "surface",
    "wall_decision_ref",
    "wall_decision_outcome",
    "guardrail_action",
    "resource_refs",
    "destination_ref",
    "policy_refs",
    "receipt_refs",
    "issued_at",
    "authority_mutation",
}

WALL_TO_ACTION = {
    "allow": "allow",
    "deny": "deny",
    "redact": "redact",
    "quarantine": "quarantine",
    "escalate": "escalate",
    "clean_room_release_requested": "escalate",
    "clean_room_release_allowed": "clean_room_release",
    "clean_room_release_denied": "deny",
}

ACTION_PRECEDENCE = {
    "allow": 0,
    "clean_room_release": 10,
    "redact": 20,
    "escalate": 30,
    "quarantine": 40,
    "deny": 50,
}


class ValidationError(Exception):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValidationError(f"missing file: {path.relative_to(ROOT)}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path.relative_to(ROOT)}: {exc}") from exc
    if not isinstance(payload, dict):
        fail(f"{path.relative_to(ROOT)}: expected JSON object")
    return payload


def require_string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        fail(f"{key}: expected non-empty string")
    return value


def require_string_list(record: dict[str, Any], key: str) -> list[str]:
    value = record.get(key)
    if not isinstance(value, list) or not value:
        fail(f"{key}: expected non-empty list")
    if len(set(value)) != len(value):
        fail(f"{key}: duplicate entries are not allowed")
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            fail(f"{key}[{index}]: expected non-empty string")
    return value


def validate_schema(schema: dict[str, Any]) -> None:
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("schema must use JSON Schema draft 2020-12")
    if schema.get("type") != "object":
        fail("schema must describe an object")
    if schema.get("additionalProperties") is not False:
        fail("schema must be strict")
    missing = sorted(REQUIRED - set(schema.get("required", [])))
    if missing:
        fail(f"schema missing required fields: {missing}")


def validate_binding(record: dict[str, Any]) -> None:
    missing = sorted(REQUIRED - set(record))
    if missing:
        fail(f"missing required fields: {missing}")
    if record["schemaVersion"] != "guardrail-fabric.wallguard-guardrail-binding.v0.1":
        fail("schemaVersion mismatch")
    if record["recordType"] != "WallGuardGuardrailBinding":
        fail("recordType mismatch")
    if record["source_system"] != "SocioProphet/guardrail-fabric":
        fail("source_system must be SocioProphet/guardrail-fabric")

    for key in ("binding_id", "surface", "wall_decision_ref", "wall_decision_outcome", "guardrail_action", "destination_ref", "issued_at"):
        require_string(record, key)
    require_string_list(record, "resource_refs")
    require_string_list(record, "policy_refs")
    require_string_list(record, "receipt_refs")

    outcome = record["wall_decision_outcome"]
    action = record["guardrail_action"]
    if outcome not in WALL_TO_ACTION:
        fail(f"unknown wall_decision_outcome: {outcome}")
    if action not in ACTION_PRECEDENCE:
        fail(f"unknown guardrail_action: {action}")
    expected = WALL_TO_ACTION[outcome]
    if ACTION_PRECEDENCE[action] < ACTION_PRECEDENCE[expected]:
        fail(f"guardrail_action cannot lower WallGuard outcome severity: {outcome} -> {action}")

    authority = record.get("authority_mutation")
    if not isinstance(authority, dict):
        fail("authority_mutation must be an object")
    if authority.get("performed") is not False:
        fail("Guardrail Fabric must not directly mutate agent authority")
    if authority.get("authority_plane") != "SocioProphet/agent-registry":
        fail("authority_mutation.authority_plane must be SocioProphet/agent-registry")
    intent = authority.get("downstream_intent")
    if action == "allow" and intent != "none":
        fail("allow actions must not request downstream authority mutation")
    if action != "allow" and intent not in {"none", "requires-agent-registry-decision"}:
        fail("unexpected authority downstream intent")


def main(argv: list[str]) -> int:
    try:
        validate_schema(load_json(SCHEMA))
        validate_binding(load_json(VALID))
        for invalid in INVALIDS:
            try:
                validate_binding(load_json(invalid))
            except ValidationError:
                continue
            fail(f"invalid fixture unexpectedly validated: {invalid.relative_to(ROOT)}")
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("OK: WallGuard guardrail binding fixtures validate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
