#!/usr/bin/env python3
"""Validate TrustOpsGuardrailActionDecision v0.1 fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "trustops-guardrail-action-decision.v0.1.schema.json"

OUTCOME_TO_ACTION = {
    "pass": "allow",
    "warn": "warn",
    "require-review": "require-review",
    "quarantine": "quarantine",
    "block": "block",
    "rollback": "rollback",
    "revoke": "revoke",
}
ACTION_PRECEDENCE = {
    "allow": 0,
    "warn": 10,
    "require-review": 20,
    "quarantine": 30,
    "block": 40,
    "rollback": 50,
    "revoke": 60,
}
REQUIRED = {
    "schemaVersion",
    "recordType",
    "decision_id",
    "source_system",
    "controlling_outcome",
    "runtime_action",
    "receipt_ids",
    "gate_ids",
    "evidence_refs",
    "policy_refs",
    "reason",
    "issued_at",
    "authority_mutation",
    "agentplane_projection",
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
    seen: set[str] = set()
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            fail(f"{key}[{index}]: expected non-empty string")
        if item in seen:
            fail(f"{key}: duplicate entry {item}")
        seen.add(item)
        out.append(item)
    return out


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
    props = schema.get("properties", {})
    if props.get("schemaVersion", {}).get("const") != "guardrail-fabric.trustops-guardrail-action-decision.v0.1":
        fail("schemaVersion const mismatch")
    if props.get("recordType", {}).get("const") != "TrustOpsGuardrailActionDecision":
        fail("recordType const mismatch")


def validate_decision(record: dict[str, Any]) -> None:
    missing = sorted(REQUIRED - set(record))
    if missing:
        fail(f"missing required fields: {missing}")
    if record["schemaVersion"] != "guardrail-fabric.trustops-guardrail-action-decision.v0.1":
        fail("schemaVersion mismatch")
    if record["recordType"] != "TrustOpsGuardrailActionDecision":
        fail("recordType mismatch")
    if record["source_system"] != "SocioProphet/guardrail-fabric":
        fail("source_system must be SocioProphet/guardrail-fabric")

    for key in ("decision_id", "controlling_outcome", "runtime_action", "reason", "issued_at"):
        require_string(record, key)

    outcome = record["controlling_outcome"]
    action = record["runtime_action"]
    if outcome not in OUTCOME_TO_ACTION:
        fail(f"unknown controlling_outcome: {outcome}")
    if action not in ACTION_PRECEDENCE:
        fail(f"unknown runtime_action: {action}")
    expected = OUTCOME_TO_ACTION[outcome]
    if ACTION_PRECEDENCE[action] < ACTION_PRECEDENCE[expected]:
        fail(f"runtime_action cannot lower TrustOps outcome severity: {outcome} -> {action}")

    receipt_ids = require_string_list(record, "receipt_ids")
    gate_ids = require_string_list(record, "gate_ids")
    evidence_refs = require_string_list(record, "evidence_refs")
    require_string_list(record, "policy_refs")
    if not all(item.startswith("trustops-receipt:") for item in receipt_ids):
        fail("all receipt_ids must be trustops-receipt: refs")
    if not all(item.startswith("gate://") for item in gate_ids):
        fail("all gate_ids must be gate:// refs")
    if not all(item.startswith("evidence://") for item in evidence_refs):
        fail("all evidence_refs must be evidence:// refs")

    authority = record.get("authority_mutation")
    if not isinstance(authority, dict):
        fail("authority_mutation must be an object")
    if authority.get("performed") is not False:
        fail("Guardrail Fabric must not directly mutate agent authority")
    if authority.get("authority_plane") != "SocioProphet/agent-registry":
        fail("authority_mutation.authority_plane must be SocioProphet/agent-registry")
    intent = authority.get("downstream_intent")
    if action in {"allow", "warn"} and intent != "none":
        fail("allow/warn guardrail actions must not request authority mutation")
    if action not in {"allow", "warn"} and intent != "requires-agent-registry-decision":
        fail("restrictive guardrail actions must expose downstream Agent Registry intent")

    projection = record.get("agentplane_projection")
    if not isinstance(projection, dict):
        fail("agentplane_projection must be an object")
    if projection.get("outcome") != outcome:
        fail("agentplane_projection.outcome must match controlling_outcome")
    if projection.get("runtime_action") != action:
        fail("agentplane_projection.runtime_action must match runtime_action")
    if projection.get("authoritative_safety_owner") != "SocioProphet/guardrail-fabric":
        fail("agentplane_projection.authoritative_safety_owner mismatch")
    if projection.get("guardrail_action_ref") != record["decision_id"]:
        fail("agentplane_projection.guardrail_action_ref must match decision_id")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate_trustops_guardrail_action_decision.py <decision.json>", file=sys.stderr)
        return 2
    try:
        validate_schema(load_json(SCHEMA))
        validate_decision(load_json(Path(argv[1])))
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {argv[1]} validates as TrustOpsGuardrailActionDecision v0.1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
