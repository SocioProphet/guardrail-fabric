#!/usr/bin/env python3
"""Validate TrustOpsPreflightHandoff v0.1 fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

OUTCOME_TO_ACTION = {
    "pass": "allow",
    "warn": "warn",
    "require-review": "require-review",
    "quarantine": "quarantine",
    "block": "block",
    "rollback": "rollback",
    "revoke": "revoke",
}

PRECEDENCE = {
    "allow": 0,
    "warn": 10,
    "require-review": 20,
    "quarantine": 30,
    "block": 40,
    "rollback": 50,
    "revoke": 60,
}

REQUIRED_FIELDS = {
    "schemaVersion",
    "recordType",
    "handoff_id",
    "source_system",
    "consumer_system",
    "source_receipt_id",
    "outcome",
    "runtime_action",
    "gate_ids",
    "evidence_refs",
    "reason",
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
        raise ValidationError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        fail(f"{path}: expected JSON object")
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
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            fail(f"{key}[{index}]: expected non-empty string")
    return value


def validate_handoff(record: dict[str, Any]) -> None:
    missing = sorted(REQUIRED_FIELDS - set(record))
    if missing:
        fail(f"missing required handoff fields: {missing}")

    if record["schemaVersion"] != "guardrail-fabric.trustops-preflight-handoff.v0.1":
        fail("schemaVersion mismatch")
    if record["recordType"] != "TrustOpsPreflightHandoff":
        fail("recordType mismatch")
    if record["source_system"] != "SocioProphet/guardrail-fabric":
        fail("source_system must be SocioProphet/guardrail-fabric")
    if record["consumer_system"] != "SocioProphet/agentplane":
        fail("consumer_system must be SocioProphet/agentplane")

    for key in ("handoff_id", "source_receipt_id", "outcome", "runtime_action", "reason"):
        require_string(record, key)

    outcome = record["outcome"]
    runtime_action = record["runtime_action"]
    if outcome not in OUTCOME_TO_ACTION:
        fail(f"unknown TrustOps outcome: {outcome}")
    if runtime_action not in PRECEDENCE:
        fail(f"unknown runtime action: {runtime_action}")

    expected_action = OUTCOME_TO_ACTION[outcome]
    if runtime_action != expected_action:
        fail(f"runtime_action must preserve monotonic mapping: {outcome} -> {expected_action}, got {runtime_action}")
    if PRECEDENCE[runtime_action] < PRECEDENCE[expected_action]:
        fail("runtime_action cannot lower TrustOps outcome severity")

    gate_ids = require_string_list(record, "gate_ids")
    evidence_refs = require_string_list(record, "evidence_refs")
    if outcome == "quarantine" and not evidence_refs:
        fail("quarantine requires exact evidence_refs")
    if not all(gate_id.startswith("gate://") for gate_id in gate_ids):
        fail("all gate_ids must be gate:// refs")
    if not all(evidence_ref.startswith("evidence://") for evidence_ref in evidence_refs):
        fail("all evidence_refs must be evidence:// refs")

    projection = record.get("agentplane_projection")
    if not isinstance(projection, dict):
        fail("agentplane_projection must be an object")
    if projection.get("outcome") != outcome:
        fail("agentplane_projection.outcome must match handoff outcome")
    if projection.get("runtime_action") != runtime_action:
        fail("agentplane_projection.runtime_action must match handoff runtime_action")
    if projection.get("authoritative_safety_owner") != "SocioProphet/guardrail-fabric":
        fail("agentplane_projection.authoritative_safety_owner mismatch")
    if projection.get("handoff_ref") != record["handoff_id"]:
        fail("agentplane_projection.handoff_ref must match handoff_id")

    if outcome == "rollback" and runtime_action == "warn":
        fail("rollback cannot silently degrade to warn")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: validate_preflight_handoff.py <fixture.json>", file=sys.stderr)
        return 2
    try:
        validate_handoff(load_json(Path(argv[1])))
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {argv[1]} validates as TrustOpsPreflightHandoff v0.1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
