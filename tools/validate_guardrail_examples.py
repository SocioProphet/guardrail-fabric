#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_DECISION_FIELDS = {
    "decisionStatus",
    "policyRef",
    "surfaceRef",
    "reasonCodes",
    "redactionHints",
    "maskingHints",
    "evidenceRef",
    "ledgerRef",
}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def fail(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 1


def validate_policy(doc: dict) -> int:
    if doc.get("apiVersion") != "guardrail.socioprophet.dev/v1":
        return fail("policy apiVersion invalid")
    if doc.get("kind") != "GuardrailPolicy":
        return fail("policy kind invalid")
    spec = doc.get("spec", {})
    for key in ["surfaceRefs", "sensitivityPolicy", "promptPolicy", "sourcePolicy", "outputPolicy"]:
        if key not in spec:
            return fail(f"policy missing spec.{key}")
    if not spec["surfaceRefs"]:
        return fail("policy surfaceRefs empty")
    return 0


def validate_input(doc: dict) -> int:
    if doc.get("kind") != "GuardrailInput":
        return fail("input kind invalid")
    spec = doc.get("spec", {})
    for key in ["surfaceRef", "task", "contentClass", "detectedSignals", "policyRef", "evidenceRef"]:
        if key not in spec:
            return fail(f"input missing spec.{key}")
    if not isinstance(spec["detectedSignals"], list):
        return fail("input detectedSignals must be a list")
    return 0


def validate_decision(doc: dict) -> int:
    if doc.get("kind") != "GuardrailDecision":
        return fail("decision kind invalid")
    spec = doc.get("spec", {})
    missing = sorted(REQUIRED_DECISION_FIELDS - set(spec))
    if missing:
        return fail(f"decision missing fields: {missing}")
    if spec["decisionStatus"] not in {"allow", "deny", "requires-review"}:
        return fail("decisionStatus invalid")
    for list_field in ["reasonCodes", "redactionHints", "maskingHints"]:
        if not isinstance(spec[list_field], list):
            return fail(f"{list_field} must be a list")
    if not spec["reasonCodes"]:
        return fail("reasonCodes must be non-empty")
    return 0


def main() -> int:
    checks = [
        validate_policy(load(ROOT / "examples" / "guardrail-policy.example.json")),
        validate_input(load(ROOT / "examples" / "guardrail-input.example.json")),
        validate_decision(load(ROOT / "examples" / "guardrail-decision.example.json")),
    ]
    if any(checks):
        return 1
    print("OK: guardrail examples validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
