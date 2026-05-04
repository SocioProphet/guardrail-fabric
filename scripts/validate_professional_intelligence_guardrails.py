#!/usr/bin/env python3
"""Validate Professional Intelligence guardrail pack example."""

from __future__ import annotations

from pathlib import Path
import json

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "professional-intelligence-guardrail-pack.schema.json"
EXAMPLE = ROOT / "examples" / "professional-intelligence" / "guardrail-pack.example.json"
REQUIRED_RULES = {
    "source-citation-required",
    "policy-decision-required",
    "workroom-scope-required",
    "tool-grant-required",
    "evidence-required",
    "low-confidence-escalation",
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    schema = load_json(SCHEMA)
    example = load_json(EXAMPLE)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(example), key=lambda error: list(error.path))
    if errors:
        print("Professional Intelligence guardrail pack failed validation:")
        for error in errors:
            location = ".".join(str(part) for part in error.path) or "<root>"
            print(f" - {location}: {error.message}")
        return 1

    observed = {rule["ruleId"] for rule in example["rules"]}
    missing = sorted(REQUIRED_RULES - observed)
    if missing:
        print(f"Professional Intelligence guardrail pack is missing required rules: {missing}")
        return 1

    for rule in example["rules"]:
        if rule.get("evidenceRequired") is not True:
            print(f"Rule {rule['ruleId']} must require evidence")
            return 1
        if rule["enforcement"] == "block" and not rule.get("requiredRefs"):
            print(f"Blocking rule {rule['ruleId']} must include requiredRefs")
            return 1

    print("Professional Intelligence guardrail pack validates against schema.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
