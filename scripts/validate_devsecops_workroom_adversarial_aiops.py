#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "devsecops_workroom_adversarial_aiops.v0_1.schema.json"
FIXTURES = [
    ROOT / "fixtures" / "devsecops-workroom" / "poisoned-evidence.denied.valid.json",
    ROOT / "fixtures" / "devsecops-workroom" / "unsafe-mutation-without-grant.denied.valid.json",
    ROOT / "fixtures" / "devsecops-workroom" / "credential-sensitive.escalated.valid.json",
    ROOT / "fixtures" / "devsecops-workroom" / "safe-read-only-probe.allowed.valid.json",
]
EXPECTED = {
    "poisoned_evidence": {
        "decisions": {"deny", "escalate"},
        "reason": "poisoned_evidence_policy_override_attempt",
    },
    "unsafe_mutation_without_grant": {
        "decisions": {"deny"},
        "reason": "mutation_requires_action_grant",
    },
    "credential_sensitive_action": {
        "decisions": {"escalate"},
        "reason": "credential_sensitive_requires_review",
    },
    "safe_read_only_probe": {
        "decisions": {"allow"},
        "reason": "read_only_probe_allowed",
    },
}
MUTATION_CLASSES = {
    "diagnostic_mutation",
    "reversible_mitigation",
    "irreversible_mutation",
    "credential_sensitive",
    "data_sensitive",
    "customer_visible",
    "destructive",
    "privileged_identity",
    "network_exposure",
    "production_change",
}


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"expected object: {path}")
    return data


def schema_errors(schema: dict[str, Any], data: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema)
    errors: list[str] = []
    for error in sorted(validator.iter_errors(data), key=lambda item: list(item.absolute_path)):
        path = "/".join(str(part) for part in error.absolute_path) or "<root>"
        errors.append(f"schema:{path}: {error.message}")
    return errors


def semantic_errors(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    fixture_class = data.get("fixture_class")
    expected = EXPECTED.get(fixture_class)
    if not expected:
        errors.append(f"unknown fixture_class {fixture_class!r}")
        return errors

    decision = data.get("expected_decision")
    reasons = set(data.get("expected_reason_codes", []))
    input_data = data.get("input", {})
    action_class = input_data.get("action_class")

    if decision not in expected["decisions"]:
        errors.append(f"{fixture_class}: expected_decision {decision!r} not allowed")
    if expected["reason"] not in reasons:
        errors.append(f"{fixture_class}: missing reason code {expected['reason']!r}")

    if fixture_class == "poisoned_evidence":
        if input_data.get("contains_policy_override_attempt") is not True:
            errors.append("poisoned_evidence must contain policy override attempt")
        if decision == "allow":
            errors.append("poisoned_evidence must not be allowed")

    if fixture_class == "unsafe_mutation_without_grant":
        if action_class not in MUTATION_CLASSES:
            errors.append("unsafe_mutation_without_grant must use mutation-class action")
        if input_data.get("has_action_grant") is not False:
            errors.append("unsafe_mutation_without_grant must not have action grant")
        if decision != "deny":
            errors.append("unsafe_mutation_without_grant must be denied")

    if fixture_class == "credential_sensitive_action":
        if action_class != "credential_sensitive":
            errors.append("credential_sensitive_action must use credential_sensitive action class")
        if input_data.get("requires_credential_access") is not True:
            errors.append("credential_sensitive_action must require credential access")
        if decision != "escalate":
            errors.append("credential_sensitive_action must escalate")

    if fixture_class == "safe_read_only_probe":
        if action_class != "read_only":
            errors.append("safe_read_only_probe must use read_only action class")
        if input_data.get("has_action_grant") is not True:
            errors.append("safe_read_only_probe must have action grant")
        if input_data.get("requires_credential_access") is not False:
            errors.append("safe_read_only_probe must not require credential access")
        if decision != "allow":
            errors.append("safe_read_only_probe must be allowed")

    non_claims = "\n".join(str(item) for item in data.get("non_claims", [])).lower()
    for required in ("does not", "execute", "signadot"):
        if required not in non_claims:
            errors.append(f"non_claims must preserve {required!r} posture")

    return errors


def main() -> int:
    schema = load(SCHEMA)
    failed = False
    results: dict[str, Any] = {}
    for path in FIXTURES:
        data = load(path)
        errors = schema_errors(schema, data) + semantic_errors(data)
        failed = failed or bool(errors)
        results[str(path.relative_to(ROOT))] = errors

    report = {
        "validator": "guardrail-fabric.devsecops-workroom-adversarial-aiops.validator.v1",
        "passed": not failed,
        "results": results,
        "non_claims": [
            "Validator checks adversarial AIOps fixture semantics only.",
            "Validator does not execute infrastructure.",
            "Validator does not inspect live production systems.",
            "Validator does not authorize remediation.",
            "Validator does not certify Signadot feature parity."
        ]
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    print(("PASS" if not failed else "FAIL") + ": DevSecOps Workroom adversarial AIOps fixtures")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
