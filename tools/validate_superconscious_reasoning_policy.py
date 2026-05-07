#!/usr/bin/env python3
"""Validate Superconscious reasoning policy admission examples.

This validator is dependency-free and read-only. It verifies the M1 deterministic
Superconscious posture: local deterministic run allowed, mock/read-only tool use
allowed, memory proposal-only, no network egress, no model calls, no host state
change, no browser/terminal/document action, and no raw private reasoning.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "superconscious-reasoning-policy.example.json"
REQUIRED_ADMISSIONS = {
    "deterministicLocalRun",
    "toolUse",
    "modelRoute",
    "memoryWrite",
    "networkEgress",
    "hostStateChange",
    "browserControl",
    "terminalAction",
    "documentAction",
    "approvalEscalation",
}


def fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate(doc: dict[str, Any]) -> int:
    if doc.get("apiVersion") != "guardrail.socioprophet.dev/v1":
        return fail("apiVersion invalid")
    if doc.get("kind") != "SuperconsciousReasoningPolicyAdmission":
        return fail("kind must be SuperconsciousReasoningPolicyAdmission")

    spec = doc.get("spec") or {}
    for key in ["reasoningRunRef", "agentRef", "workspaceRef", "policyRef", "admissions", "safeTrace", "decision"]:
        if key not in spec:
            return fail(f"missing spec.{key}")
    if not str(spec["reasoningRunRef"]).startswith("urn:srcos:reasoning-run:"):
        return fail("reasoningRunRef must be a SourceOS reasoning-run URN")
    if not str(spec["agentRef"]).startswith("urn:socioprophet:agent:"):
        return fail("agentRef must be a SocioProphet agent URN")
    if not str(spec["workspaceRef"]).startswith("urn:socioprophet:workspace:"):
        return fail("workspaceRef must be a SocioProphet workspace URN")

    admissions = spec["admissions"]
    missing = sorted(REQUIRED_ADMISSIONS - set(admissions))
    if missing:
        return fail(f"admissions missing fields: {missing}")
    expected = {
        "deterministicLocalRun": "allow",
        "toolUse": "allow-readonly-mock",
        "modelRoute": "allow-deterministic-stub",
        "memoryWrite": "proposal-only",
        "networkEgress": "deny",
        "hostStateChange": "deny",
        "browserControl": "deny",
        "terminalAction": "deny",
        "documentAction": "deny",
        "approvalEscalation": "not-required",
    }
    for key, value in expected.items():
        if admissions.get(key) != value:
            return fail(f"admissions.{key} must be {value}")

    safe_trace = spec["safeTrace"]
    if safe_trace.get("mode") != "operational-trace-only":
        return fail("safeTrace.mode must be operational-trace-only")
    if safe_trace.get("rawPrivateReasoning") != "not-collected":
        return fail("safeTrace.rawPrivateReasoning must be not-collected")

    decision = spec["decision"]
    if decision.get("decisionStatus") != "allow":
        return fail("decision.decisionStatus must be allow for deterministic M1")
    reason_codes = decision.get("reasonCodes")
    if not isinstance(reason_codes, list) or not reason_codes:
        return fail("decision.reasonCodes must be a non-empty list")
    required_reasons = {
        "deterministic-local-run",
        "no-network-egress",
        "no-model-calls",
        "no-host-state-change",
        "memory-proposal-only",
        "safe-operational-trace",
    }
    if required_reasons - set(reason_codes):
        return fail("decision.reasonCodes missing required deterministic M1 reasons")
    if not str(decision.get("evidenceRef", "")).startswith("urn:srcos:reasoning-event:"):
        return fail("decision.evidenceRef must reference a SourceOS reasoning event")

    print("OK: Superconscious reasoning policy admission example validated")
    return 0


def main() -> int:
    return validate(load(FIXTURE))


if __name__ == "__main__":
    raise SystemExit(main())
