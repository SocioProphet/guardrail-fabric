"""Tests for TrustOps guardrail action decision records."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from guardrail_fabric.trustops_runtime_actions import (
    RuntimeGuardrailAction,
    TrustOpsGateDecision,
    TrustOpsOutcome,
    build_guardrail_action_decision_dict,
)

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_trustops_guardrail_action_decision.py"
FIXTURES = ROOT / "tests" / "fixtures" / "trustops-guardrail-action-decision"


def validate_fixture(name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(FIXTURES / name)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_build_guardrail_action_decision_does_not_mutate_authority() -> None:
    record = build_guardrail_action_decision_dict(
        [
            TrustOpsGateDecision(
                outcome=TrustOpsOutcome.BLOCK,
                receipt_id="trustops-receipt:block-001",
                gate_id="gate://trustops/privacy-leakage",
                evidence_refs=("evidence://trustops/privacy-leakage/trace-001",),
            )
        ],
        decision_id="trustops-guardrail-action-decision:block-001",
        issued_at="2026-05-26T20:50:00Z",
        policy_refs=("policy://trustops/runtime-action-v0.1",),
    )

    assert record["recordType"] == "TrustOpsGuardrailActionDecision"
    assert record["runtime_action"] == "block"
    assert record["authority_mutation"]["performed"] is False
    assert record["authority_mutation"]["authority_plane"] == "SocioProphet/agent-registry"
    assert record["authority_mutation"]["downstream_intent"] == "requires-agent-registry-decision"
    assert record["agentplane_projection"]["guardrail_action_ref"] == record["decision_id"]


def test_allow_guardrail_action_has_no_authority_intent() -> None:
    record = build_guardrail_action_decision_dict(
        [
            {
                "outcome": "pass",
                "receipt_id": "trustops-receipt:pass-001",
                "gate_id": "gate://trustops/art-smoke",
                "evidence_refs": ["evidence://trustops/art-smoke/receipt-001"],
            }
        ],
        decision_id="trustops-guardrail-action-decision:allow-001",
        issued_at="2026-05-26T20:55:00Z",
        policy_refs=("policy://trustops/runtime-action-v0.1",),
    )

    assert record["runtime_action"] == RuntimeGuardrailAction.ALLOW.value
    assert record["authority_mutation"]["performed"] is False
    assert record["authority_mutation"]["downstream_intent"] == "none"


def test_valid_guardrail_action_fixture_validates() -> None:
    result = validate_fixture("block.valid.json")
    assert result.returncode == 0, result.stderr
    assert "OK:" in result.stdout


def test_authority_mutation_fixture_fails() -> None:
    result = validate_fixture("authority-mutated.invalid.json")
    assert result.returncode == 1
    assert "must not directly mutate agent authority" in result.stderr


def test_rollback_degraded_fixture_fails() -> None:
    result = validate_fixture("rollback-degraded-to-warn.invalid.json")
    assert result.returncode == 1
    assert "cannot lower TrustOps outcome severity" in result.stderr


def test_valid_fixture_roundtrips_json() -> None:
    payload = json.loads((FIXTURES / "block.valid.json").read_text(encoding="utf-8"))
    assert payload["authority_mutation"]["performed"] is False
    assert payload["agentplane_projection"]["authoritative_safety_owner"] == "SocioProphet/guardrail-fabric"
