"""Tests for Guardrail Fabric TrustOps preflight handoff."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from guardrail_fabric.preflight_handoff import (
    SAFETY_OWNER,
    TrustOpsPreflightHandoffError,
    build_preflight_handoff,
)
from guardrail_fabric.trustops_runtime_actions import (
    RuntimeGuardrailAction,
    TrustOpsGateDecision,
    TrustOpsOutcome,
)

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools" / "validate_preflight_handoff.py"
FIXTURES = ROOT / "tests" / "fixtures" / "preflight-handoff"


def run_validator(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(path)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def test_build_preflight_handoff_pass_projects_to_agentplane() -> None:
    handoff = build_preflight_handoff(
        [
            TrustOpsGateDecision(
                outcome=TrustOpsOutcome.PASS,
                receipt_id="trustops-receipt:pass-001",
                gate_id="gate://trustops/safety-preflight/pass",
                evidence_refs=("evidence://trustops/safety-preflight/pass",),
            )
        ],
        handoff_id="trustops-preflight-handoff:pass-001",
    )

    assert handoff.source_system == SAFETY_OWNER
    assert handoff.outcome == TrustOpsOutcome.PASS
    assert handoff.runtime_action == RuntimeGuardrailAction.ALLOW
    assert handoff.to_agentplane_projection() == {
        "outcome": "pass",
        "runtime_action": "allow",
        "authoritative_safety_owner": SAFETY_OWNER,
        "handoff_ref": "trustops-preflight-handoff:pass-001",
    }


def test_build_preflight_handoff_preserves_require_review() -> None:
    handoff = build_preflight_handoff(
        [
            TrustOpsGateDecision(
                outcome=TrustOpsOutcome.REQUIRE_REVIEW,
                receipt_id="trustops-receipt:review-001",
                gate_id="gate://trustops/safety-preflight/dependency-approval-required",
                evidence_refs=("evidence://trustops/safety-preflight/dependency-approval/package.json",),
            )
        ],
        handoff_id="trustops-preflight-handoff:review-001",
    )

    assert handoff.outcome == TrustOpsOutcome.REQUIRE_REVIEW
    assert handoff.runtime_action == RuntimeGuardrailAction.REQUIRE_REVIEW


def test_build_preflight_handoff_blocks_downgrade_override() -> None:
    with pytest.raises(TrustOpsPreflightHandoffError):
        build_preflight_handoff(
            [
                TrustOpsGateDecision(
                    outcome=TrustOpsOutcome.ROLLBACK,
                    receipt_id="trustops-receipt:rollback-001",
                    gate_id="gate://trustops/safety-preflight/rollback-required",
                    evidence_refs=("evidence://trustops/safety-preflight/rollback-required",),
                    runtime_action_override=RuntimeGuardrailAction.WARN,
                )
            ],
            handoff_id="trustops-preflight-handoff:rollback-001",
        )


def test_valid_handoff_fixtures_validate() -> None:
    for name in ("pass-allow.valid.json", "require-review.valid.json", "block.valid.json"):
        result = run_validator(FIXTURES / name)
        assert result.returncode == 0, result.stderr
        assert "OK:" in result.stdout


def test_invalid_handoff_fixtures_fail_closed() -> None:
    for name in (
        "rollback-degraded-to-warn.invalid.json",
        "quarantine-missing-evidence.invalid.json",
    ):
        result = run_validator(FIXTURES / name)
        assert result.returncode == 1
        assert "ERROR:" in result.stderr
