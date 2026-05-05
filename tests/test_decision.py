from __future__ import annotations

import json

from guardrail_fabric import ActionClass, Decision, decision_from_event
from guardrail_fabric.log import append_decision


def test_default_event_allows_with_digest() -> None:
    decision = decision_from_event(
        policy_id="sourceos/core/simulated-event",
        tool="Bash",
        action_class=ActionClass.SHELL,
        tool_input={"command": "git status"},
        repo="SocioProphet/guardrail-fabric",
        branch="main",
    )

    data = decision.to_dict()
    assert data["schema"] == "sourceos.guardrail.decision.v0.1"
    assert data["decision"] == Decision.ALLOW.value
    assert data["effects"]["agentMayContinue"] is True
    assert data["evidence"]["inputDigest"].startswith("sha256:")
    assert data["evidence"]["actionClass"] == ActionClass.SHELL.value


def test_oversized_payload_defers_not_fail_open() -> None:
    decision = decision_from_event(
        policy_id="sourceos/core/simulated-event",
        tool="Write",
        action_class=ActionClass.FILESYSTEM,
        payload_size_bytes=2_000_000,
        payload_limit_bytes=1_000,
    )

    assert decision.policyId == "sourceos/core/oversized-payload"
    assert decision.decision == Decision.DEFER
    assert decision.effects.agentMayContinue is False
    assert decision.effects.requiresHumanApproval is True


def test_required_policy_error_quarantines() -> None:
    decision = decision_from_event(
        policy_id="sourceos/core/simulated-event",
        tool="Bash",
        action_class=ActionClass.SHELL,
        required_policy_error="missing sourceos/git policy pack",
    )

    assert decision.policyId == "sourceos/core/required-policy-load-failed"
    assert decision.decision == Decision.QUARANTINE
    assert decision.effects.agentMayContinue is False
    assert decision.effects.requiresHumanApproval is True


def test_append_decision_writes_jsonl(tmp_path) -> None:
    decision = decision_from_event(
        policy_id="sourceos/core/simulated-event",
        tool="Bash",
        action_class=ActionClass.SHELL,
        tool_input={"command": "git status"},
    )

    log_path = append_decision(decision, cwd=tmp_path)
    lines = log_path.read_text(encoding="utf-8").splitlines()

    assert log_path == tmp_path / ".sourceos" / "logs" / "guardrail-decisions.jsonl"
    assert len(lines) == 1
    assert json.loads(lines[0])["decisionId"] == decision.decisionId
