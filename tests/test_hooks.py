from __future__ import annotations

import io
import json
import sys

from guardrail_fabric.decision import ActionClass, Decision
from guardrail_fabric.hooks import (
    evaluate_claude_code_payload,
    hook_event_name,
    infer_action_class,
    main,
    normalize_claude_code_payload,
    render_claude_code_response,
)


class _Stdin:
    def __init__(self, payload: bytes) -> None:
        self.buffer = io.BytesIO(payload)


def test_infer_action_class_for_git_command() -> None:
    action_class = infer_action_class("Bash", {"command": "git status"})
    assert action_class == ActionClass.GIT


def test_hook_event_name_defaults_to_pretooluse() -> None:
    assert hook_event_name({}) == "PreToolUse"
    assert hook_event_name({"hook_event_name": "PostToolUse"}) == "PostToolUse"
    assert hook_event_name({"hookEventName": "PostToolUse"}) == "PostToolUse"


def test_normalize_claude_code_payload() -> None:
    ctx = normalize_claude_code_payload(
        {
            "session_id": "session-1",
            "cwd": "/tmp/repo",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
        }
    )

    assert ctx.tool == "Bash"
    assert ctx.action_class == ActionClass.GIT
    assert ctx.command == "git status"
    assert ctx.cwd == "/tmp/repo"
    assert ctx.session_id == "session-1"
    assert ctx.agent_id == "claude-code"


def test_hook_evaluation_blocks_privilege_escalation() -> None:
    evaluation = evaluate_claude_code_payload(
        {
            "session_id": "session-1",
            "tool_name": "Bash",
            "tool_input": {"command": "sudo rm -rf /tmp/example"},
        }
    )

    assert evaluation.exit_code == 0
    assert evaluation.decision.policyId == "sourceos/shell/block-privilege-escalation"
    assert evaluation.decision.decision == Decision.DENY
    assert evaluation.response is not None
    assert evaluation.response["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert evaluation.response["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "Remediation:" in evaluation.response["hookSpecificOutput"]["permissionDecisionReason"]


def test_posttooluse_block_response_uses_decision_block() -> None:
    evaluation = evaluate_claude_code_payload(
        {
            "hook_event_name": "PostToolUse",
            "session_id": "session-1",
            "tool_name": "Bash",
            "tool_input": {"command": "cat output.txt"},
            "tool_response": {"stdout": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"},
        }
    )

    assert evaluation.decision.policyId == "sourceos/secrets/redact-secret-output"
    assert evaluation.response is not None
    assert evaluation.response["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert evaluation.response["hookSpecificOutput"]["additionalContext"]


def test_hook_evaluation_redacts_secret_output_as_context() -> None:
    evaluation = evaluate_claude_code_payload(
        {
            "session_id": "session-1",
            "tool_name": "Bash",
            "tool_input": {"command": "cat output.txt"},
            "tool_result": {"stdout": "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"},
        }
    )

    assert evaluation.decision.policyId == "sourceos/secrets/redact-secret-output"
    assert evaluation.decision.decision == Decision.REDACT
    assert evaluation.response is not None
    assert "additionalContext" in evaluation.response["hookSpecificOutput"]


def test_hook_evaluation_oversized_payload_defers() -> None:
    evaluation = evaluate_claude_code_payload(
        {
            "session_id": "session-1",
            "tool_name": "Write",
            "tool_input": {"file_path": "big.txt"},
        },
        payload_size_bytes=2_000_000,
        payload_limit_bytes=1_000,
    )

    assert evaluation.decision.policyId == "sourceos/core/oversized-payload"
    assert evaluation.decision.decision == Decision.DEFER
    assert evaluation.response is not None
    assert evaluation.response["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_render_allow_response_is_empty() -> None:
    evaluation = evaluate_claude_code_payload(
        {
            "session_id": "session-1",
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
        }
    )
    response, exit_code = render_claude_code_response(evaluation.decision)

    assert response is None
    assert exit_code == 0


def test_hook_cli_debug_decision(monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    payload = json.dumps(
        {
            "session_id": "session-1",
            "tool_name": "Bash",
            "tool_input": {"command": "sudo rm -rf /tmp/example"},
        }
    ).encode("utf-8")
    monkeypatch.setattr(sys, "stdin", _Stdin(payload))

    exit_code = main(["--debug-decision"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["policyId"] == "sourceos/shell/block-privilege-escalation"
    assert data["decision"] == "deny"


def test_hook_cli_writes_log(monkeypatch, tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    payload = json.dumps(
        {
            "session_id": "session-1",
            "cwd": str(tmp_path),
            "tool_name": "Bash",
            "tool_input": {"command": "git status"},
        }
    ).encode("utf-8")
    log_path = tmp_path / "hook-decisions.jsonl"
    monkeypatch.setattr(sys, "stdin", _Stdin(payload))

    exit_code = main(["--write-log", "--log-path", str(log_path), "--debug-decision"])
    captured = capsys.readouterr()
    stdout_data = json.loads(captured.out)
    log_data = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])

    assert exit_code == 0
    assert stdout_data["decisionId"] == log_data["decisionId"]
    assert log_data["schema"] == "sourceos.guardrail.decision.v0.1"
