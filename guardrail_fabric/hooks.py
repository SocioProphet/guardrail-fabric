"""Agent hook adapters for guardrail-fabric.

The first adapter normalizes Claude Code-style hook payloads into the
SourceOS PolicyContext and renders a compatible hook response from the shared
SourceOS decision ABI. The adapter remains model-free and local-first.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .decision import ActionClass, Decision, PolicyDecision, decision_from_event
from .log import append_decision
from .policies import PolicyContext, evaluate_baseline

DEFAULT_STDIN_LIMIT_BYTES = 1_048_576


@dataclass(frozen=True)
class HookEvaluation:
    """Result of evaluating one agent hook event."""

    decision: PolicyDecision
    response: dict[str, Any] | None
    exit_code: int


def read_stdin_bytes(limit_bytes: int = DEFAULT_STDIN_LIMIT_BYTES) -> tuple[bytes, bool]:
    """Read stdin while detecting oversized payloads without implicit allow."""

    data = sys.stdin.buffer.read(limit_bytes + 1)
    return data[:limit_bytes], len(data) > limit_bytes


def infer_action_class(tool_name: str | None, tool_input: dict[str, Any]) -> ActionClass:
    """Infer a coarse action class from a normalized tool event."""

    tool = tool_name or ""
    command = str(tool_input.get("command", "")).strip().lower()
    file_path = str(tool_input.get("file_path") or tool_input.get("path") or "")

    if tool in {"Read", "Write", "Edit", "MultiEdit", "Delete"} or file_path:
        return ActionClass.FILESYSTEM
    if tool == "Bash":
        if command.startswith("git ") or " git " in command:
            return ActionClass.GIT
        if command.startswith(("kubectl ", "terraform ", "tofu ", "aws ", "gcloud ", "az ", "helm ", "gh ")):
            return ActionClass.INFRA
        if command.startswith(("psql ", "mysql ", "sqlite3 ", "pgcli ", "clickhouse-client ")):
            return ActionClass.DATABASE
        if command.startswith(("npm ", "pnpm ", "yarn ", "bun ", "pip ", "pip3 ", "uv ", "poetry ", "cargo ", "gem ", "twine ")):
            return ActionClass.PACKAGE
        if command.startswith(("curl ", "wget ", "http ", "httpie ")):
            return ActionClass.NETWORK
        return ActionClass.SHELL
    if "browser" in tool.lower() or "playwright" in tool.lower() or "cdp" in tool.lower():
        return ActionClass.BROWSER
    if "model" in tool.lower() or "llm" in tool.lower():
        return ActionClass.MODEL
    return ActionClass.UNKNOWN


def normalize_claude_code_payload(payload: dict[str, Any]) -> PolicyContext:
    """Normalize a Claude Code-style hook payload into PolicyContext.

    Expected input shape is intentionally permissive so adapters can pass
    through current and future hook payload versions.
    """

    tool_name = payload.get("tool_name") or payload.get("toolName")
    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    tool_result = payload.get("tool_result") or payload.get("toolResult")
    session_id = payload.get("session_id") or payload.get("sessionId")
    cwd = payload.get("cwd")

    if not isinstance(tool_input, dict):
        tool_input = {"raw": tool_input}
    if tool_result is not None and not isinstance(tool_result, dict):
        tool_result = {"raw": tool_result}

    return PolicyContext(
        tool=str(tool_name) if tool_name is not None else None,
        action_class=infer_action_class(str(tool_name) if tool_name is not None else None, tool_input),
        tool_input=tool_input,
        tool_output=tool_result,
        cwd=str(cwd) if cwd is not None else None,
        session_id=str(session_id) if session_id is not None else None,
        agent_id="claude-code",
        task_id=str(payload.get("task_id") or payload.get("taskId")) if payload.get("task_id") or payload.get("taskId") else None,
    )


def render_claude_code_response(decision: PolicyDecision) -> tuple[dict[str, Any] | None, int]:
    """Render a SourceOS decision as a Claude Code-compatible hook response."""

    if decision.decision == Decision.ALLOW:
        return None, 0

    message = f"SourceOS guardrail {decision.policyId}: {decision.reason} Remediation: {decision.remediation}"

    if decision.decision in {Decision.DENY, Decision.QUARANTINE, Decision.DEFER, Decision.ESCALATE}:
        return {
            "hookSpecificOutput": {
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }, 0

    if decision.decision in {Decision.INSTRUCT, Decision.ALLOW_WITH_CONTEXT, Decision.REDACT}:
        return {
            "hookSpecificOutput": {
                "additionalContext": message,
            }
        }, 0

    return {
        "hookSpecificOutput": {
            "additionalContext": message,
        }
    }, 0


def evaluate_claude_code_payload(
    payload: dict[str, Any],
    *,
    payload_size_bytes: int | None = None,
    payload_limit_bytes: int = DEFAULT_STDIN_LIMIT_BYTES,
    required_policy_error: str | None = None,
) -> HookEvaluation:
    """Evaluate one Claude Code-style hook payload through baseline policies."""

    ctx = normalize_claude_code_payload(payload)

    if payload_size_bytes is not None and payload_size_bytes > payload_limit_bytes:
        decision = decision_from_event(
            policy_id="sourceos/core/hook-event",
            tool=ctx.tool,
            action_class=ctx.action_class,
            tool_input=ctx.tool_input,
            tool_output=ctx.tool_output,
            cwd=ctx.cwd,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            task_id=ctx.task_id,
            payload_size_bytes=payload_size_bytes,
            payload_limit_bytes=payload_limit_bytes,
        )
    elif required_policy_error:
        decision = decision_from_event(
            policy_id="sourceos/core/hook-event",
            tool=ctx.tool,
            action_class=ctx.action_class,
            tool_input=ctx.tool_input,
            tool_output=ctx.tool_output,
            cwd=ctx.cwd,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            task_id=ctx.task_id,
            required_policy_error=required_policy_error,
        )
    else:
        decision = evaluate_baseline(ctx)

    response, exit_code = render_claude_code_response(decision)
    return HookEvaluation(decision=decision, response=response, exit_code=exit_code)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail-fabric-hook",
        description="Evaluate an agent hook payload through SourceOS guardrails.",
    )
    parser.add_argument("--adapter", choices=["claude-code"], default="claude-code")
    parser.add_argument("--payload-limit-bytes", type=int, default=DEFAULT_STDIN_LIMIT_BYTES)
    parser.add_argument("--write-log", action="store_true", help="Append the decision to a SourceOS JSONL log")
    parser.add_argument("--log-path", help="Override decision log path")
    parser.add_argument("--debug-decision", action="store_true", help="Emit full SourceOS decision instead of hook response")
    parser.add_argument("--required-policy-error", help="Simulate a required policy loader failure")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    raw, oversized = read_stdin_bytes(args.payload_limit_bytes)
    if oversized:
        payload: dict[str, Any] = {}
        payload_size = args.payload_limit_bytes + 1
    else:
        payload_size = len(raw)
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            payload = {
                "tool_name": "unknown",
                "tool_input": {"json_decode_error": str(exc)},
            }
            args.required_policy_error = args.required_policy_error or f"invalid hook JSON: {exc}"

    evaluation = evaluate_claude_code_payload(
        payload,
        payload_size_bytes=payload_size if oversized else None,
        payload_limit_bytes=args.payload_limit_bytes,
        required_policy_error=args.required_policy_error,
    )

    if args.write_log:
        cwd = evaluation.decision.evidence.cwd
        append_decision(evaluation.decision, path=args.log_path, cwd=cwd)

    if args.debug_decision:
        sys.stdout.write(json.dumps(evaluation.decision.to_dict(), indent=2, sort_keys=True))
        sys.stdout.write("\n")
    elif evaluation.response is not None:
        sys.stdout.write(json.dumps(evaluation.response, sort_keys=True))
        sys.stdout.write("\n")

    return evaluation.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
