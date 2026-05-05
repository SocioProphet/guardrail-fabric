"""Minimal guardrail-fabric simulation CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .decision import ActionClass, decision_from_event
from .log import append_decision
from .policies import PolicyContext, evaluate_baseline


def _load_json_arg(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    candidate = Path(value)
    if candidate.exists():
        return json.loads(candidate.read_text(encoding="utf-8"))
    return json.loads(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail-fabric",
        description="Simulate a SourceOS guardrail decision from a normalized tool event.",
    )
    parser.add_argument("--policy-id", default="sourceos/core/simulated-event")
    parser.add_argument("--tool", default="Bash")
    parser.add_argument(
        "--action-class",
        default=ActionClass.UNKNOWN.value,
        choices=[item.value for item in ActionClass],
    )
    parser.add_argument("--tool-input", help="JSON object or path to JSON file")
    parser.add_argument("--tool-output", help="JSON object or path to JSON file")
    parser.add_argument("--repo")
    parser.add_argument("--branch")
    parser.add_argument("--commit")
    parser.add_argument("--cwd")
    parser.add_argument("--session-id")
    parser.add_argument("--agent-id")
    parser.add_argument("--task-id")
    parser.add_argument("--payload-size-bytes", type=int)
    parser.add_argument("--payload-limit-bytes", type=int, default=1_048_576)
    parser.add_argument("--required-policy-error")
    parser.add_argument("--baseline", action="store_true", help="Evaluate the built-in SourceOS baseline policy pack")
    parser.add_argument("--write-log", action="store_true", help="Append the decision to .sourceos/logs/guardrail-decisions.jsonl")
    parser.add_argument("--log-path", help="Override decision log path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    tool_input = _load_json_arg(args.tool_input)
    tool_output = _load_json_arg(args.tool_output) if args.tool_output else None

    if args.baseline and args.payload_size_bytes is None and not args.required_policy_error:
        decision = evaluate_baseline(
            PolicyContext(
                tool=args.tool,
                action_class=ActionClass(args.action_class),
                tool_input=tool_input,
                tool_output=tool_output,
                repo=args.repo,
                branch=args.branch,
                commit=args.commit,
                cwd=args.cwd,
                session_id=args.session_id,
                agent_id=args.agent_id,
                task_id=args.task_id,
            )
        )
    else:
        decision = decision_from_event(
            policy_id=args.policy_id,
            tool=args.tool,
            action_class=ActionClass(args.action_class),
            tool_input=tool_input,
            tool_output=tool_output,
            repo=args.repo,
            branch=args.branch,
            commit=args.commit,
            cwd=args.cwd,
            session_id=args.session_id,
            agent_id=args.agent_id,
            task_id=args.task_id,
            payload_size_bytes=args.payload_size_bytes,
            payload_limit_bytes=args.payload_limit_bytes,
            required_policy_error=args.required_policy_error,
        )

    if args.write_log:
        append_decision(decision, path=args.log_path, cwd=args.cwd)

    sys.stdout.write(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
