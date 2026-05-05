"""Local evidence logging for guardrail-fabric decisions."""

from __future__ import annotations

from pathlib import Path

from .decision import PolicyDecision


def default_decision_log_path(cwd: str | Path | None = None) -> Path:
    """Return the default repo-local SourceOS guardrail decision log path."""

    root = Path(cwd or ".").expanduser().resolve()
    return root / ".sourceos" / "logs" / "guardrail-decisions.jsonl"


def append_decision(decision: PolicyDecision, path: str | Path | None = None, *, cwd: str | Path | None = None) -> Path:
    """Append a decision artifact to a JSONL log and return the log path."""

    target = Path(path).expanduser().resolve() if path else default_decision_log_path(cwd)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(decision.to_json())
        handle.write("\n")
    return target
