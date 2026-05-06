"""Repo-local agent hook settings installer.

This module writes only project-local settings files under `.claude/`.
It never edits user home settings.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EVENTS = ("PreToolUse", "PostToolUse")
SCOPES = ("project", "local")
DEFAULT_COMMAND = "guardrail-fabric-hook --write-log"
DEFAULT_MATCHER = "*"
DEFAULT_TIMEOUT = 10


@dataclass(frozen=True)
class InstallResult:
    target: str
    scope: str
    changed: bool
    dryRun: bool
    settings: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scope": self.scope,
            "changed": self.changed,
            "dryRun": self.dryRun,
            "settings": self.settings,
        }


def target_path(project_dir: Path, scope: str) -> Path:
    if scope == "project":
        return project_dir / ".claude" / "settings.json"
    if scope == "local":
        return project_dir / ".claude" / "settings.local.json"
    raise ValueError(f"unsupported scope: {scope}")


def load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"settings must be a JSON object: {path}")
    return data


def hook(command: str, timeout: int | None) -> dict[str, Any]:
    value: dict[str, Any] = {"type": "command", "command": command}
    if timeout is not None:
        value["timeout"] = timeout
    return value


def has_command(entry: dict[str, Any], command: str) -> bool:
    hooks = entry.get("hooks")
    if not isinstance(hooks, list):
        return False
    return any(isinstance(item, dict) and item.get("type") == "command" and item.get("command") == command for item in hooks)


def add_event(settings: dict[str, Any], event: str, matcher: str, command: str, timeout: int | None, replace: bool) -> bool:
    hooks_root = settings.setdefault("hooks", {})
    if not isinstance(hooks_root, dict):
        raise ValueError("settings.hooks must be an object")
    entries = hooks_root.setdefault(event, [])
    if not isinstance(entries, list):
        raise ValueError(f"settings.hooks.{event} must be a list")

    desired = hook(command, timeout)
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("matcher", "") != matcher:
            continue
        items = entry.setdefault("hooks", [])
        if not isinstance(items, list):
            raise ValueError(f"settings.hooks.{event}.hooks must be a list")
        if has_command(entry, command):
            if not replace:
                return False
            before = json.dumps(items, sort_keys=True)
            items[:] = [item for item in items if not (isinstance(item, dict) and item.get("type") == "command" and item.get("command") == command)]
            items.append(desired)
            return json.dumps(items, sort_keys=True) != before
        items.append(desired)
        return True

    entries.append({"matcher": matcher, "hooks": [desired]})
    return True


def install(
    *,
    project_dir: Path,
    scope: str = "project",
    events: tuple[str, ...] = EVENTS,
    matcher: str = DEFAULT_MATCHER,
    command: str = DEFAULT_COMMAND,
    timeout: int | None = DEFAULT_TIMEOUT,
    dry_run: bool = False,
    replace: bool = False,
) -> InstallResult:
    invalid = [event for event in events if event not in EVENTS]
    if invalid:
        raise ValueError(f"unsupported events: {invalid}")
    target = target_path(project_dir, scope)
    settings = load_json_object(target)
    before = json.dumps(settings, sort_keys=True)
    for event in events:
        add_event(settings, event, matcher, command, timeout, replace)
    changed = before != json.dumps(settings, sort_keys=True)
    if changed and not dry_run:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(settings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return InstallResult(str(target), scope, changed, dry_run, settings)


def parse_events(value: str | None) -> tuple[str, ...]:
    if not value:
        return EVENTS
    return tuple(part.strip() for part in value.split(",") if part.strip())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install repo-local SourceOS guardrail hook settings.")
    parser.add_argument("--project-dir", default=".")
    parser.add_argument("--scope", choices=SCOPES, default="project")
    parser.add_argument("--events")
    parser.add_argument("--matcher", default=DEFAULT_MATCHER)
    parser.add_argument("--command", default=DEFAULT_COMMAND)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--no-timeout", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--replace", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = install(
        project_dir=Path(args.project_dir).resolve(),
        scope=args.scope,
        events=parse_events(args.events),
        matcher=args.matcher,
        command=args.command,
        timeout=None if args.no_timeout else args.timeout,
        dry_run=args.dry_run,
        replace=args.replace,
    )
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
