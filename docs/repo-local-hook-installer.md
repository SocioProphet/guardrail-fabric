# Repo-local SourceOS hook installer

`guardrail-fabric-install-project-hooks` installs SourceOS guardrail hooks into repo-local Claude Code-style settings files.

It intentionally supports only repo-local scopes:

- `project` writes `.claude/settings.json`
- `local` writes `.claude/settings.local.json`

It does not write user home settings.

## Install project hooks

```bash
guardrail-fabric-install-project-hooks --scope project
```

This registers both `PreToolUse` and `PostToolUse` events with:

```bash
guardrail-fabric-hook --write-log
```

## Install local-only hooks

```bash
guardrail-fabric-install-project-hooks --scope local
```

## Preview without writing

```bash
guardrail-fabric-install-project-hooks --dry-run
```

## Match one tool class

```bash
guardrail-fabric-install-project-hooks --matcher Bash
```

## Refresh an existing matching command

```bash
guardrail-fabric-install-project-hooks --replace
```

## Event selection

```bash
guardrail-fabric-install-project-hooks --events PreToolUse
```

By default, the installer registers both `PreToolUse` and `PostToolUse`.

## Generated settings shape

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "guardrail-fabric-hook --write-log",
            "timeout": 10
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "guardrail-fabric-hook --write-log",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

## Safety posture

The installer merges with existing settings, deduplicates matching command hooks, supports dry-run, and does not edit user-level configuration.
