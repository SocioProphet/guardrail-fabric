from __future__ import annotations

import json

from guardrail_fabric.project_hooks import DEFAULT_COMMAND, install, main, target_path


def test_project_scope_target_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    assert target_path(tmp_path, "project") == tmp_path / ".claude" / "settings.json"
    assert target_path(tmp_path, "local") == tmp_path / ".claude" / "settings.local.json"


def test_install_project_hooks_creates_settings(tmp_path) -> None:  # type: ignore[no-untyped-def]
    result = install(project_dir=tmp_path, scope="project")
    settings_path = tmp_path / ".claude" / "settings.json"
    settings = json.loads(settings_path.read_text(encoding="utf-8"))

    assert result.changed is True
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "*"
    assert settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == DEFAULT_COMMAND
    assert settings["hooks"]["PostToolUse"][0]["hooks"][0]["type"] == "command"
    assert settings["hooks"]["PostToolUse"][0]["hooks"][0]["timeout"] == 10


def test_install_local_scope_writes_settings_local(tmp_path) -> None:  # type: ignore[no-untyped-def]
    install(project_dir=tmp_path, scope="local", events=("PreToolUse",), matcher="Bash")

    assert not (tmp_path / ".claude" / "settings.json").exists()
    settings = json.loads((tmp_path / ".claude" / "settings.local.json").read_text(encoding="utf-8"))
    assert list(settings["hooks"].keys()) == ["PreToolUse"]
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "Bash"


def test_install_is_idempotent(tmp_path) -> None:  # type: ignore[no-untyped-def]
    first = install(project_dir=tmp_path, scope="project")
    second = install(project_dir=tmp_path, scope="project")

    assert first.changed is True
    assert second.changed is False
    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert len(settings["hooks"]["PreToolUse"][0]["hooks"]) == 1
    assert len(settings["hooks"]["PostToolUse"][0]["hooks"]) == 1


def test_install_dry_run_does_not_write(tmp_path) -> None:  # type: ignore[no-untyped-def]
    result = install(project_dir=tmp_path, scope="project", dry_run=True)

    assert result.changed is True
    assert result.dryRun is True
    assert not (tmp_path / ".claude" / "settings.json").exists()


def test_install_merges_existing_settings(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings_path = tmp_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps(
            {
                "env": {"EXISTING": "1"},
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Read",
                            "hooks": [{"type": "command", "command": "echo read"}],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    install(project_dir=tmp_path, scope="project", matcher="Bash")
    settings = json.loads(settings_path.read_text(encoding="utf-8"))

    assert settings["env"] == {"EXISTING": "1"}
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "Read"
    assert settings["hooks"]["PreToolUse"][1]["matcher"] == "Bash"
    assert settings["hooks"]["PostToolUse"][0]["matcher"] == "Bash"


def test_cli_outputs_install_result(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main(["--project-dir", str(tmp_path), "--scope", "project", "--events", "PreToolUse", "--matcher", "Bash"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["changed"] is True
    assert data["scope"] == "project"
    assert data["settings"]["hooks"]["PreToolUse"][0]["matcher"] == "Bash"
