from __future__ import annotations

import json

from guardrail_fabric.simulate import main


def test_simulator_outputs_allow_decision(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main([
        "--tool",
        "Bash",
        "--action-class",
        "shell",
        "--tool-input",
        '{"command":"git status"}',
    ])

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["decision"] == "allow"
    assert data["policyId"] == "sourceos/core/simulated-event"


def test_simulator_baseline_blocks_privilege_escalation(capsys) -> None:  # type: ignore[no-untyped-def]
    exit_code = main([
        "--baseline",
        "--tool",
        "Bash",
        "--action-class",
        "shell",
        "--tool-input",
        '{"command":"sudo rm -rf /tmp/example"}',
    ])

    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert exit_code == 0
    assert data["decision"] == "deny"
    assert data["policyId"] == "sourceos/shell/block-privilege-escalation"


def test_simulator_writes_log(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    log_path = tmp_path / "decisions.jsonl"
    exit_code = main([
        "--baseline",
        "--tool",
        "Bash",
        "--action-class",
        "shell",
        "--tool-input",
        '{"command":"git status"}',
        "--write-log",
        "--log-path",
        str(log_path),
    ])

    captured = capsys.readouterr()
    stdout_data = json.loads(captured.out)
    logged_data = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])

    assert exit_code == 0
    assert stdout_data["decisionId"] == logged_data["decisionId"]
    assert logged_data["decision"] == "allow"
