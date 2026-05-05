from __future__ import annotations

import json
from pathlib import Path

from guardrail_fabric import ActionClass, Decision, decision_from_event


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sourceos.guardrail.decision.v0.1.schema.json"


def test_schema_file_loads_and_declares_required_fields() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["title"] == "SourceOS Guardrail Policy Decision v0.1"
    assert schema["properties"]["schema"]["const"] == "sourceos.guardrail.decision.v0.1"
    for field in (
        "schema",
        "decisionId",
        "timestamp",
        "policyId",
        "policyVersion",
        "scope",
        "severity",
        "decision",
        "reason",
        "remediation",
        "evidence",
        "effects",
    ):
        assert field in schema["required"]


def test_decision_artifact_matches_schema_enums() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    artifact = decision_from_event(
        policy_id="sourceos/core/simulated-event",
        tool="Bash",
        action_class=ActionClass.SHELL,
        tool_input={"command": "git status"},
    ).to_dict()

    assert artifact["schema"] == schema["properties"]["schema"]["const"]
    assert artifact["decision"] in schema["properties"]["decision"]["enum"]
    assert artifact["scope"] in schema["properties"]["scope"]["enum"]
    assert artifact["severity"] in schema["properties"]["severity"]["enum"]
    assert artifact["evidence"]["actionClass"] in schema["properties"]["evidence"]["properties"]["actionClass"]["enum"]
    assert artifact["decision"] == Decision.ALLOW.value
