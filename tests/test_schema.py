from __future__ import annotations

import json
from pathlib import Path

from guardrail_fabric import ActionClass, Decision, decision_from_event

from tools.validate_trust_chain_runtime_admission import main as validate_trust_chain_runtime_admission


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "sourceos.guardrail.decision.v0.1.schema.json"
TRUST_CHAIN_ALLOW = ROOT / "examples" / "trust-chain" / "runtime-asset-admission.allow.json"
TRUST_CHAIN_DENY = ROOT / "examples" / "trust-chain" / "runtime-asset-admission.deny.json"


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


def test_trust_chain_runtime_admission_fixtures_validate() -> None:
    assert validate_trust_chain_runtime_admission() == 0


def test_trust_chain_allow_fixture_permits_agent_continuation() -> None:
    fixture = json.loads(TRUST_CHAIN_ALLOW.read_text(encoding="utf-8"))
    assert fixture["decision"] == "allow"
    assert fixture["evidence"]["actionClass"] == "runtime"
    assert fixture["evidence"]["artifactType"] == "RuntimeAsset"
    assert fixture["effects"]["agentMayContinue"] is True
    assert fixture["effects"]["requiresHumanApproval"] is False


def test_trust_chain_deny_fixture_stops_agent_continuation() -> None:
    fixture = json.loads(TRUST_CHAIN_DENY.read_text(encoding="utf-8"))
    assert fixture["decision"] == "deny"
    assert fixture["evidence"]["actionClass"] == "runtime"
    assert fixture["evidence"]["artifactType"] == "RuntimeAsset"
    assert fixture["evidence"]["promotionPosture"] == "production_denied"
    assert fixture["effects"]["agentMayContinue"] is False
    assert fixture["effects"]["requiresHumanApproval"] is True
