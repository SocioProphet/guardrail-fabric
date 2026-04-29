from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "guardrail_fabric.py"
spec = importlib.util.spec_from_file_location("guardrail_fabric", MODULE_PATH)
assert spec and spec.loader
guardrail_fabric = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guardrail_fabric)


def test_guardrail_allows_safe_citation_required_input() -> None:
    policy = guardrail_fabric.load_json(ROOT / "examples" / "guardrail-policy.example.json")
    guardrail_input = guardrail_fabric.load_json(ROOT / "examples" / "guardrail-input.example.json")

    decision = guardrail_fabric.evaluate(policy, guardrail_input)

    assert decision["kind"] == "GuardrailDecision"
    assert decision["spec"]["decisionStatus"] == "allow"
    assert "citation-required" in decision["spec"]["reasonCodes"]
    assert "evidence-ref-present" in decision["spec"]["reasonCodes"]


def test_guardrail_denies_secret_signal_with_redaction_hint() -> None:
    policy = guardrail_fabric.load_json(ROOT / "examples" / "guardrail-policy.example.json")
    guardrail_input = guardrail_fabric.load_json(ROOT / "examples" / "guardrail-input.example.json")
    guardrail_input["spec"]["detectedSignals"] = ["secrets"]

    decision = guardrail_fabric.evaluate(policy, guardrail_input)

    assert decision["spec"]["decisionStatus"] == "deny"
    assert "deny-signal-detected" in decision["spec"]["reasonCodes"]
    assert "redact-detected-secrets" in decision["spec"]["redactionHints"]


def test_guardrail_requires_review_for_pii_with_masking_hint() -> None:
    policy = guardrail_fabric.load_json(ROOT / "examples" / "guardrail-policy.example.json")
    guardrail_input = guardrail_fabric.load_json(ROOT / "examples" / "guardrail-input.example.json")
    guardrail_input["spec"]["detectedSignals"] = ["pii"]

    decision = guardrail_fabric.evaluate(policy, guardrail_input)

    assert decision["spec"]["decisionStatus"] == "requires-review"
    assert "review-signal-detected" in decision["spec"]["reasonCodes"]
    assert "mask-pii" in decision["spec"]["maskingHints"]


def test_cli_emits_demo_decision(tmp_path: Path) -> None:
    out = tmp_path / "decision.json"
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "guardrail_fabric.py"), "emit-demo-decision", "--output", str(out)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["kind"] == "GuardrailDecision"
    assert payload["spec"]["policyRef"] == "guardrail://fabric/default-safe-text-v1"
