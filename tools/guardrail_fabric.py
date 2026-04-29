#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "examples" / "guardrail-policy.example.json"
INPUT_PATH = ROOT / "examples" / "guardrail-input.example.json"

DENY_SIGNALS = {"secrets", "jailbreak", "tool-override", "policy-bypass"}
REVIEW_SIGNALS = {"pii", "private-user-data"}
MASK_SIGNALS = {"pii", "private-user-data"}
REDACT_SIGNALS = {"secrets"}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate(policy: dict[str, Any], guardrail_input: dict[str, Any]) -> dict[str, Any]:
    spec = guardrail_input["spec"]
    signals = set(spec.get("detectedSignals", []))
    reason_codes: list[str] = []
    redaction_hints: list[str] = []
    masking_hints: list[str] = []

    policy_ref = policy["metadata"]["policyRef"]
    if spec["policyRef"] != policy_ref:
        return build_decision(guardrail_input, "requires-review", ["policy-ref-mismatch"], [], [])

    covered_surfaces = set(policy["spec"].get("surfaceRefs", []))
    if spec["surfaceRef"] not in covered_surfaces:
        return build_decision(guardrail_input, "requires-review", ["surface-not-covered"], [], [])
    reason_codes.append("surface-covered")

    deny_hits = sorted(signals & DENY_SIGNALS)
    if deny_hits:
        if "secrets" in deny_hits and policy["spec"]["outputPolicy"].get("redactDetectedSecrets"):
            redaction_hints.append("redact-detected-secrets")
        return build_decision(guardrail_input, "deny", ["deny-signal-detected", *deny_hits], redaction_hints, masking_hints)

    review_hits = sorted(signals & REVIEW_SIGNALS)
    if review_hits:
        if policy["spec"]["outputPolicy"].get("maskDetectedPii"):
            masking_hints.extend(f"mask-{signal}" for signal in review_hits if signal in MASK_SIGNALS)
        return build_decision(guardrail_input, "requires-review", ["review-signal-detected", *review_hits], redaction_hints, masking_hints)

    reason_codes.append("no-deny-signals")
    if "citation-required" in signals:
        reason_codes.append("citation-required")
    if policy["spec"]["outputPolicy"].get("requireEvidenceRef") and spec.get("evidenceRef"):
        reason_codes.append("evidence-ref-present")
    return build_decision(guardrail_input, "allow", reason_codes, redaction_hints, masking_hints)


def build_decision(
    guardrail_input: dict[str, Any],
    status: str,
    reason_codes: list[str],
    redaction_hints: list[str],
    masking_hints: list[str],
) -> dict[str, Any]:
    metadata = guardrail_input["metadata"]
    spec = guardrail_input["spec"]
    return {
        "apiVersion": "guardrail.socioprophet.dev/v1",
        "kind": "GuardrailDecision",
        "metadata": {
            "decisionId": f"guardrail-decision-{metadata['inputId']}",
            "inputId": metadata["inputId"],
            "createdAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        },
        "spec": {
            "decisionStatus": status,
            "policyRef": spec["policyRef"],
            "surfaceRef": spec["surfaceRef"],
            "reasonCodes": reason_codes,
            "redactionHints": redaction_hints,
            "maskingHints": masking_hints,
            "evidenceRef": spec["evidenceRef"],
            "ledgerRef": f"ledger://model-governance/demo/{metadata['inputId']}",
        },
    }


def emit_demo(output_path: Path | None = None) -> int:
    decision = evaluate(load_json(POLICY_PATH), load_json(INPUT_PATH))
    payload = json.dumps(decision, indent=2, sort_keys=True) + "\n"
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SocioProphet deterministic guardrail fabric")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("emit-demo-decision")
    demo.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.command == "emit-demo-decision":
        return emit_demo(args.output)
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
