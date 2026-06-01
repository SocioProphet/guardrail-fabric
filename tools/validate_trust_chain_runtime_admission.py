#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

try:
    import jsonschema
except Exception as exc:  # pragma: no cover
    print(f"dependency error: {exc}", file=sys.stderr)
    raise

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "sourceos.guardrail.decision.v0.1.schema.json"
ALLOW_FIXTURE = ROOT / "examples" / "trust-chain" / "runtime-asset-admission.allow.json"
DENY_FIXTURE = ROOT / "examples" / "trust-chain" / "runtime-asset-admission.deny.json"

REQUIRED_REFS = {
    "sbomRef",
    "vexRef",
    "lockfileRef",
    "signatureRef",
    "scanRecordRef",
    "policyProfileRef",
    "admissionDecisionRef",
}


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"fixture must be an object: {path}")
    return data


def validate_common(doc: dict[str, Any], schema: dict[str, Any], path: Path) -> None:
    jsonschema.validate(doc, schema)
    if doc.get("policyId") != "trust-chain/runtime-asset-admission":
        raise ValueError(f"{path}: policyId must be trust-chain/runtime-asset-admission")
    evidence = doc.get("evidence", {})
    if evidence.get("actionClass") != "runtime":
        raise ValueError(f"{path}: evidence.actionClass must be runtime")
    if evidence.get("artifactType") != "RuntimeAsset":
        raise ValueError(f"{path}: evidence.artifactType must be RuntimeAsset")


def validate_allow(doc: dict[str, Any], schema: dict[str, Any], path: Path) -> None:
    validate_common(doc, schema, path)
    if doc.get("decision") != "allow":
        raise ValueError(f"{path}: allow fixture must have decision=allow")
    evidence = doc["evidence"]
    missing = sorted(ref for ref in REQUIRED_REFS if not evidence.get(ref))
    if missing:
        raise ValueError(f"{path}: allow fixture missing refs: {missing}")
    required_posture = {
        "vulnerabilityPosture": "no_known_blocking_findings",
        "patchPosture": "current_for_scope",
        "sourceChannelTrust": "trusted",
    }
    for key, expected in required_posture.items():
        if evidence.get(key) != expected:
            raise ValueError(f"{path}: allow fixture requires {key}={expected}")
    effects = doc["effects"]
    if effects.get("agentMayContinue") is not True or effects.get("requiresHumanApproval") is not False:
        raise ValueError(f"{path}: allow fixture effects must permit continuation without human approval")


def validate_deny(doc: dict[str, Any], schema: dict[str, Any], path: Path) -> None:
    validate_common(doc, schema, path)
    if doc.get("decision") != "deny":
        raise ValueError(f"{path}: deny fixture must have decision=deny")
    evidence = doc["evidence"]
    if evidence.get("vulnerabilityPosture") != "known_blocking_findings":
        raise ValueError(f"{path}: deny fixture must record known blocking findings")
    if evidence.get("patchPosture") != "patch_required":
        raise ValueError(f"{path}: deny fixture must require patching")
    if evidence.get("promotionPosture") != "production_denied":
        raise ValueError(f"{path}: deny fixture must deny production promotion")
    effects = doc["effects"]
    if effects.get("agentMayContinue") is not False or effects.get("requiresHumanApproval") is not True:
        raise ValueError(f"{path}: deny fixture effects must stop agent continuation and require human approval")


def check(check_id: str, func, schema: dict[str, Any], path: Path) -> dict[str, Any]:
    try:
        func(load(path), schema, path)
        return {"check_id": check_id, "passed": True, "diagnostics": []}
    except Exception as exc:  # noqa: BLE001
        return {"check_id": check_id, "passed": False, "diagnostics": [str(exc)]}


def main() -> int:
    schema = load(SCHEMA)
    results = [
        check("allow-fixture", validate_allow, schema, ALLOW_FIXTURE),
        check("deny-fixture", validate_deny, schema, DENY_FIXTURE),
    ]
    passed = all(item["passed"] for item in results)
    print(json.dumps({"validator": "guardrail-fabric.trust-chain-runtime-admission.v0.1", "passed": passed, "results": results}, indent=2, sort_keys=True))
    print(("PASS" if passed else "FAIL") + ": trust-chain runtime admission fixtures")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
