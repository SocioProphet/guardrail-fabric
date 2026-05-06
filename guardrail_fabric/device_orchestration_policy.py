"""Deterministic policy skeleton for Sovereign Device Orchestration.

This module intentionally has no third-party dependencies. It is a bridge from
`SocioProphet/prophet-platform/specs/orchestration/orchestration_contract_fixture.py`
to the Guardrail Fabric policy pack requested in issue #18.

The evaluator accepts a small policy context dictionary and returns a decision
shape compatible with the orchestration receipt contract. The ABI adapter emits
`sourceos.guardrail.decision.v0.1` artifacts so the policy pack can run through
the existing Guardrail Fabric CLI and evidence logging path.
"""

from __future__ import annotations

from typing import Any, Mapping

from .decision import ActionClass, Decision, Evidence, PolicyDecision, Scope, Severity, stable_digest


ALLOWED_OUTCOMES = {
    "allowed",
    "denied",
    "requires_approval",
    "requires_local_only",
    "redacted",
    "degraded",
}

OBSERVE_CLASSES = {"observe", "explain", "search", "draft", "propose"}
LOW_RISK_CLASSES = {"low_risk_actuation"}
MEDIUM_RISK_CLASSES = {"medium_risk_actuation"}
HIGH_RISK_CLASSES = {"high_risk_actuation", "irreversible_action"}

HIGH_RISK_ACTION_TYPES = {
    "arm_alarm",
    "disarm_alarm",
    "unlock_door",
    "lock_door",
    "export_raw_video",
    "vehicle_control",
    "payment",
    "identity_token_use",
    "health_relevant_action",
    "os_mutation",
    "irreversible_delete",
}

RAW_CAMERA_ACTIONS = {"export_raw_video", "retain_raw_video", "share_raw_video"}


def evaluate_orchestration_action(context: Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate a vendor-neutral orchestration action context.

    Required context fields are intentionally minimal so SourceOS, AgentPlane,
    Sherlock, and UI fixtures can call this without importing the full runtime:

    - `subject_node_id`
    - `action_type`
    - `capability_class`
    - `adapter_health`
    - `approval_mode`
    - `policy_package`
    - `routine_id` and/or `event_id`, when known
    """

    action_type = str(context.get("action_type", "observe"))
    capability_class = str(context.get("capability_class", "observe"))
    adapter_health = str(context.get("adapter_health", "healthy"))
    approval_mode = str(context.get("approval_mode", "none"))
    subject_node_id = str(context.get("subject_node_id", "unknown"))

    reasons: list[str] = []
    outcome = "allowed"

    if adapter_health in {"degraded", "unavailable", "disabled"}:
        outcome = "degraded"
        reasons.append("Adapter is not healthy; action must remain observational or be retried after repair.")
    elif action_type in RAW_CAMERA_ACTIONS:
        outcome = "denied"
        reasons.append("Raw camera export or retention is denied by default in the first orchestration slice.")
    elif capability_class in HIGH_RISK_CLASSES or action_type in HIGH_RISK_ACTION_TYPES:
        if approval_mode in {"explicit_user_approval", "two_party_approval", "admin_approval"}:
            outcome = "requires_approval"
            reasons.append("High-risk orchestration action requires explicit approval before execution.")
        else:
            outcome = "denied"
            reasons.append("High-risk orchestration action lacked an acceptable approval mode.")
    elif capability_class in MEDIUM_RISK_CLASSES:
        outcome = "requires_approval"
        reasons.append("Medium-risk orchestration action requires approval in the bootstrap policy pack.")
    elif capability_class in LOW_RISK_CLASSES:
        outcome = "allowed"
        reasons.append("Low-risk actuation is allowed when target node and adapter state are valid.")
    elif capability_class in OBSERVE_CLASSES:
        outcome = "allowed"
        reasons.append("Observation, explanation, search, draft, and proposal actions are allowed.")
    else:
        outcome = "denied"
        reasons.append("Unknown capability class denied fail-closed.")

    decision_id = str(context.get("decision_id") or f"decision:device-orchestration:{action_type}:{outcome}")

    decision = {
        "decision_id": decision_id,
        "outcome": outcome,
        "evaluated_at": str(context.get("evaluated_at", "1970-01-01T00:00:00Z")),
        "actor_id": str(context.get("actor_id", "adapter:guardrail-fabric")),
        "subject_node_id": subject_node_id,
        "event_id": str(context.get("event_id", "event:unknown")),
        "capability_class": capability_class,
        "policy_package": str(context.get("policy_package", "guardrail-fabric/device-orchestration@0.1")),
        "reasons": reasons,
    }

    if context.get("routine_id"):
        decision["routine_id"] = str(context["routine_id"])

    assert decision["outcome"] in ALLOWED_OUTCOMES
    return decision


def sourceos_decision_from_orchestration_context(context: Mapping[str, Any]) -> PolicyDecision:
    """Convert an orchestration policy decision into the Guardrail Fabric ABI."""

    orchestration = evaluate_orchestration_action(context)
    outcome = orchestration["outcome"]

    decision_map = {
        "allowed": Decision.ALLOW,
        "denied": Decision.DENY,
        "requires_approval": Decision.ESCALATE,
        "requires_local_only": Decision.INSTRUCT,
        "redacted": Decision.REDACT,
        "degraded": Decision.DEFER,
    }
    severity_map = {
        "allowed": Severity.INFO,
        "denied": Severity.HIGH,
        "requires_approval": Severity.HIGH,
        "requires_local_only": Severity.MEDIUM,
        "redacted": Severity.MEDIUM,
        "degraded": Severity.MEDIUM,
    }
    remediation_map = {
        "allowed": "Continue and emit an orchestration evidence receipt.",
        "denied": "Do not execute the action. Preserve the denied proposal and policy reasons as evidence.",
        "requires_approval": "Pause execution and request explicit scoped approval before actuation.",
        "requires_local_only": "Keep the action local-only and do not use a remote/cloud adapter path.",
        "redacted": "Suppress sensitive content and emit a redacted evidence receipt.",
        "degraded": "Do not actuate. Repair or recheck adapter health, then replay through policy.",
    }

    evidence = Evidence(
        repo=str(context.get("repo")) if context.get("repo") else None,
        branch=str(context.get("branch")) if context.get("branch") else None,
        commit=str(context.get("commit")) if context.get("commit") else None,
        cwd=str(context.get("cwd")) if context.get("cwd") else None,
        tool="DeviceOrchestration",
        actionClass=ActionClass.RUNTIME,
        inputDigest=stable_digest(dict(context)),
        sessionId=str(context.get("session_id")) if context.get("session_id") else None,
        agentId=str(context.get("agent_id")) if context.get("agent_id") else None,
        taskId=str(context.get("task_id")) if context.get("task_id") else None,
    )

    return PolicyDecision.create(
        policy_id=str(orchestration["policy_package"]),
        decision=decision_map[outcome],
        severity=severity_map[outcome],
        scope=Scope.RUNTIME,
        reason="; ".join(orchestration["reasons"]),
        remediation=remediation_map[outcome],
        evidence=evidence,
    )


__all__ = [
    "ALLOWED_OUTCOMES",
    "evaluate_orchestration_action",
    "sourceos_decision_from_orchestration_context",
]
