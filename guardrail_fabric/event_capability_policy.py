"""Policy generation for event-capability records.

This module converts event-capability records into policy-grounded reactions.
It is the Guardrail Fabric side of the event-native orchestration loop:

  event -> capability -> policy decision -> reaction -> receipt refs -> queue/admission

The functions are deterministic and dependency-free so SourceOS, AgentPlane,
and Sherlock can use the same fixture shape during bootstrap.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from .device_orchestration_policy import evaluate_orchestration_action


DEFAULT_POLICY_PACKAGE = "guardrail-fabric/device-orchestration@0.1"


def context_from_event_capability_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Build the device-orchestration policy context from one event-capability record."""

    event = record.get("event") if isinstance(record.get("event"), Mapping) else {}
    capability = record.get("capability") if isinstance(record.get("capability"), Mapping) else {}
    payload = event.get("payload") if isinstance(event.get("payload"), Mapping) else {}

    action_type = payload.get("requested_action") or capability.get("action_type") or capability.get("capability_id") or "observe"
    adapter_health = payload.get("adapter_health") or capability.get("adapter_health") or "healthy"
    approval_token_present = bool(payload.get("approval_token_present"))
    approval_mode = str(capability.get("approval_mode", "none"))

    if capability.get("effect_class") in {"high_risk_actuation", "irreversible_action"} and approval_token_present:
        approval_mode = approval_mode if approval_mode != "none" else "explicit_user_approval"

    return {
        "decision_id": "decision:event-capability:" + str(record.get("record_id", "unknown")).replace("record:", ""),
        "event_id": str(event.get("event_id", "event:unknown")),
        "subject_node_id": str(event.get("target_node_id", "unknown")),
        "actor_id": "adapter:guardrail-fabric",
        "action_type": str(action_type),
        "capability_class": str(capability.get("effect_class", "observe")),
        "adapter_health": str(adapter_health),
        "approval_mode": approval_mode,
        "policy_package": str(capability.get("policy_package", DEFAULT_POLICY_PACKAGE)),
        "routine_id": str(payload.get("routine_id")) if payload.get("routine_id") else None,
    }


def evaluate_event_capability_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a PolicyDecision-shaped dict for an event-capability record."""

    return evaluate_orchestration_action(context_from_event_capability_record(record))


def annotate_event_capability_record(record: Mapping[str, Any]) -> dict[str, Any]:
    """Attach generated policy output to an event-capability record.

    The returned record is suitable for SourceOS queueing and AgentPlane
    admission. Existing event/capability data is preserved; reaction outcome is
    regenerated from Guardrail Fabric policy.
    """

    output = deepcopy(dict(record))
    decision = evaluate_event_capability_record(output)
    reaction = output.get("reaction") if isinstance(output.get("reaction"), dict) else {}
    capability = output.get("capability") if isinstance(output.get("capability"), dict) else {}

    reaction["policy_outcome"] = decision["outcome"]
    reaction["status"] = "scheduled" if decision["outcome"] in {"allowed", "redacted"} else "blocked_or_waiting"
    reaction["dead_letter_on_failure"] = True
    reaction.setdefault("receipt_refs", [])
    output["reaction"] = reaction
    output["policy_decision"] = decision
    output["evidence_refs"] = sorted(set((output.get("evidence_refs") or []) + reaction.get("receipt_refs", [])))

    # Keep the capability contract aligned with the policy-generated outcome for
    # bootstrap records. Live policies may later split required vs observed outcome.
    if capability:
        capability["required_policy_outcome"] = decision["outcome"]
        output["capability"] = capability

    return output


def annotate_event_capability_records(records: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [annotate_event_capability_record(record) for record in records]


__all__ = [
    "annotate_event_capability_record",
    "annotate_event_capability_records",
    "context_from_event_capability_record",
    "evaluate_event_capability_record",
]
