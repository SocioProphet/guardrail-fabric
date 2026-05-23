"""Guardrail Fabric preflight handoff contract for AgentPlane admission.

The handoff keeps safety semantics owned by Guardrail Fabric while providing a
stable record that AgentPlane can consume as preflight input. It preserves the
TrustOps outcome, provider-neutral runtime action, gate ids, evidence refs, and
an explicit AgentPlane projection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .trustops_runtime_actions import (
    RuntimeGuardrailAction,
    TrustOpsGateDecision,
    TrustOpsMappingError,
    TrustOpsOutcome,
    map_trustops_to_runtime_action,
)

SCHEMA_VERSION = "guardrail-fabric.trustops-preflight-handoff.v0.1"
RECORD_TYPE = "TrustOpsPreflightHandoff"
SAFETY_OWNER = "SocioProphet/guardrail-fabric"
AGENTPLANE_CONSUMER = "SocioProphet/agentplane"


class TrustOpsPreflightHandoffError(ValueError):
    """Raised when a preflight handoff cannot be safely produced."""


@dataclass(frozen=True)
class TrustOpsPreflightHandoff:
    """AgentPlane-consumable handoff from Guardrail Fabric safety preflight."""

    handoff_id: str
    source_receipt_id: str
    outcome: TrustOpsOutcome
    runtime_action: RuntimeGuardrailAction
    gate_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    reason: str
    source_system: str = SAFETY_OWNER
    consumer_system: str = AGENTPLANE_CONSUMER
    fail_closed_reason: str | None = None

    def to_agentplane_projection(self) -> dict[str, str]:
        """Return the AgentPlane preflight fields this handoff licenses."""

        return {
            "outcome": self.outcome.value,
            "runtime_action": self.runtime_action.value,
            "authoritative_safety_owner": self.source_system,
            "handoff_ref": self.handoff_id,
        }

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schemaVersion": SCHEMA_VERSION,
            "recordType": RECORD_TYPE,
            "handoff_id": self.handoff_id,
            "source_system": self.source_system,
            "consumer_system": self.consumer_system,
            "source_receipt_id": self.source_receipt_id,
            "outcome": self.outcome.value,
            "runtime_action": self.runtime_action.value,
            "gate_ids": list(self.gate_ids),
            "evidence_refs": list(self.evidence_refs),
            "reason": self.reason,
            "agentplane_projection": self.to_agentplane_projection(),
        }
        if self.fail_closed_reason is not None:
            payload["fail_closed_reason"] = self.fail_closed_reason
        return payload


def build_preflight_handoff(
    decisions: Iterable[TrustOpsGateDecision | dict[str, Any]],
    *,
    handoff_id: str,
    source_receipt_id: str | None = None,
    rollback_supported: bool = True,
) -> TrustOpsPreflightHandoff:
    """Build a Guardrail Fabric-owned preflight handoff.

    The handoff uses the monotonic TrustOps runtime-action mapper. It therefore
    fails if a requested runtime action tries to lower severity, such as mapping
    rollback to warn.
    """

    try:
        runtime_decision = map_trustops_to_runtime_action(
            decisions,
            rollback_supported=rollback_supported,
        )
    except TrustOpsMappingError as exc:
        raise TrustOpsPreflightHandoffError(str(exc)) from exc

    if not runtime_decision.gate_ids:
        raise TrustOpsPreflightHandoffError("preflight handoff requires gate_ids")
    if not runtime_decision.evidence_refs:
        raise TrustOpsPreflightHandoffError("preflight handoff requires evidence_refs")

    return TrustOpsPreflightHandoff(
        handoff_id=handoff_id,
        source_receipt_id=source_receipt_id or runtime_decision.receipt_ids[0],
        outcome=runtime_decision.controlling_outcome,
        runtime_action=runtime_decision.action,
        gate_ids=runtime_decision.gate_ids,
        evidence_refs=runtime_decision.evidence_refs,
        reason=runtime_decision.reason,
        fail_closed_reason=runtime_decision.fallback_reason,
    )


def build_preflight_handoff_dict(
    decisions: Iterable[TrustOpsGateDecision | dict[str, Any]],
    *,
    handoff_id: str,
    source_receipt_id: str | None = None,
    rollback_supported: bool = True,
) -> dict[str, Any]:
    """Build and serialize a Guardrail Fabric preflight handoff."""

    return build_preflight_handoff(
        decisions,
        handoff_id=handoff_id,
        source_receipt_id=source_receipt_id,
        rollback_supported=rollback_supported,
    ).to_dict()
