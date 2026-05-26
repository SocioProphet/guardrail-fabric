"""TrustOps receipt outcome to runtime guardrail action mapping.

This module is intentionally provider-neutral. It translates TrustOps gate
decisions into runtime guardrail actions without depending on ART, AIF360,
AIX360, model-provider SDKs, or adapter-specific severity vocabularies.

Core invariant: evidence and gate outcomes are monotonic. A provider adapter may
add implementation detail, but it may not lower a TrustOps severity. In
particular, deny-like states outrank warning-like states; rollback never
silently degrades to warn; and quarantine preserves the evidence refs and gate
ids that caused it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

SAFETY_OWNER = "SocioProphet/guardrail-fabric"
AGENT_REGISTRY_OWNER = "SocioProphet/agent-registry"
SCHEMA_VERSION = "guardrail-fabric.trustops-guardrail-action-decision.v0.1"
RECORD_TYPE = "TrustOpsGuardrailActionDecision"


class TrustOpsOutcome(str, Enum):
    """Canonical TrustOps receipt outcomes ordered by runtime severity."""

    PASS = "pass"
    WARN = "warn"
    REQUIRE_REVIEW = "require-review"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    ROLLBACK = "rollback"
    REVOKE = "revoke"


class RuntimeGuardrailAction(str, Enum):
    """Provider-neutral runtime action emitted from TrustOps outcomes."""

    ALLOW = "allow"
    WARN = "warn"
    REQUIRE_REVIEW = "require-review"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    ROLLBACK = "rollback"
    REVOKE = "revoke"


OUTCOME_PRECEDENCE: dict[TrustOpsOutcome, int] = {
    TrustOpsOutcome.PASS: 0,
    TrustOpsOutcome.WARN: 10,
    TrustOpsOutcome.REQUIRE_REVIEW: 20,
    TrustOpsOutcome.QUARANTINE: 30,
    TrustOpsOutcome.BLOCK: 40,
    TrustOpsOutcome.ROLLBACK: 50,
    TrustOpsOutcome.REVOKE: 60,
}
"""Monotonic TrustOps severity order. Higher number means safer/stricter."""

ACTION_PRECEDENCE: dict[RuntimeGuardrailAction, int] = {
    RuntimeGuardrailAction.ALLOW: 0,
    RuntimeGuardrailAction.WARN: 10,
    RuntimeGuardrailAction.REQUIRE_REVIEW: 20,
    RuntimeGuardrailAction.QUARANTINE: 30,
    RuntimeGuardrailAction.BLOCK: 40,
    RuntimeGuardrailAction.ROLLBACK: 50,
    RuntimeGuardrailAction.REVOKE: 60,
}
"""Runtime action severity order. Adapters may not lower this order."""

DEFAULT_ACTION_FOR_OUTCOME: dict[TrustOpsOutcome, RuntimeGuardrailAction] = {
    TrustOpsOutcome.PASS: RuntimeGuardrailAction.ALLOW,
    TrustOpsOutcome.WARN: RuntimeGuardrailAction.WARN,
    TrustOpsOutcome.REQUIRE_REVIEW: RuntimeGuardrailAction.REQUIRE_REVIEW,
    TrustOpsOutcome.QUARANTINE: RuntimeGuardrailAction.QUARANTINE,
    TrustOpsOutcome.BLOCK: RuntimeGuardrailAction.BLOCK,
    TrustOpsOutcome.ROLLBACK: RuntimeGuardrailAction.ROLLBACK,
    TrustOpsOutcome.REVOKE: RuntimeGuardrailAction.REVOKE,
}


def downstream_authority_intent(action: RuntimeGuardrailAction) -> str:
    """Return the authority intent without mutating authority state."""

    return {
        RuntimeGuardrailAction.ALLOW: "none",
        RuntimeGuardrailAction.WARN: "none",
        RuntimeGuardrailAction.REQUIRE_REVIEW: "requires-agent-registry-decision",
        RuntimeGuardrailAction.QUARANTINE: "requires-agent-registry-decision",
        RuntimeGuardrailAction.BLOCK: "requires-agent-registry-decision",
        RuntimeGuardrailAction.ROLLBACK: "requires-agent-registry-decision",
        RuntimeGuardrailAction.REVOKE: "requires-agent-registry-decision",
    }[action]


class TrustOpsMappingError(ValueError):
    """Raised when a TrustOps decision cannot be safely mapped."""


@dataclass(frozen=True)
class TrustOpsGateDecision:
    """One TrustOps receipt/gate outcome to be mapped into runtime action.

    Parameters
    ----------
    outcome:
        TrustOps receipt outcome.
    receipt_id:
        Stable TrustOps receipt identifier. Required for audit replay.
    gate_id:
        Stable policy gate identifier. Required for deterministic mapping.
    evidence_refs:
        Exact evidence references that justify the gate outcome.
    provider_id:
        Optional adapter/provider identifier. Informational only; providers do
        not control the monotonic mapping.
    runtime_action_override:
        Optional adapter/requested runtime action. It is accepted only when it
        is at least as strict as the TrustOps outcome severity.
    """

    outcome: TrustOpsOutcome
    receipt_id: str
    gate_id: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    provider_id: str | None = None
    runtime_action_override: RuntimeGuardrailAction | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TrustOpsGateDecision":
        """Build a decision from a plain JSON-like dictionary."""

        return cls(
            outcome=_coerce_outcome(payload.get("outcome")),
            receipt_id=_require_string(payload, "receipt_id"),
            gate_id=_require_string(payload, "gate_id"),
            evidence_refs=tuple(str(item) for item in payload.get("evidence_refs", ())),
            provider_id=payload.get("provider_id"),
            runtime_action_override=(
                _coerce_action(payload["runtime_action_override"])
                if payload.get("runtime_action_override") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class RuntimeGuardrailDecision:
    """Provider-neutral runtime decision derived from TrustOps evidence."""

    action: RuntimeGuardrailAction
    controlling_outcome: TrustOpsOutcome
    receipt_ids: tuple[str, ...]
    gate_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    reason: str
    fallback_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a stable JSON-serializable representation."""

        data: dict[str, Any] = {
            "action": self.action.value,
            "controlling_outcome": self.controlling_outcome.value,
            "receipt_ids": list(self.receipt_ids),
            "gate_ids": list(self.gate_ids),
            "evidence_refs": list(self.evidence_refs),
            "reason": self.reason,
        }
        if self.fallback_reason is not None:
            data["fallback_reason"] = self.fallback_reason
        return data


@dataclass(frozen=True)
class TrustOpsGuardrailActionDecision:
    """Guardrail Fabric-owned runtime control decision record.

    This record is a runtime-control decision, not an Agent Registry authority
    mutation. If authority should change, the record exposes downstream intent
    and evidence refs for Agent Registry to evaluate separately.
    """

    decision_id: str
    runtime_decision: RuntimeGuardrailDecision
    issued_at: str
    policy_refs: tuple[str, ...]
    source_system: str = SAFETY_OWNER
    authority_plane: str = AGENT_REGISTRY_OWNER

    def to_agentplane_projection(self) -> dict[str, str]:
        return {
            "outcome": self.runtime_decision.controlling_outcome.value,
            "runtime_action": self.runtime_decision.action.value,
            "authoritative_safety_owner": self.source_system,
            "guardrail_action_ref": self.decision_id,
        }

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schemaVersion": SCHEMA_VERSION,
            "recordType": RECORD_TYPE,
            "decision_id": self.decision_id,
            "source_system": self.source_system,
            "controlling_outcome": self.runtime_decision.controlling_outcome.value,
            "runtime_action": self.runtime_decision.action.value,
            "receipt_ids": list(self.runtime_decision.receipt_ids),
            "gate_ids": list(self.runtime_decision.gate_ids),
            "evidence_refs": list(self.runtime_decision.evidence_refs),
            "policy_refs": list(self.policy_refs),
            "reason": self.runtime_decision.reason,
            "issued_at": self.issued_at,
            "authority_mutation": {
                "performed": False,
                "authority_plane": self.authority_plane,
                "downstream_intent": downstream_authority_intent(self.runtime_decision.action),
            },
            "agentplane_projection": self.to_agentplane_projection(),
        }
        if self.runtime_decision.fallback_reason is not None:
            data["fallback_reason"] = self.runtime_decision.fallback_reason
        return data


def map_trustops_to_runtime_action(
    decisions: Iterable[TrustOpsGateDecision | dict[str, Any]],
    *,
    rollback_supported: bool = True,
) -> RuntimeGuardrailDecision:
    """Translate TrustOps gate decisions into one monotonic runtime action.

    If multiple gate decisions are present, the highest-precedence outcome wins.
    Deny-like outcomes therefore always outrank warning-like outcomes. If a
    rollback outcome is emitted in a runtime that cannot rollback, the action
    escalates to ``block`` with ``fallback_reason='rollback_unsupported'``.
    It never degrades to ``warn``.
    """

    normalized = tuple(_normalize_decision(item) for item in decisions)
    if not normalized:
        raise TrustOpsMappingError("at least one TrustOps gate decision is required")

    for decision in normalized:
        _validate_decision(decision)

    controlling = max(
        normalized,
        key=lambda item: OUTCOME_PRECEDENCE[item.outcome],
    )
    action = DEFAULT_ACTION_FOR_OUTCOME[controlling.outcome]
    fallback_reason: str | None = None

    if controlling.runtime_action_override is not None:
        override = controlling.runtime_action_override
        if ACTION_PRECEDENCE[override] < OUTCOME_PRECEDENCE[controlling.outcome]:
            raise TrustOpsMappingError(
                "runtime_action_override cannot lower TrustOps outcome severity: "
                f"{controlling.outcome.value} -> {override.value}"
            )
        action = override

    if controlling.outcome is TrustOpsOutcome.ROLLBACK and not rollback_supported:
        action = RuntimeGuardrailAction.BLOCK
        fallback_reason = "rollback_unsupported"

    return RuntimeGuardrailDecision(
        action=action,
        controlling_outcome=controlling.outcome,
        receipt_ids=_ordered_unique(item.receipt_id for item in normalized),
        gate_ids=_ordered_unique(item.gate_id for item in normalized),
        evidence_refs=_ordered_unique(
            evidence_ref
            for item in normalized
            for evidence_ref in item.evidence_refs
        ),
        reason=(
            "Mapped TrustOps outcome "
            f"'{controlling.outcome.value}' to runtime action '{action.value}' "
            "using the monotonic provider-neutral translation table."
        ),
        fallback_reason=fallback_reason,
    )


def build_guardrail_action_decision(
    decisions: Iterable[TrustOpsGateDecision | dict[str, Any]],
    *,
    decision_id: str,
    issued_at: str,
    policy_refs: Iterable[str],
    rollback_supported: bool = True,
) -> TrustOpsGuardrailActionDecision:
    """Build a Guardrail Fabric-owned runtime-control decision record."""

    runtime_decision = map_trustops_to_runtime_action(
        decisions,
        rollback_supported=rollback_supported,
    )
    policy_tuple = tuple(policy_refs)
    if not decision_id:
        raise TrustOpsMappingError("decision_id is required")
    if not issued_at:
        raise TrustOpsMappingError("issued_at is required")
    if not policy_tuple:
        raise TrustOpsMappingError("policy_refs are required")
    if not runtime_decision.gate_ids:
        raise TrustOpsMappingError("guardrail action decision requires gate_ids")
    if not runtime_decision.evidence_refs:
        raise TrustOpsMappingError("guardrail action decision requires evidence_refs")
    return TrustOpsGuardrailActionDecision(
        decision_id=decision_id,
        runtime_decision=runtime_decision,
        issued_at=issued_at,
        policy_refs=policy_tuple,
    )


def build_guardrail_action_decision_dict(
    decisions: Iterable[TrustOpsGateDecision | dict[str, Any]],
    *,
    decision_id: str,
    issued_at: str,
    policy_refs: Iterable[str],
    rollback_supported: bool = True,
) -> dict[str, Any]:
    """Build and serialize a Guardrail Fabric runtime-control decision."""

    return build_guardrail_action_decision(
        decisions,
        decision_id=decision_id,
        issued_at=issued_at,
        policy_refs=policy_refs,
        rollback_supported=rollback_supported,
    ).to_dict()


def _normalize_decision(
    item: TrustOpsGateDecision | dict[str, Any],
) -> TrustOpsGateDecision:
    if isinstance(item, TrustOpsGateDecision):
        return item
    if isinstance(item, dict):
        return TrustOpsGateDecision.from_dict(item)
    raise TrustOpsMappingError(f"unsupported TrustOps decision type: {type(item)!r}")


def _validate_decision(decision: TrustOpsGateDecision) -> None:
    if not decision.receipt_id:
        raise TrustOpsMappingError("receipt_id is required")
    if not decision.gate_id:
        raise TrustOpsMappingError("gate_id is required")
    if decision.outcome is TrustOpsOutcome.QUARANTINE and not decision.evidence_refs:
        raise TrustOpsMappingError(
            "quarantine requires exact evidence_refs and gate_id preservation"
        )
    if decision.runtime_action_override is not None:
        override = decision.runtime_action_override
        if ACTION_PRECEDENCE[override] < OUTCOME_PRECEDENCE[decision.outcome]:
            raise TrustOpsMappingError(
                "runtime_action_override cannot lower TrustOps outcome severity: "
                f"{decision.outcome.value} -> {override.value}"
            )


def _coerce_outcome(value: Any) -> TrustOpsOutcome:
    try:
        return TrustOpsOutcome(str(value))
    except ValueError as exc:
        raise TrustOpsMappingError(f"unknown TrustOps outcome: {value!r}") from exc


def _coerce_action(value: Any) -> RuntimeGuardrailAction:
    try:
        return RuntimeGuardrailAction(str(value))
    except ValueError as exc:
        raise TrustOpsMappingError(f"unknown runtime guardrail action: {value!r}") from exc


def _require_string(payload: dict[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise TrustOpsMappingError(f"{field_name} must be a non-empty string")
    return value


def _ordered_unique(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return tuple(ordered)
