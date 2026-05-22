"""Tests for TrustOps outcome to runtime guardrail action mapping."""

from __future__ import annotations

import pytest

from guardrail_fabric.trustops_runtime_actions import (
    RuntimeGuardrailAction,
    TrustOpsGateDecision,
    TrustOpsMappingError,
    TrustOpsOutcome,
    map_trustops_to_runtime_action,
)


def test_warn_beats_pass() -> None:
    decision = map_trustops_to_runtime_action(
        [
            TrustOpsGateDecision(
                outcome=TrustOpsOutcome.PASS,
                receipt_id="trustops-receipt:pass-001",
                gate_id="gate:smoke",
                evidence_refs=("evidence:smoke",),
            ),
            TrustOpsGateDecision(
                outcome=TrustOpsOutcome.WARN,
                receipt_id="trustops-receipt:warn-001",
                gate_id="gate:uncertainty",
                evidence_refs=("evidence:uncertainty",),
            ),
        ]
    )

    assert decision.action == RuntimeGuardrailAction.WARN
    assert decision.controlling_outcome == TrustOpsOutcome.WARN
    assert decision.receipt_ids == (
        "trustops-receipt:pass-001",
        "trustops-receipt:warn-001",
    )


def test_deny_like_state_beats_warning_like_state() -> None:
    decision = map_trustops_to_runtime_action(
        [
            {
                "outcome": "warn",
                "receipt_id": "trustops-receipt:warn-001",
                "gate_id": "gate:uncertainty",
                "evidence_refs": ["evidence:uncertainty"],
            },
            {
                "outcome": "block",
                "receipt_id": "trustops-receipt:block-001",
                "gate_id": "gate:privacy-leakage",
                "evidence_refs": ["evidence:privacy-leakage"],
            },
        ]
    )

    assert decision.action == RuntimeGuardrailAction.BLOCK
    assert decision.controlling_outcome == TrustOpsOutcome.BLOCK


def test_rollback_never_degrades_to_warn_when_unsupported() -> None:
    decision = map_trustops_to_runtime_action(
        [
            TrustOpsGateDecision(
                outcome=TrustOpsOutcome.ROLLBACK,
                receipt_id="trustops-receipt:rollback-001",
                gate_id="gate:model-regression",
                evidence_refs=("evidence:model-regression",),
            )
        ],
        rollback_supported=False,
    )

    assert decision.action == RuntimeGuardrailAction.BLOCK
    assert decision.action != RuntimeGuardrailAction.WARN
    assert decision.fallback_reason == "rollback_unsupported"


def test_quarantine_preserves_gate_and_evidence_refs() -> None:
    decision = map_trustops_to_runtime_action(
        [
            TrustOpsGateDecision(
                outcome=TrustOpsOutcome.QUARANTINE,
                receipt_id="trustops-receipt:quarantine-001",
                gate_id="gate:rag-poisoning",
                evidence_refs=(
                    "evidence:rag-poisoning:receipt",
                    "evidence:rag-poisoning:trace",
                ),
            )
        ]
    )

    assert decision.action == RuntimeGuardrailAction.QUARANTINE
    assert decision.gate_ids == ("gate:rag-poisoning",)
    assert decision.evidence_refs == (
        "evidence:rag-poisoning:receipt",
        "evidence:rag-poisoning:trace",
    )


def test_quarantine_requires_exact_evidence_refs() -> None:
    with pytest.raises(TrustOpsMappingError, match="quarantine requires exact evidence_refs"):
        map_trustops_to_runtime_action(
            [
                TrustOpsGateDecision(
                    outcome=TrustOpsOutcome.QUARANTINE,
                    receipt_id="trustops-receipt:quarantine-001",
                    gate_id="gate:rag-poisoning",
                    evidence_refs=(),
                )
            ]
        )


def test_provider_override_cannot_lower_severity() -> None:
    with pytest.raises(TrustOpsMappingError, match="cannot lower TrustOps outcome severity"):
        map_trustops_to_runtime_action(
            [
                TrustOpsGateDecision(
                    outcome=TrustOpsOutcome.ROLLBACK,
                    receipt_id="trustops-receipt:rollback-001",
                    gate_id="gate:model-regression",
                    evidence_refs=("evidence:model-regression",),
                    provider_id="provider:adapter-a",
                    runtime_action_override=RuntimeGuardrailAction.WARN,
                )
            ]
        )


def test_provider_override_may_escalate_severity() -> None:
    decision = map_trustops_to_runtime_action(
        [
            TrustOpsGateDecision(
                outcome=TrustOpsOutcome.REQUIRE_REVIEW,
                receipt_id="trustops-receipt:review-001",
                gate_id="gate:human-review",
                evidence_refs=("evidence:human-review",),
                provider_id="provider:adapter-a",
                runtime_action_override=RuntimeGuardrailAction.BLOCK,
            )
        ]
    )

    assert decision.action == RuntimeGuardrailAction.BLOCK
    assert decision.controlling_outcome == TrustOpsOutcome.REQUIRE_REVIEW


def test_to_dict_is_provider_neutral_and_serializable() -> None:
    decision = map_trustops_to_runtime_action(
        [
            TrustOpsGateDecision(
                outcome=TrustOpsOutcome.REVOKE,
                receipt_id="trustops-receipt:revoke-001",
                gate_id="gate:tool-abuse",
                evidence_refs=("evidence:tool-abuse",),
                provider_id="provider:adapter-a",
            )
        ]
    )
    payload = decision.to_dict()

    assert payload["action"] == "revoke"
    assert payload["controlling_outcome"] == "revoke"
    assert payload["receipt_ids"] == ["trustops-receipt:revoke-001"]
    assert payload["gate_ids"] == ["gate:tool-abuse"]
    assert payload["evidence_refs"] == ["evidence:tool-abuse"]
