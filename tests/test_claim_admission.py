"""Tests for the claim/action admission policy contracts.

These are deterministic fixture tests that validate every admission decision
state (allow, deny, require_review, provisional) for all canonical claim
and action classes.
"""

from __future__ import annotations

import pytest

from guardrail_fabric import (
    AdmissionActionClass,
    AdmissionDecision,
    CandidateSource,
    ClaimAdmissionPolicy,
    ClaimClass,
    ActionAdmissionPolicy,
    Decision,
    EvidenceSufficiencyRule,
    ProvisionalAdmission,
    ReviewGate,
    Revocation,
    default_action_policies,
    default_claim_policies,
    default_evidence_rules,
)


# ---------------------------------------------------------------------------
# AdmissionDecision mapping
# ---------------------------------------------------------------------------


def test_admission_decision_maps_to_allow() -> None:
    assert AdmissionDecision.ALLOW.to_policy_decision() == Decision.ALLOW


def test_admission_decision_maps_to_deny() -> None:
    assert AdmissionDecision.DENY.to_policy_decision() == Decision.DENY


def test_admission_decision_maps_to_require_review() -> None:
    assert AdmissionDecision.REQUIRE_REVIEW.to_policy_decision() == Decision.ESCALATE


def test_admission_decision_maps_to_provisional() -> None:
    assert AdmissionDecision.PROVISIONAL.to_policy_decision() == Decision.ALLOW_WITH_CONTEXT


# ---------------------------------------------------------------------------
# Default evidence rules
# ---------------------------------------------------------------------------


def test_default_evidence_rules_covers_all_claim_classes() -> None:
    rules = default_evidence_rules()
    for claim_class in ClaimClass:
        assert claim_class in rules, f"Missing evidence rule for {claim_class}"


def test_world_gaia_requires_human_verification() -> None:
    rules = default_evidence_rules()
    assert rules[ClaimClass.WORLD_GAIA].requires_human_verification is True


def test_technical_document_does_not_require_human_verification() -> None:
    rules = default_evidence_rules()
    assert rules[ClaimClass.TECHNICAL_DOCUMENT].requires_human_verification is False


def test_explainable_text_classification_does_not_require_citation() -> None:
    rules = default_evidence_rules()
    assert rules[ClaimClass.EXPLAINABLE_TEXT_CLASSIFICATION].requires_citation is False


def test_runtime_action_requires_explanation_trace_and_human_verification() -> None:
    rules = default_evidence_rules()
    rule = rules[ClaimClass.RUNTIME_ACTION]
    assert rule.requires_explanation_trace is True
    assert rule.requires_human_verification is True


# ---------------------------------------------------------------------------
# Raw candidate source invariants (deny)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "candidate_source",
    [
        CandidateSource.MODEL_OUTPUT,
        CandidateSource.GRAPH_CANDIDATE,
        CandidateSource.VECTOR_CANDIDATE,
    ],
)
def test_raw_candidate_source_is_denied(candidate_source: CandidateSource) -> None:
    """Invariant: raw model/graph/vector candidates are never admitted truth."""
    policies = default_claim_policies()
    policy = policies[ClaimClass.TECHNICAL_DOCUMENT]
    result = policy.evaluate(
        claim_id="claim-raw-001",
        candidate_source=candidate_source,
        has_explanation_trace=True,
        has_citation=True,
        source_trust="high",
    )
    assert result.decision == Decision.DENY
    assert candidate_source.value.replace("_", " ") in result.reason or candidate_source.value in result.reason


# ---------------------------------------------------------------------------
# Technical document claim — all four decision states
# ---------------------------------------------------------------------------


def test_technical_document_deny_missing_explanation_trace() -> None:
    policy = default_claim_policies()[ClaimClass.TECHNICAL_DOCUMENT]
    result = policy.evaluate(
        claim_id="td-001",
        candidate_source=CandidateSource.VERIFIED_CITATION,
        has_explanation_trace=False,
        has_citation=True,
        source_trust="medium",
    )
    assert result.decision == Decision.DENY
    assert "explanation trace" in result.reason


def test_technical_document_deny_missing_citation() -> None:
    policy = default_claim_policies()[ClaimClass.TECHNICAL_DOCUMENT]
    result = policy.evaluate(
        claim_id="td-002",
        candidate_source=CandidateSource.HUMAN_AUTHORED,
        has_explanation_trace=True,
        has_citation=False,
        source_trust="medium",
    )
    assert result.decision == Decision.DENY
    assert "citation" in result.reason


def test_technical_document_provisional_below_minimum_trust() -> None:
    """Provisional: all evidence present but source trust is below minimum."""
    policy = default_claim_policies()[ClaimClass.TECHNICAL_DOCUMENT]
    result = policy.evaluate(
        claim_id="td-003",
        candidate_source=CandidateSource.EXPLAINABLE_TRACE,
        has_explanation_trace=True,
        has_citation=True,
        source_trust="low",
    )
    assert result.decision == Decision.ALLOW_WITH_CONTEXT
    assert result.effects.agentMayContinue is True
    assert "provisional" in result.reason.lower()


def test_technical_document_allow_all_evidence_met() -> None:
    """Allow: all evidence requirements met and no blocking review gates."""
    policy = default_claim_policies()[ClaimClass.TECHNICAL_DOCUMENT]
    result = policy.evaluate(
        claim_id="td-004",
        candidate_source=CandidateSource.VERIFIED_CITATION,
        has_explanation_trace=True,
        has_citation=True,
        source_trust="medium",
    )
    assert result.decision == Decision.ALLOW
    assert result.effects.agentMayContinue is True


# ---------------------------------------------------------------------------
# World/GAIA claim — require_review gate always fires
# ---------------------------------------------------------------------------


def test_world_gaia_deny_missing_explanation_trace() -> None:
    policy = default_claim_policies()[ClaimClass.WORLD_GAIA]
    result = policy.evaluate(
        claim_id="gaia-001",
        candidate_source=CandidateSource.VERIFIED_CITATION,
        has_explanation_trace=False,
        has_citation=True,
        human_verified=True,
        source_trust="high",
    )
    assert result.decision == Decision.DENY


def test_world_gaia_require_review_human_verification_missing() -> None:
    """require_review: explanation trace present but human_verified=False."""
    policy = default_claim_policies()[ClaimClass.WORLD_GAIA]
    result = policy.evaluate(
        claim_id="gaia-002",
        candidate_source=CandidateSource.VERIFIED_CITATION,
        has_explanation_trace=True,
        has_citation=True,
        human_verified=False,
        source_trust="high",
    )
    assert result.decision == Decision.ESCALATE
    assert result.effects.requiresHumanApproval is True


def test_world_gaia_require_review_via_gate_even_with_strong_evidence() -> None:
    """require_review: all evidence met but mandatory review gate fires."""
    policy = default_claim_policies()[ClaimClass.WORLD_GAIA]
    result = policy.evaluate(
        claim_id="gaia-003",
        candidate_source=CandidateSource.VERIFIED_CITATION,
        has_explanation_trace=True,
        has_citation=True,
        human_verified=True,
        source_trust="verified",
    )
    # The WORLD_GAIA policy always has a high-impact review gate
    assert result.decision == Decision.ESCALATE
    assert result.effects.requiresHumanApproval is True
    assert "review gate" in result.reason.lower()


# ---------------------------------------------------------------------------
# Explainable text classification claim
# ---------------------------------------------------------------------------


def test_explainable_text_classification_allow() -> None:
    policy = default_claim_policies()[ClaimClass.EXPLAINABLE_TEXT_CLASSIFICATION]
    result = policy.evaluate(
        claim_id="etc-001",
        candidate_source=CandidateSource.EXPLAINABLE_TRACE,
        has_explanation_trace=True,
        has_citation=False,
        source_trust="medium",
    )
    assert result.decision == Decision.ALLOW


def test_explainable_text_classification_deny_missing_trace() -> None:
    policy = default_claim_policies()[ClaimClass.EXPLAINABLE_TEXT_CLASSIFICATION]
    result = policy.evaluate(
        claim_id="etc-002",
        candidate_source=CandidateSource.EXPLAINABLE_TRACE,
        has_explanation_trace=False,
        source_trust="medium",
    )
    assert result.decision == Decision.DENY


def test_explainable_text_classification_provisional_low_trust() -> None:
    policy = default_claim_policies()[ClaimClass.EXPLAINABLE_TEXT_CLASSIFICATION]
    result = policy.evaluate(
        claim_id="etc-003",
        candidate_source=CandidateSource.EXPLAINABLE_TRACE,
        has_explanation_trace=True,
        source_trust="low",
    )
    assert result.decision == Decision.ALLOW_WITH_CONTEXT


# ---------------------------------------------------------------------------
# Runtime/action claim
# ---------------------------------------------------------------------------


def test_runtime_action_claim_require_review_missing_human_verification() -> None:
    policy = default_claim_policies()[ClaimClass.RUNTIME_ACTION]
    result = policy.evaluate(
        claim_id="ra-001",
        candidate_source=CandidateSource.HUMAN_AUTHORED,
        has_explanation_trace=True,
        human_verified=False,
        source_trust="high",
    )
    assert result.decision == Decision.ESCALATE
    assert result.effects.requiresHumanApproval is True


def test_runtime_action_claim_allow_all_met() -> None:
    policy = default_claim_policies()[ClaimClass.RUNTIME_ACTION]
    result = policy.evaluate(
        claim_id="ra-002",
        candidate_source=CandidateSource.HUMAN_AUTHORED,
        has_explanation_trace=True,
        human_verified=True,
        source_trust="high",
    )
    assert result.decision == Decision.ALLOW


# ---------------------------------------------------------------------------
# Action admission policies — all four action classes
# ---------------------------------------------------------------------------


def test_default_action_policies_covers_all_action_classes() -> None:
    policies = default_action_policies()
    for action_class in AdmissionActionClass:
        assert action_class in policies, f"Missing action policy for {action_class}"


def test_action_requires_prior_claim_admission() -> None:
    """Invariant: action requires prior claim admission before execution."""
    policy = default_action_policies()[AdmissionActionClass.EXECUTE_INGEST_FUSION]
    result = policy.evaluate(
        action_id="act-001",
        admitted_claim_ids=None,
    )
    assert result.decision == Decision.DENY
    assert result.effects.agentMayContinue is False


def test_execute_ingest_fusion_allow_with_admitted_claim() -> None:
    """execute_ingest_fusion has no mandatory review gate."""
    policy = default_action_policies()[AdmissionActionClass.EXECUTE_INGEST_FUSION]
    result = policy.evaluate(
        action_id="act-002",
        admitted_claim_ids=["claim-approved-001"],
    )
    assert result.decision == Decision.ALLOW
    assert result.effects.agentMayContinue is True


def test_publish_gaia_manifest_require_review() -> None:
    """publish_gaia_manifest always triggers a mandatory human review gate."""
    policy = default_action_policies()[AdmissionActionClass.PUBLISH_GAIA_MANIFEST]
    result = policy.evaluate(
        action_id="act-003",
        admitted_claim_ids=["claim-approved-001"],
    )
    assert result.decision == Decision.ESCALATE
    assert result.effects.requiresHumanApproval is True


def test_update_claim_registry_require_review() -> None:
    policy = default_action_policies()[AdmissionActionClass.UPDATE_CLAIM_REGISTRY]
    result = policy.evaluate(
        action_id="act-004",
        admitted_claim_ids=["claim-approved-002"],
    )
    assert result.decision == Decision.ESCALATE
    assert result.effects.requiresHumanApproval is True


def test_activate_agent_artifact_require_review() -> None:
    policy = default_action_policies()[AdmissionActionClass.ACTIVATE_AGENT_ARTIFACT]
    result = policy.evaluate(
        action_id="act-005",
        admitted_claim_ids=["claim-approved-003"],
    )
    assert result.decision == Decision.ESCALATE
    assert result.effects.requiresHumanApproval is True


# ---------------------------------------------------------------------------
# ProvisionalAdmission
# ---------------------------------------------------------------------------


def test_provisional_admission_create_has_uuid_and_timestamp() -> None:
    pa = ProvisionalAdmission.create(
        claim_id="claim-prov-001",
        policy_id="governed-intelligence/claim/technical-document",
        conditions=("re-verify within 30 days",),
    )
    assert pa.admission_id
    assert pa.timestamp.endswith("Z")
    assert pa.revoked is False
    assert "re-verify within 30 days" in pa.conditions


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


def test_revocation_create_has_uuid_and_timestamp() -> None:
    rev = Revocation.create(
        admission_id="adm-001",
        claim_id="claim-prov-001",
        policy_id="governed-intelligence/claim/technical-document",
        reason="Source credibility downgraded after external audit.",
        revoked_by="human:alice@example.com",
    )
    assert rev.revocation_id
    assert rev.timestamp.endswith("Z")
    assert rev.reason
    assert "alice" in rev.revoked_by


# ---------------------------------------------------------------------------
# Fixture: Claim -> Evidence -> ExplanationTrace -> PolicyDecision
# ---------------------------------------------------------------------------


def test_claim_evidence_trace_to_policy_decision_fixture() -> None:
    """End-to-end fixture: claim + evidence + explanation trace → allow decision."""
    policy = default_claim_policies()[ClaimClass.TECHNICAL_DOCUMENT]
    decision = policy.evaluate(
        claim_id="fixture-claim-001",
        candidate_source=CandidateSource.VERIFIED_CITATION,
        has_explanation_trace=True,
        has_citation=True,
        source_trust="high",
        extra_context={
            "explanation_trace_id": "trace-abc-001",
            "citation_id": "citation-xyz-001",
        },
    )
    data = decision.to_dict()
    assert data["schema"] == "sourceos.guardrail.decision.v0.1"
    assert data["decision"] == Decision.ALLOW.value
    assert data["evidence"]["actionClass"] == "model"
    assert data["evidence"]["inputDigest"].startswith("sha256:")


# ---------------------------------------------------------------------------
# Fixture: ActionProposal -> ActionAdmission -> RuntimeReceipt requirement
# ---------------------------------------------------------------------------


def test_action_proposal_to_admission_to_receipt_requirement_fixture() -> None:
    """End-to-end fixture: action proposal → admission → RuntimeReceipt required."""
    # Step 1: admit the supporting claim
    claim_policy = default_claim_policies()[ClaimClass.RUNTIME_ACTION]
    claim_decision = claim_policy.evaluate(
        claim_id="fixture-claim-002",
        candidate_source=CandidateSource.HUMAN_AUTHORED,
        has_explanation_trace=True,
        human_verified=True,
        source_trust="high",
    )
    assert claim_decision.decision == Decision.ALLOW

    # Step 2: submit action with the admitted claim IDs
    action_policy = default_action_policies()[AdmissionActionClass.EXECUTE_INGEST_FUSION]
    action_decision = action_policy.evaluate(
        action_id="fixture-action-001",
        admitted_claim_ids=["fixture-claim-002"],
    )
    assert action_decision.decision == Decision.ALLOW
    assert action_decision.effects.agentMayContinue is True

    # Step 3: verify the decision mandates a RuntimeReceipt (logs required)
    data = action_decision.to_dict()
    assert data["effects"]["logsRequired"] is True
    assert data["effects"]["tamperSealRequired"] is True


# ---------------------------------------------------------------------------
# Custom ClaimAdmissionPolicy via EvidenceSufficiencyRule
# ---------------------------------------------------------------------------


def test_custom_policy_with_explicit_review_gate() -> None:
    gate = ReviewGate(
        gate_id="test/legal-review-gate",
        description="Legal content requires mandatory human review.",
        applies_to_claim_classes=(ClaimClass.TECHNICAL_DOCUMENT,),
        reason="Legal implications require human sign-off.",
    )
    rule = EvidenceSufficiencyRule(
        claim_class=ClaimClass.TECHNICAL_DOCUMENT,
        requires_explanation_trace=True,
        requires_citation=True,
        minimum_source_trust="medium",
    )
    policy = ClaimAdmissionPolicy(
        policy_id="test/custom-legal-policy",
        claim_class=ClaimClass.TECHNICAL_DOCUMENT,
        evidence_rule=rule,
        review_gates=(gate,),
    )
    result = policy.evaluate(
        claim_id="legal-claim-001",
        candidate_source=CandidateSource.VERIFIED_CITATION,
        has_explanation_trace=True,
        has_citation=True,
        source_trust="high",
    )
    assert result.decision == Decision.ESCALATE
    assert "legal-review-gate" in result.reason
    assert result.effects.requiresHumanApproval is True
