"""Claim and action admission policy contracts for governed intelligence.

This module implements the Guardrail Fabric / Policy Fabric contracts for
admitting or rejecting SocioProphet claims and agent actions under the
governed-intelligence reference architecture.

Guardrail/Policy Fabric owns the ``Govern`` step in the canonical loop::

    Observe -> Anchor -> Normalize -> Propose -> Explain -> Verify
    -> Govern -> Act -> Receipt -> Learn

Key invariants enforced here:

- Raw model output is not admitted truth.
- Raw graph candidate is not admitted truth.
- Raw vector candidate is never admitted truth; ``VectorCandidate.status``
  must remain ``candidate_only``.
- Agent action requires action admission before effectful runtime execution.
- High-impact legal/security/world-state/runtime claims can require review
  even when evidence is strong.

Repo boundary
-------------
- ``guardrail-fabric`` (this repo): owns policy objects, decision emission,
  evidence rules, review gates, provisional admissions, and revocations.
- ``ontogenesis``: owns canonical schema definitions; do not diverge.
- ``holmes``: owns reasoning traces consumed as evidence here.
- ``sherlock-search``: owns retrieval evidence consumed here.
- ``gaia-world-model``: produces world/GAIA claims admitted here.
- ``agentplane``: consumes ``ActionAdmission`` decisions as execution gates.
- ``sociosphere``: coordinates parent workflows via ``PolicyDecision`` refs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from .decision import (
    ActionClass,
    Decision,
    Effects,
    Evidence,
    PolicyDecision,
    Scope,
    Severity,
    stable_digest,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AdmissionDecision(str, Enum):
    """Admission-layer decision states for claims and agent actions.

    These map onto the canonical :class:`~guardrail_fabric.decision.Decision`
    ABI when a :class:`~guardrail_fabric.decision.PolicyDecision` is emitted.

    Mapping:

    - ``allow``          → :attr:`~guardrail_fabric.decision.Decision.ALLOW`
    - ``deny``           → :attr:`~guardrail_fabric.decision.Decision.DENY`
    - ``require_review`` → :attr:`~guardrail_fabric.decision.Decision.ESCALATE`
    - ``provisional``    → :attr:`~guardrail_fabric.decision.Decision.ALLOW_WITH_CONTEXT`
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_REVIEW = "require_review"
    PROVISIONAL = "provisional"

    def to_policy_decision(self) -> Decision:
        """Return the canonical :class:`Decision` that corresponds to this state."""
        _map: dict[AdmissionDecision, Decision] = {
            AdmissionDecision.ALLOW: Decision.ALLOW,
            AdmissionDecision.DENY: Decision.DENY,
            AdmissionDecision.REQUIRE_REVIEW: Decision.ESCALATE,
            AdmissionDecision.PROVISIONAL: Decision.ALLOW_WITH_CONTEXT,
        }
        return _map[self]


class ClaimClass(str, Enum):
    """Taxonomy of claim classes subject to admission policy."""

    TECHNICAL_DOCUMENT = "technical_document"
    WORLD_GAIA = "world_gaia"
    EXPLAINABLE_TEXT_CLASSIFICATION = "explainable_text_classification"
    RUNTIME_ACTION = "runtime_action"


class AdmissionActionClass(str, Enum):
    """Action classes subject to action admission policy.

    These are distinct from the runtime :class:`~guardrail_fabric.decision.ActionClass`
    and represent the semantic action being admitted for execution.
    """

    PUBLISH_GAIA_MANIFEST = "publish_gaia_manifest"
    UPDATE_CLAIM_REGISTRY = "update_claim_registry"
    EXECUTE_INGEST_FUSION = "execute_ingest_fusion"
    ACTIVATE_AGENT_ARTIFACT = "activate_agent_artifact"


class CandidateSource(str, Enum):
    """Source provenance of a claim candidate.

    The invariant is that raw model, graph, and vector candidates are never
    admitted as truth without additional verification.  Only human-authored,
    citation-verified, or explanation-traced derivations may be admitted.
    """

    MODEL_OUTPUT = "model_output"
    """Raw LLM/model output — never admitted truth."""

    GRAPH_CANDIDATE = "graph_candidate"
    """Raw knowledge-graph candidate — never admitted truth."""

    VECTOR_CANDIDATE = "vector_candidate"
    """Raw vector-similarity candidate — never admitted truth.
    ``VectorCandidate.status`` must remain ``candidate_only``."""

    HUMAN_AUTHORED = "human_authored"
    """Human-authored content — may be admitted."""

    VERIFIED_CITATION = "verified_citation"
    """Citation-verified claim — may be admitted."""

    EXPLAINABLE_TRACE = "explainable_trace"
    """Claim derived via a verifiable explanation trace — may be admitted."""


_RAW_CANDIDATE_SOURCES: frozenset[CandidateSource] = frozenset(
    {
        CandidateSource.MODEL_OUTPUT,
        CandidateSource.GRAPH_CANDIDATE,
        CandidateSource.VECTOR_CANDIDATE,
    }
)

_TRUST_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "verified": 3,
}


# ---------------------------------------------------------------------------
# Core policy objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceSufficiencyRule:
    """Minimum evidence requirements for a claim class to be admissible.

    Instances for each :class:`ClaimClass` are provided by
    :func:`default_evidence_rules`.
    """

    claim_class: ClaimClass
    requires_explanation_trace: bool = True
    requires_human_verification: bool = False
    requires_citation: bool = True
    minimum_source_trust: str = "medium"
    """One of ``low`` | ``medium`` | ``high`` | ``verified``."""
    disallowed_sources: tuple[CandidateSource, ...] = field(
        default_factory=lambda: tuple(_RAW_CANDIDATE_SOURCES)
    )
    description: str = ""


@dataclass(frozen=True)
class ReviewGate:
    """A review gate that forces ``require_review`` even when evidence is strong.

    High-impact legal, security, world-state, or runtime claims must pass
    through a review gate before admission regardless of evidence quality.
    """

    gate_id: str
    description: str
    applies_to_claim_classes: tuple[ClaimClass, ...] = field(default_factory=tuple)
    applies_to_action_classes: tuple[AdmissionActionClass, ...] = field(default_factory=tuple)
    reason: str = ""


@dataclass(frozen=True)
class ClaimAdmissionPolicy:
    """Policy governing admission of a SocioProphet claim.

    Evaluates a candidate claim against evidence sufficiency rules and
    review gates and emits a :class:`~guardrail_fabric.decision.PolicyDecision`.
    """

    policy_id: str
    claim_class: ClaimClass
    evidence_rule: EvidenceSufficiencyRule
    review_gates: tuple[ReviewGate, ...] = field(default_factory=tuple)
    description: str = ""

    def evaluate(
        self,
        *,
        claim_id: str,
        candidate_source: CandidateSource,
        has_explanation_trace: bool = False,
        has_citation: bool = False,
        human_verified: bool = False,
        source_trust: str = "low",
        extra_context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate a claim candidate and return a :class:`PolicyDecision`.

        Parameters
        ----------
        claim_id:
            Stable identifier for the claim being evaluated.
        candidate_source:
            Provenance of the raw candidate content.
        has_explanation_trace:
            Whether a verifiable explanation trace is attached.
        has_citation:
            Whether a verified citation is attached.
        human_verified:
            Whether a human has explicitly verified this claim.
        source_trust:
            Trust level of the source: ``low`` | ``medium`` | ``high``
            | ``verified``.
        extra_context:
            Optional metadata forwarded into the evidence digest.
        """
        rule = self.evidence_rule
        ctx_digest = stable_digest(
            {"claim_id": claim_id, "source": candidate_source.value, **(extra_context or {})}
        )
        evidence = Evidence(
            actionClass=ActionClass.MODEL,
            inputDigest=ctx_digest,
        )

        # Invariant: raw model/graph/vector candidates are never admitted truth
        if candidate_source in rule.disallowed_sources:
            source_label = candidate_source.value.replace("_", " ")
            return PolicyDecision.create(
                policy_id=self.policy_id,
                decision=Decision.DENY,
                severity=Severity.HIGH,
                scope=Scope.REPO,
                reason=(
                    f"Claim '{claim_id}' sourced from '{candidate_source.value}' "
                    f"is not admissible. Raw {source_label} is not admitted truth."
                ),
                remediation=(
                    "Provide a verified citation, human-authored anchor, or an "
                    "explanation-traced derivation before submitting this claim."
                ),
                evidence=evidence,
                effects=Effects(agentMayContinue=False),
            )

        # Evidence sufficiency: explanation trace
        if rule.requires_explanation_trace and not has_explanation_trace:
            return PolicyDecision.create(
                policy_id=self.policy_id,
                decision=Decision.DENY,
                severity=Severity.MEDIUM,
                scope=Scope.REPO,
                reason=(
                    f"Claim '{claim_id}' requires an explanation trace but none was provided."
                ),
                remediation=(
                    "Attach an ExplanationTrace before resubmitting the claim for admission."
                ),
                evidence=evidence,
                effects=Effects(agentMayContinue=False),
            )

        # Evidence sufficiency: citation
        if rule.requires_citation and not has_citation:
            return PolicyDecision.create(
                policy_id=self.policy_id,
                decision=Decision.DENY,
                severity=Severity.MEDIUM,
                scope=Scope.REPO,
                reason=(
                    f"Claim '{claim_id}' requires a citation but none was provided."
                ),
                remediation=(
                    "Attach a verified citation before resubmitting the claim for admission."
                ),
                evidence=evidence,
                effects=Effects(agentMayContinue=False),
            )

        # Evidence sufficiency: human verification
        if rule.requires_human_verification and not human_verified:
            return PolicyDecision.create(
                policy_id=self.policy_id,
                decision=Decision.ESCALATE,
                severity=Severity.HIGH,
                scope=Scope.REPO,
                reason=(
                    f"Claim '{claim_id}' requires human verification before admission."
                ),
                remediation=(
                    "Route the claim to a human reviewer and resubmit with "
                    "human_verified=True once approval is recorded."
                ),
                evidence=evidence,
                effects=Effects(agentMayContinue=False, requiresHumanApproval=True),
            )

        # Review gates: force require_review even when evidence is strong
        for gate in self.review_gates:
            if self.claim_class in gate.applies_to_claim_classes:
                return PolicyDecision.create(
                    policy_id=self.policy_id,
                    decision=Decision.ESCALATE,
                    severity=Severity.HIGH,
                    scope=Scope.REPO,
                    reason=(
                        f"Claim '{claim_id}' is subject to review gate "
                        f"'{gate.gate_id}': {gate.reason}"
                    ),
                    remediation=(
                        "Submit the claim for human review before admission. "
                        "Record the human override with gate_id and reviewer identity."
                    ),
                    evidence=evidence,
                    effects=Effects(agentMayContinue=False, requiresHumanApproval=True),
                )

        # Provisional: admitted with conditions when trust is below minimum
        required_rank = _TRUST_RANK.get(rule.minimum_source_trust, 1)
        actual_rank = _TRUST_RANK.get(source_trust, 0)
        if actual_rank < required_rank:
            return PolicyDecision.create(
                policy_id=self.policy_id,
                decision=Decision.ALLOW_WITH_CONTEXT,
                severity=Severity.LOW,
                scope=Scope.REPO,
                reason=(
                    f"Claim '{claim_id}' is provisionally admitted. Source trust "
                    f"'{source_trust}' is below the minimum '{rule.minimum_source_trust}'. "
                    "This admission is provisional and subject to re-verification."
                ),
                remediation=(
                    "Elevate the source trust level before treating this claim as "
                    "authoritative. Record the claim status as 'provisional' in the "
                    "claim registry and schedule re-verification."
                ),
                evidence=evidence,
                effects=Effects(agentMayContinue=True),
            )

        # All checks passed: admit the claim
        return PolicyDecision.create(
            policy_id=self.policy_id,
            decision=Decision.ALLOW,
            severity=Severity.INFO,
            scope=Scope.REPO,
            reason=(
                f"Claim '{claim_id}' meets all evidence requirements and review gates."
            ),
            remediation=(
                "No action required. Record the admission in the claim registry."
            ),
            evidence=evidence,
            effects=Effects(agentMayContinue=True),
        )


@dataclass(frozen=True)
class ActionAdmissionPolicy:
    """Policy governing admission of an agent action before runtime execution.

    Agent actions require explicit admission before effectful runtime execution.
    This policy checks that prior claim admissions are present and that no
    mandatory review gate applies.
    """

    policy_id: str
    action_class: AdmissionActionClass
    review_gates: tuple[ReviewGate, ...] = field(default_factory=tuple)
    requires_prior_claim_admission: bool = True
    description: str = ""

    def evaluate(
        self,
        *,
        action_id: str,
        admitted_claim_ids: list[str] | None = None,
        extra_context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate an action proposal and return a :class:`PolicyDecision`.

        Parameters
        ----------
        action_id:
            Stable identifier for the action proposal.
        admitted_claim_ids:
            Identifiers of claims already admitted by a
            :class:`ClaimAdmissionPolicy`.  Required when
            ``requires_prior_claim_admission`` is ``True``.
        extra_context:
            Optional metadata forwarded into the evidence digest.
        """
        ctx_digest = stable_digest(
            {
                "action_id": action_id,
                "action_class": self.action_class.value,
                **(extra_context or {}),
            }
        )
        evidence = Evidence(
            actionClass=ActionClass.RUNTIME,
            inputDigest=ctx_digest,
        )

        # Invariant: action requires prior claim admission
        if self.requires_prior_claim_admission and not admitted_claim_ids:
            return PolicyDecision.create(
                policy_id=self.policy_id,
                decision=Decision.DENY,
                severity=Severity.HIGH,
                scope=Scope.RUNTIME,
                reason=(
                    f"Action '{action_id}' ({self.action_class.value}) requires prior "
                    "claim admission but no admitted claim IDs were provided."
                ),
                remediation=(
                    "Admit the supporting claims through ClaimAdmissionPolicy before "
                    "submitting the action proposal."
                ),
                evidence=evidence,
                effects=Effects(agentMayContinue=False),
            )

        # Review gates: force require_review for high-impact action classes
        for gate in self.review_gates:
            if self.action_class in gate.applies_to_action_classes:
                return PolicyDecision.create(
                    policy_id=self.policy_id,
                    decision=Decision.ESCALATE,
                    severity=Severity.HIGH,
                    scope=Scope.RUNTIME,
                    reason=(
                        f"Action '{action_id}' ({self.action_class.value}) is subject "
                        f"to review gate '{gate.gate_id}': {gate.reason}"
                    ),
                    remediation=(
                        "Submit the action proposal for human review before execution. "
                        "Record the ActionAdmission with reviewer identity and gate_id."
                    ),
                    evidence=evidence,
                    effects=Effects(agentMayContinue=False, requiresHumanApproval=True),
                )

        # Action admitted
        return PolicyDecision.create(
            policy_id=self.policy_id,
            decision=Decision.ALLOW,
            severity=Severity.INFO,
            scope=Scope.RUNTIME,
            reason=(
                f"Action '{action_id}' ({self.action_class.value}) is admitted for execution."
            ),
            remediation=(
                "Proceed with bounded execution. Record a RuntimeReceipt upon completion."
            ),
            evidence=evidence,
            effects=Effects(agentMayContinue=True),
        )


@dataclass(frozen=True)
class ProvisionalAdmission:
    """A provisional admission record for a claim or action.

    Provisional admissions are time-bounded and must be re-verified before
    the claim or action is treated as authoritative.
    """

    admission_id: str
    claim_id: str
    policy_id: str
    timestamp: str
    expiry: str | None = None
    conditions: tuple[str, ...] = field(default_factory=tuple)
    revoked: bool = False

    @classmethod
    def create(
        cls,
        *,
        claim_id: str,
        policy_id: str,
        expiry: str | None = None,
        conditions: tuple[str, ...] = (),
    ) -> "ProvisionalAdmission":
        return cls(
            admission_id=str(uuid4()),
            claim_id=claim_id,
            policy_id=policy_id,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            expiry=expiry,
            conditions=conditions,
        )


@dataclass(frozen=True)
class Revocation:
    """A revocation record for a previously admitted claim or action.

    Revocations are append-only evidence artifacts.  Do not mutate a prior
    admission in place; issue a ``Revocation`` instead.
    """

    revocation_id: str
    admission_id: str
    claim_id: str
    policy_id: str
    timestamp: str
    reason: str
    revoked_by: str

    @classmethod
    def create(
        cls,
        *,
        admission_id: str,
        claim_id: str,
        policy_id: str,
        reason: str,
        revoked_by: str,
    ) -> "Revocation":
        return cls(
            revocation_id=str(uuid4()),
            admission_id=admission_id,
            claim_id=claim_id,
            policy_id=policy_id,
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            reason=reason,
            revoked_by=revoked_by,
        )


# ---------------------------------------------------------------------------
# Default policy catalogue
# ---------------------------------------------------------------------------


def default_evidence_rules() -> dict[ClaimClass, EvidenceSufficiencyRule]:
    """Return the default evidence sufficiency rules for each claim class.

    Claim classes and their minimum requirements:

    =============================================  ====  ====  ====  ========
    Claim class                                    Expl  Cit   Hum   Trust
    =============================================  ====  ====  ====  ========
    ``technical_document``                         yes   yes   no    medium
    ``world_gaia``                                 yes   yes   yes   high
    ``explainable_text_classification``            yes   no    no    medium
    ``runtime_action``                             yes   no    yes   high
    =============================================  ====  ====  ====  ========
    """
    return {
        ClaimClass.TECHNICAL_DOCUMENT: EvidenceSufficiencyRule(
            claim_class=ClaimClass.TECHNICAL_DOCUMENT,
            requires_explanation_trace=True,
            requires_human_verification=False,
            requires_citation=True,
            minimum_source_trust="medium",
            description=(
                "Technical document claims require a verified citation and an "
                "explanation trace. Human verification is recommended but not "
                "mandatory for medium-trust sources."
            ),
        ),
        ClaimClass.WORLD_GAIA: EvidenceSufficiencyRule(
            claim_class=ClaimClass.WORLD_GAIA,
            requires_explanation_trace=True,
            requires_human_verification=True,
            requires_citation=True,
            minimum_source_trust="high",
            description=(
                "World/GAIA claims affect the shared world-state model and "
                "require citation, an explanation trace, and explicit human "
                "verification before admission."
            ),
        ),
        ClaimClass.EXPLAINABLE_TEXT_CLASSIFICATION: EvidenceSufficiencyRule(
            claim_class=ClaimClass.EXPLAINABLE_TEXT_CLASSIFICATION,
            requires_explanation_trace=True,
            requires_human_verification=False,
            requires_citation=False,
            minimum_source_trust="medium",
            description=(
                "Explainable text classification claims must include an "
                "explanation trace that links the classification decision to "
                "verifiable input features. Citations are optional."
            ),
        ),
        ClaimClass.RUNTIME_ACTION: EvidenceSufficiencyRule(
            claim_class=ClaimClass.RUNTIME_ACTION,
            requires_explanation_trace=True,
            requires_human_verification=True,
            requires_citation=False,
            minimum_source_trust="high",
            description=(
                "Runtime/action claims govern effectful agent execution and "
                "require an explanation trace and human verification."
            ),
        ),
    }


def default_action_policies() -> dict[AdmissionActionClass, ActionAdmissionPolicy]:
    """Return the default :class:`ActionAdmissionPolicy` for each action class.

    Minimum gates for each action class:

    - ``publish_gaia_manifest``: mandatory human review gate.
    - ``update_claim_registry``: mandatory human review gate.
    - ``execute_ingest_fusion``: no mandatory review gate; prior claim admission required.
    - ``activate_agent_artifact``: mandatory human review gate.
    """
    publish_gate = ReviewGate(
        gate_id="governed-intelligence/publish-gaia-manifest-review",
        description="Publishing a GAIA map/tile manifest requires human review.",
        applies_to_action_classes=(AdmissionActionClass.PUBLISH_GAIA_MANIFEST,),
        reason=(
            "GAIA manifest publication is a world-state action with broad "
            "impact on downstream consumers. Human review is mandatory."
        ),
    )
    registry_gate = ReviewGate(
        gate_id="governed-intelligence/update-claim-registry-review",
        description="Updating the repo-derived claim registry requires human review.",
        applies_to_action_classes=(AdmissionActionClass.UPDATE_CLAIM_REGISTRY,),
        reason=(
            "Claim registry updates affect downstream policy decisions and "
            "admission chains. Human review is mandatory."
        ),
    )
    artifact_gate = ReviewGate(
        gate_id="governed-intelligence/activate-agent-artifact-review",
        description="Activating an agent-authored artifact requires human review.",
        applies_to_action_classes=(AdmissionActionClass.ACTIVATE_AGENT_ARTIFACT,),
        reason=(
            "Agent-authored artifacts may contain unverified logic or "
            "unintended side-effects. Human review is mandatory before activation."
        ),
    )
    return {
        AdmissionActionClass.PUBLISH_GAIA_MANIFEST: ActionAdmissionPolicy(
            policy_id="governed-intelligence/action/publish-gaia-manifest",
            action_class=AdmissionActionClass.PUBLISH_GAIA_MANIFEST,
            review_gates=(publish_gate,),
            requires_prior_claim_admission=True,
            description="Admission policy for publishing GAIA map/tile manifests.",
        ),
        AdmissionActionClass.UPDATE_CLAIM_REGISTRY: ActionAdmissionPolicy(
            policy_id="governed-intelligence/action/update-claim-registry",
            action_class=AdmissionActionClass.UPDATE_CLAIM_REGISTRY,
            review_gates=(registry_gate,),
            requires_prior_claim_admission=True,
            description="Admission policy for updating the repo-derived claim registry.",
        ),
        AdmissionActionClass.EXECUTE_INGEST_FUSION: ActionAdmissionPolicy(
            policy_id="governed-intelligence/action/execute-ingest-fusion",
            action_class=AdmissionActionClass.EXECUTE_INGEST_FUSION,
            review_gates=(),
            requires_prior_claim_admission=True,
            description=(
                "Admission policy for bounded ingest/fusion workflows. "
                "No mandatory review gate; prior claim admission is required."
            ),
        ),
        AdmissionActionClass.ACTIVATE_AGENT_ARTIFACT: ActionAdmissionPolicy(
            policy_id="governed-intelligence/action/activate-agent-artifact",
            action_class=AdmissionActionClass.ACTIVATE_AGENT_ARTIFACT,
            review_gates=(artifact_gate,),
            requires_prior_claim_admission=True,
            description="Admission policy for activating agent-authored artifacts.",
        ),
    }


def default_claim_policies() -> dict[ClaimClass, ClaimAdmissionPolicy]:
    """Return the default :class:`ClaimAdmissionPolicy` for each claim class."""
    rules = default_evidence_rules()
    # World/GAIA claims are always gated even with strong evidence
    gaia_gate = ReviewGate(
        gate_id="governed-intelligence/world-gaia-high-impact-review",
        description=(
            "World/GAIA claims with legal, security, or world-state impact "
            "require human review regardless of evidence strength."
        ),
        applies_to_claim_classes=(ClaimClass.WORLD_GAIA,),
        reason=(
            "High-impact world-state changes require explicit human authorisation "
            "to prevent autonomous propagation of incorrect or harmful world models."
        ),
    )
    return {
        ClaimClass.TECHNICAL_DOCUMENT: ClaimAdmissionPolicy(
            policy_id="governed-intelligence/claim/technical-document",
            claim_class=ClaimClass.TECHNICAL_DOCUMENT,
            evidence_rule=rules[ClaimClass.TECHNICAL_DOCUMENT],
            review_gates=(),
            description="Admission policy for technical document claims.",
        ),
        ClaimClass.WORLD_GAIA: ClaimAdmissionPolicy(
            policy_id="governed-intelligence/claim/world-gaia",
            claim_class=ClaimClass.WORLD_GAIA,
            evidence_rule=rules[ClaimClass.WORLD_GAIA],
            review_gates=(gaia_gate,),
            description="Admission policy for world/GAIA claims.",
        ),
        ClaimClass.EXPLAINABLE_TEXT_CLASSIFICATION: ClaimAdmissionPolicy(
            policy_id="governed-intelligence/claim/explainable-text-classification",
            claim_class=ClaimClass.EXPLAINABLE_TEXT_CLASSIFICATION,
            evidence_rule=rules[ClaimClass.EXPLAINABLE_TEXT_CLASSIFICATION],
            review_gates=(),
            description="Admission policy for explainable text classification claims.",
        ),
        ClaimClass.RUNTIME_ACTION: ClaimAdmissionPolicy(
            policy_id="governed-intelligence/claim/runtime-action",
            claim_class=ClaimClass.RUNTIME_ACTION,
            evidence_rule=rules[ClaimClass.RUNTIME_ACTION],
            review_gates=(),
            description="Admission policy for runtime/action claims.",
        ),
    }
