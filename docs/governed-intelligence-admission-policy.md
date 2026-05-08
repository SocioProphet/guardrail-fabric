# Governed Intelligence — Claim/Action Admission Policy

## Purpose

This document defines the **Guardrail Fabric / Policy Fabric** contracts for
admitting or rejecting SocioProphet claims and agent actions under the
governed-intelligence reference architecture.

**guardrail-fabric** owns the `Govern` step in the canonical loop:

```
Observe -> Anchor -> Normalize -> Propose -> Explain -> Verify
-> Govern -> Act -> Receipt -> Learn
```

The Govern step applies **claim admission** and **action admission** policies
before any claim is treated as truth or any agent action is executed.

---

## Repo boundaries

| Repo | Responsibility |
|---|---|
| **guardrail-fabric** (this repo) | Owns `ClaimAdmissionPolicy`, `ActionAdmissionPolicy`, `EvidenceSufficiencyRule`, `ReviewGate`, `ProvisionalAdmission`, `Revocation`, and `PolicyDecision` emission. |
| **ontogenesis** | Canonical schema definitions. Do not diverge. |
| **holmes** | Produces reasoning/`ExplanationTrace` artifacts consumed as evidence here. |
| **sherlock-search** | Produces retrieval evidence (`citationId`, `sourceTrust`) consumed here. |
| **gaia-world-model** | Produces world/GAIA claims admitted here. |
| **agentplane** | Consumes `ActionAdmission` `PolicyDecision` as a runtime execution gate. Records `RuntimeReceipt`. |
| **sociosphere** | Coordinates parent workflows via `PolicyDecision` refs. |

---

## Required objects

### `PolicyDecision`

Canonical decision artifact (schema `sourceos.guardrail.decision.v0.1`).
Emitted by `ClaimAdmissionPolicy.evaluate()` and
`ActionAdmissionPolicy.evaluate()`.  Defined in `guardrail_fabric.decision`.

### `ClaimAdmissionPolicy`

Evaluates a candidate claim against `EvidenceSufficiencyRule` and
`ReviewGate` instances.  Returns a `PolicyDecision`.

```python
from guardrail_fabric import ClaimAdmissionPolicy, CandidateSource, default_claim_policies

policy = default_claim_policies()["technical_document"]
decision = policy.evaluate(
    claim_id="claim-001",
    candidate_source=CandidateSource.VERIFIED_CITATION,
    has_explanation_trace=True,
    has_citation=True,
    source_trust="medium",
)
```

### `ActionAdmissionPolicy`

Evaluates an action proposal before runtime execution.  Checks prior claim
admissions and mandatory review gates.  Returns a `PolicyDecision`.

```python
from guardrail_fabric import ActionAdmissionPolicy, default_action_policies

policy = default_action_policies()["execute_ingest_fusion"]
decision = policy.evaluate(
    action_id="action-001",
    admitted_claim_ids=["claim-001"],
)
```

### `EvidenceSufficiencyRule`

Declares the minimum evidence requirements for a given `ClaimClass`:

- `requires_explanation_trace`
- `requires_human_verification`
- `requires_citation`
- `minimum_source_trust` (`low` | `medium` | `high` | `verified`)
- `disallowed_sources` (raw model/graph/vector candidates by default)

### `ReviewGate`

Forces `require_review` (→ `Decision.ESCALATE`) even when evidence is strong.
Used for high-impact legal, security, world-state, or runtime claims.

### `ProvisionalAdmission`

An append-only record for claims admitted with conditions.  Includes expiry
and conditions.  Must be re-verified before the claim is treated as
authoritative.

### `Revocation`

An append-only record that supersedes a prior admission.  Never mutate an
existing admission in-place; issue a `Revocation` instead.

---

## Decision states

| Admission state | Canonical `Decision` ABI | Meaning |
|---|---|---|
| `allow` | `allow` | All evidence requirements met; no review gate applies. |
| `deny` | `deny` | Invariant violation or missing required evidence. |
| `require_review` | `escalate` | Review gate applies; `requiresHumanApproval=true`. |
| `provisional` | `allow_with_context` | Evidence met but source trust below minimum. |

---

## Invariants

1. **Raw model output is not admitted truth.**
2. **Raw graph candidate is not admitted truth.**
3. **Raw vector candidate is never admitted truth.**  `VectorCandidate.status`
   must remain `candidate_only`.
4. **Agent action requires action admission before effectful runtime execution.**
5. **High-impact legal/security/world-state/runtime claims can require review
   even when evidence is strong.**

---

## Claim class evidence requirements

| Claim class | Expl. trace | Citation | Human verif. | Min trust |
|---|---|---|---|---|
| `technical_document` | ✅ | ✅ | ❌ | `medium` |
| `world_gaia` | ✅ | ✅ | ✅ | `high` |
| `explainable_text_classification` | ✅ | ❌ | ❌ | `medium` |
| `runtime_action` | ✅ | ❌ | ✅ | `high` |

---

## Action class admission gates

| Action class | Mandatory review gate | Prior claim admission required |
|---|---|---|
| `publish_gaia_manifest` | ✅ | ✅ |
| `update_claim_registry` | ✅ | ✅ |
| `execute_ingest_fusion` | ❌ | ✅ |
| `activate_agent_artifact` | ✅ | ✅ |

---

## Examples

See `examples/governed-intelligence/` for deterministic fixture files:

| File | Decision state |
|---|---|
| `claim-allow.example.json` | `allow` |
| `claim-deny.example.json` | `deny` |
| `claim-require-review.example.json` | `require_review` |
| `claim-provisional.example.json` | `provisional` |
| `claim-evidence-trace-fixture.json` | Full Claim → Evidence → ExplanationTrace → PolicyDecision chain |
| `action-admission-fixture.json` | Full ActionProposal → ActionAdmission → RuntimeReceipt requirement chain |

---

## Validation

```bash
pytest tests/test_claim_admission.py -v
```

All 35 deterministic tests must pass before admission policy changes are merged.

---

## Discovery catalogue

The following consumers discover policy responsibilities via this document and
the Python API in `guardrail_fabric.claim_admission`:

- **Holmes** (`SocioProphet/holmes`): produces `ExplanationTrace` objects
  consumed as `has_explanation_trace=True` evidence.
- **Sherlock** (`SocioProphet/sherlock-search`): produces retrieval evidence
  (`citationId`, `sourceTrust`) consumed by `ClaimAdmissionPolicy`.
- **GAIA** (`SocioProphet/gaia-world-model`): produces world/GAIA claims
  admitted via `ClaimAdmissionPolicy(claim_class=ClaimClass.WORLD_GAIA)`.
- **Agentplane**: consumes `ActionAdmission` `PolicyDecision` as a runtime
  execution gate before the `Act` step.  Records `RuntimeReceipt` after
  execution for the `Receipt` step.
- **Sociosphere** (`SocioProphet/sociosphere`): coordinates the parent
  workflow loop.  References `PolicyDecision.decisionId` in workflow events.

---

## Non-goals

- Do not implement Agentplane execution in this repo.
- Do not implement Sherlock retrieval or Holmes reasoning in this repo.
- Do not create repo-local schemas that diverge from Ontogenesis canonical
  contracts.
- Runtime integration with Agentplane is a follow-up PR after Agentplane
  adopts the corresponding contract.

---

## Related issues

- Parent coordination: `SocioProphet/sociosphere#310`
- Schema root: `SocioProphet/ontogenesis#77`
- Holmes reasoning: `SocioProphet/holmes#7`
- Sherlock evidence: `SocioProphet/sherlock-search#51`
- GAIA world-claim: `SocioProphet/gaia-world-model#25`
