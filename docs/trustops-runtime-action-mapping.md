# TrustOps Runtime Action Mapping v0.1

## Purpose

`guardrail-fabric` owns the provider-neutral translation from TrustOps receipt outcomes to runtime guardrail actions.

The mapping is deterministic because the same TrustOps receipt chain must mean the same thing across adapters, providers, and execution surfaces.

This surface follows the estate-wide lifecycle-boundary rule:

```text
TrustOps receipt = evidence
Guardrail action decision = runtime-control decision
Agent Registry authority decision = authority mutation decision
```

Those records must remain separate. Guardrail Fabric can decide the runtime control action, but it does not directly mutate agent authority.

## Monotonic precedence

Runtime mappings use this canonical order:

```text
pass < warn < require-review < quarantine < block < rollback < revoke
```

Higher-precedence states dominate lower-precedence states. A deny-like state therefore always beats a warning-like state.

## Deny-like normalization

If an upstream adapter emits `deny`, normalize it to `block` before calling the runtime mapping layer. `deny` is an admission/control-plane label; `block` is the runtime guardrail action used to stop execution.

Do not allow adapter-local interpretations such as:

- `deny -> warn`
- `rollback -> warn`
- `quarantine` without the evidence refs and gate ids that caused it

## Provider neutrality

`provider_id` is metadata. It may appear on a `TrustOpsGateDecision`, but it cannot change runtime severity. Provider overrides may only keep or increase severity; they may not lower it.

This preserves the invariant that one TrustOps receipt chain maps to the same runtime action regardless of adapter.

## Rollback fallback

If a receipt outcome is `rollback` and the runtime cannot perform rollback, the mapper emits `block` with `fallback_reason = rollback_unsupported`.

Rollback never silently degrades to `warn`.

## TrustOpsGuardrailActionDecision

`TrustOpsGuardrailActionDecision v0.1` is the Guardrail Fabric-owned decision record for runtime control. It wraps the monotonic runtime action mapping in an auditable artifact that downstream systems can consume.

Required fields include:

```text
schemaVersion
recordType
decision_id
source_system
controlling_outcome
runtime_action
receipt_ids
gate_ids
evidence_refs
policy_refs
reason
issued_at
authority_mutation
agentplane_projection
```

The critical boundary field is:

```json
"authority_mutation": {
  "performed": false,
  "authority_plane": "SocioProphet/agent-registry",
  "downstream_intent": "requires-agent-registry-decision"
}
```

Guardrail Fabric never writes current agent authority. If the runtime action implies authority reduction, suspension, or revocation, the record exposes downstream intent for `agent-registry` to evaluate as a separate governed authority decision.

## AgentPlane projection

The record includes a narrow AgentPlane projection:

```text
outcome
runtime_action
authoritative_safety_owner
guardrail_action_ref
```

AgentPlane may use this as safety preflight input. It must not treat this as an Agent Registry authority state.

## Validation

```bash
make validate-trustops-guardrail-action-decision
```

The validator checks:

- schema strictness;
- monotonic runtime-action mapping;
- receipt refs, gate refs, evidence refs, and policy refs;
- no direct authority mutation by Guardrail Fabric;
- downstream authority intent for restrictive actions;
- AgentPlane projection consistency.

Negative fixtures cover:

- direct authority mutation from Guardrail Fabric;
- rollback degraded to warning.

## Non-goals

This record does not mutate Agent Registry authority state.

It does not execute model, RAG, agent, or service runtime work.

It does not store TrustOps receipts in the model-governance ledger.

It does not emit AgentPlane attempt admission receipts.

It is a runtime-control decision record only.
