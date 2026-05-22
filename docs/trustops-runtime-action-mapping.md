# TrustOps Runtime Action Mapping v0.1

## Purpose

`guardrail-fabric` owns the provider-neutral translation from TrustOps receipt outcomes to runtime guardrail actions.

The mapping is deterministic because the same TrustOps receipt chain must mean the same thing across adapters, providers, and execution surfaces.

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
