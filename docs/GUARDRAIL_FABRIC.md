# Guardrail Fabric

Guardrail Fabric emits deterministic policy decisions for SocioProphet model fabric.

It is not a live moderation provider and does not execute model calls. The first slice evaluates local policy and signal examples and emits a guardrail decision record that can be referenced by Model Router, Model Governance Ledger, Agent Registry, Prophet Platform, and Prophet CLI.

## Role in model fabric

- `model-router` references guardrail decisions before route selection.
- `model-governance-ledger` records guardrail decision evidence.
- `agent-registry` supplies agent/tool authority context.
- `prophet-cli` delegates `prophet guardrail test` here once packaging lands.
- `SourceOS` consumes approved carry refs only and must not own mutable model lifecycle authority.

## Decision statuses

The first deterministic evaluator emits:

- `allow`
- `deny`
- `requires-review`

## Current policy dimensions

- surface coverage;
- sensitive signal handling;
- prompt/policy bypass signals;
- citation requirement;
- evidence ref requirement;
- redaction hints;
- masking hints.

## Current boundary

This repository must not store secrets, private prompts, provider credentials, model weights, datasets, or live provider calls.

The first implementation emits local deterministic JSON only.

## v0.2 breaking-change policy

See [`docs/v0.2-breaking-change-policy.md`](v0.2-breaking-change-policy.md) for the
per-schema breaking-change rules, version-bump procedure, and current gate state.

## Validation

```bash
make validate
make test
make emit-demo-decision
```
