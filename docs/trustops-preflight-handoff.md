# TrustOps Preflight Handoff v0.1

## Purpose

`TrustOpsPreflightHandoff v0.1` is the Guardrail Fabric-owned handoff artifact for AgentPlane governed-runner admission.

It lets AgentPlane consume a safety result without becoming the owner of safety semantics.

Guardrail Fabric owns:

- TrustOps safety outcomes;
- runtime action mapping;
- gate identifiers;
- evidence references;
- outcome precedence;
- fail-closed safety behavior.

AgentPlane consumes the handoff as an input to `PreflightReceipt` and `AttemptAdmissionReceipt` construction.

## Record shape

A handoff record includes:

- `schemaVersion = guardrail-fabric.trustops-preflight-handoff.v0.1`
- `recordType = TrustOpsPreflightHandoff`
- `handoff_id`
- `source_system = SocioProphet/guardrail-fabric`
- `consumer_system = SocioProphet/agentplane`
- `source_receipt_id`
- `outcome`
- `runtime_action`
- `gate_ids`
- `evidence_refs`
- `reason`
- `agentplane_projection`
- optional `fail_closed_reason`

## AgentPlane projection

The handoff carries the exact fields AgentPlane may project into its preflight/admission input:

```json
{
  "outcome": "pass | warn | require-review | quarantine | block | rollback | revoke",
  "runtime_action": "allow | warn | require-review | quarantine | block | rollback | revoke",
  "authoritative_safety_owner": "SocioProphet/guardrail-fabric",
  "handoff_ref": "trustops-preflight-handoff:*"
}
```

AgentPlane must preserve `authoritative_safety_owner` and `handoff_ref`.

## Outcome/action mapping

The handoff uses the monotonic provider-neutral TrustOps mapping:

| TrustOps outcome | Runtime action |
|---|---|
| `pass` | `allow` |
| `warn` | `warn` |
| `require-review` | `require-review` |
| `quarantine` | `quarantine` |
| `block` | `block` |
| `rollback` | `rollback` |
| `revoke` | `revoke` |

A runtime action may not silently lower severity.

In particular:

- rollback cannot degrade to warn;
- quarantine must preserve exact evidence refs and gate ids;
- deny-like states outrank warning-like states;
- missing evidence fails closed.

## Fixtures

Positive fixtures:

```text
tests/fixtures/preflight-handoff/pass-allow.valid.json
tests/fixtures/preflight-handoff/require-review.valid.json
tests/fixtures/preflight-handoff/block.valid.json
```

Negative fixtures:

```text
tests/fixtures/preflight-handoff/rollback-degraded-to-warn.invalid.json
tests/fixtures/preflight-handoff/quarantine-missing-evidence.invalid.json
```

## Validation

Run the focused validator:

```bash
make validate-preflight-handoff
```

Or validate a fixture directly:

```bash
python3 tools/validate_preflight_handoff.py tests/fixtures/preflight-handoff/pass-allow.valid.json
```

Run tests:

```bash
python3 -m pytest -q tests/test_preflight_handoff.py
```

## AgentPlane consumption rule

AgentPlane may consume the handoff result as safety input.

AgentPlane must not:

- reinterpret Guardrail Fabric safety semantics;
- lower runtime action severity;
- invent missing evidence refs;
- collapse quarantine/block/rollback/revoke into warning states;
- derive authority state from safety receipts.

Authority state remains owned by Agent Registry.

## Non-goals

This handoff does not:

- execute verifier commands;
- execute agents;
- inspect the local filesystem;
- mutate repository state;
- update Agent Registry authority;
- emit AgentPlane admission receipts;
- settle budget;
- implement provider-specific adapter behavior.

It is a typed safety handoff from Guardrail Fabric to AgentPlane.
