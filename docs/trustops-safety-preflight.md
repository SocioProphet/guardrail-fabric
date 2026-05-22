# TrustOps Safety Preflight v0.1

## Purpose

`guardrail-fabric` owns the pre-execution safety preflight decision layer for governed runtime admission.

Safety preflight runs before any effectful agent/runtime attempt. It evaluates proposed verifier commands, file changes, network posture, approval boundaries, and secret/protected material exposure. The result is a provider-neutral TrustOps-compatible decision that can be translated by the runtime action mapper.

This layer is intentionally pure and filesystem-independent: callers pass the proposed commands, changed files, and policy boundaries. The evaluator emits a receipt-like decision object; it does not execute commands or inspect the local machine.

## Contract object

The public evaluator is:

```python
from guardrail_fabric import evaluate_safety_preflight
```

It returns `SafetyPreflightDecision`:

- `receipt_id`
- `outcome = pass | require-review | block`
- `allowed`
- `reason`
- `violations[]`

Each violation records:

- `kind`
- `gate_id`
- `outcome`
- `message`
- `evidence_ref`
- optional `command`, `file`, or `match`

The decision can be converted into the TrustOps runtime-action layer:

```python
runtime_decision = decision.to_runtime_guardrail_decision()
```

## Gates

### Command safety

The command gate blocks destructive or unbounded verifier/runtime commands before execution.

Examples:

- `rm -rf`
- `git reset --hard`
- `git clean -f`
- `curl ... | sh`
- `wget ... | bash`
- `sudo`
- raw device operations such as `dd if=`
- destructive Docker/Kubernetes commands
- remote shell/file-copy commands such as `ssh` and `scp`

A blocked command produces `outcome=block`.

### Filesystem boundary

Changed files must remain inside the governed repo boundary and path policy.

The gate blocks:

- absolute paths
- `../` repo escapes
- denied paths
- files outside configured allowed paths
- protected material such as `.env`, private keys, and key files

A filesystem boundary violation produces `outcome=block`.

### Network posture

Network mode is one of:

- `off`
- `allowlisted`
- `open`

Default mode is `off`.

When mode is `off`, network verifier commands with HTTP(S) targets are blocked. When mode is `allowlisted`, only domains matching `allowed_network_domains` are permitted. `open` allows network targets but should not be used for high-assurance admission without a policy bundle granting it.

A blocked network target produces `outcome=block`.

### Approval-required changes

Some changes are not blocked outright, but they require explicit approval before execution:

- dependency files, such as `package.json`, `pnpm-lock.yaml`, `pyproject.toml`, or `requirements.txt`
- migration files
- CI/deployment/configuration files

Without approval, these produce `outcome=require-review`.

Approval keys:

- `dependency_changes`
- `migration_changes`
- `config_changes`

### Secret-like values

The preflight scans supplied text values and commands for secret-like material. Detected secrets produce `outcome=block`.

The evaluator intentionally reports the rule label rather than re-emitting the raw secret value.

## Outcome precedence

The preflight uses the same control discipline as the runtime action mapper:

```text
block > require-review > warn > pass
```

If a proposed run both requires review and contains a block-level violation, the controlling outcome is `block`.

## Runtime mapping

A `SafetyPreflightDecision` converts to a `TrustOpsGateDecision`, then into a `RuntimeGuardrailDecision`.

Examples:

- clean preflight -> `pass` -> runtime `allow`
- dependency change without approval -> `require-review` -> runtime `require-review`
- destructive command -> `block` -> runtime `block`

## Non-goals

- This module does not execute verifier commands.
- This module does not perform live filesystem inspection.
- This module does not mutate repo state.
- This module does not decide agent authority; Agent Registry owns authority state.
- This module does not admit attempts; AgentPlane consumes this decision as one input to attempt admission.

## Related contracts

- `docs/trustops-runtime-action-mapping.md`
- `guardrail_fabric.trustops_runtime_actions`
- `guardrail_fabric.safety_preflight`

## Validation

```bash
pytest tests/test_safety_preflight.py -q
```

The test suite covers:

- safe preflight -> allow
- destructive commands -> block
- path escapes -> block
- denied paths -> block
- protected paths -> block
- network-off blocking
- allowlisted network pass/block behavior
- dependency/config/migration review gates
- secret-like text blocking
- block-dominates-review precedence
