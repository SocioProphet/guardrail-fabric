# guardrail-fabric

Reusable guardrail fabric for SocioProphet models, agents, tools, RAG packages, knowledge bases, and runtime deployments.

## SourceOS Agent Reliability Control Plane

This repository owns the deterministic guardrail layer for the SourceOS Agent Reliability Control Plane.

The current implemented slice provides:

- `sourceos.guardrail.decision.v0.1` policy decision ABI
- Python dataclasses and enums for decisions, evidence, effects, severity, scope, and action class
- local JSONL decision logging at `.sourceos/logs/guardrail-decisions.jsonl`
- a policy simulation CLI
- fail-closed behavior for oversized payloads and required policy-load failures
- JSON Schema for the decision artifact
- baseline deterministic policy pack for shell, Git, secrets, package, infrastructure, and database safety
- CI-backed tests across Python 3.10, 3.11, and 3.12

## Install locally

```bash
python -m pip install -e .
```

## Simulate a decision

```bash
guardrail-fabric \
  --policy-id sourceos/core/simulated-event \
  --tool Bash \
  --action-class shell \
  --tool-input '{"command":"git status"}' \
  --repo SocioProphet/guardrail-fabric \
  --branch main
```

Write the simulated decision to the repo-local evidence log:

```bash
guardrail-fabric \
  --tool Bash \
  --action-class shell \
  --tool-input '{"command":"git status"}' \
  --write-log
```

The log is written to:

```text
.sourceos/logs/guardrail-decisions.jsonl
```

## Evaluate baseline policies

Use `--baseline` to run the built-in SourceOS baseline policy pack.

Safe read-only Git command:

```bash
guardrail-fabric \
  --baseline \
  --tool Bash \
  --action-class shell \
  --tool-input '{"command":"git status"}' \
  --branch main
```

Blocked privilege escalation:

```bash
guardrail-fabric \
  --baseline \
  --tool Bash \
  --action-class shell \
  --tool-input '{"command":"sudo rm -rf /tmp/example"}'
```

Blocked protected-branch mutation:

```bash
guardrail-fabric \
  --baseline \
  --tool Bash \
  --action-class shell \
  --tool-input '{"command":"git commit -m test"}' \
  --branch main
```

Escalated infrastructure mutation:

```bash
guardrail-fabric \
  --baseline \
  --tool Bash \
  --action-class shell \
  --tool-input '{"command":"kubectl delete pod bad-pod"}'
```

## Fail-closed checks

Oversized payloads defer rather than implicitly allowing the action:

```bash
guardrail-fabric \
  --tool Write \
  --action-class filesystem \
  --payload-size-bytes 2000000 \
  --payload-limit-bytes 1000
```

Required policy loader failures quarantine the action:

```bash
guardrail-fabric \
  --tool Bash \
  --action-class shell \
  --required-policy-error "missing sourceos/git policy pack"
```

## Run tests

```bash
python -m pip install -e . pytest
pytest -q
```

## Documentation

- `docs/sourceos-agent-reliability-control-plane.md` defines the implementation lane.
- `schemas/sourceos.guardrail.decision.v0.1.schema.json` defines the machine-readable decision shape.

## Next implementation slices

1. Improve policy engine ordering and accumulate multiple instruct/allow-with-context decisions.
2. Add anti-tamper policies for guardrail config, CI, evidence logs, branch protection, and AgentPlane stop gates.
3. Add agent hook adapters: Claude Code, Codex, Cursor, Gemini CLI, OpenCode, and AgentPlane-native execution.
4. Add stop-gate integration with AgentPlane evidence artifacts.
5. Add PolicyFabric inheritance and signed break-glass integration.
6. Add TurtleTerm and SocioSphere local session review surfaces.
