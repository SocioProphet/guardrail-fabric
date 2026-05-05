# guardrail-fabric

Reusable guardrail fabric for SocioProphet models, agents, tools, RAG packages, knowledge bases, and runtime deployments.

## SourceOS Agent Reliability Control Plane

This repository now owns the deterministic guardrail layer for the SourceOS Agent Reliability Control Plane.

The first implemented slice provides:

- `sourceos.guardrail.decision.v0.1` policy decision ABI
- Python dataclasses and enums for decisions, evidence, effects, severity, scope, and action class
- local JSONL decision logging at `.sourceos/logs/guardrail-decisions.jsonl`
- a minimal policy simulation CLI
- fail-closed behavior for oversized payloads and required policy-load failures
- JSON Schema for the decision artifact
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

1. Baseline policy pack: shell, Git, secrets, package managers, infra, database, and anti-tamper.
2. Agent hook adapters: Claude Code, Codex, Cursor, Gemini CLI, OpenCode, and AgentPlane-native execution.
3. Stop-gate integration with AgentPlane evidence artifacts.
4. Policy inheritance integration with PolicyFabric.
5. Local session review integration with TurtleTerm and SocioSphere.
