# Professional Intelligence Guardrails

## Purpose

This document defines the first Guardrail Fabric pack for the Professional Intelligence OS Gate 3 demo path.

Guardrail Fabric does not own policy authoring, model routing, workspace UX, memory context, or agent identity. It consumes those references and enforces runtime constraints that decide whether a workflow step may proceed, must escalate, or must be blocked.

## Contract surface

The guardrail-pack schema lives at:

- `schemas/professional-intelligence-guardrail-pack.schema.json`

The seed pack lives at:

- `examples/professional-intelligence/guardrail-pack.example.json`

Validate locally:

```bash
python -m pip install jsonschema
python scripts/validate_professional_intelligence_guardrails.py
```

The workflow `.github/workflows/professional-intelligence-guardrails.yml` validates the pack when guardrail artifacts change.

## Required rules

The seed pack validates these required controls:

- source citation required;
- policy decision required;
- workroom scope required;
- tool grant required;
- evidence required;
- low-confidence escalation.

## Gate 3 role

The pack makes the Professional Intelligence OS demo path enforceable by connecting:

- Sherlock search packet citations;
- Policy Fabric policy decisions;
- Prophet Workspace workroom scope;
- Agent Registry tool grants;
- Prophet Platform and Agentplane evidence references;
- Memory Mesh context pack boundaries;
- human escalation for incomplete or low-confidence context.

## Non-goals

- Do not bypass Policy Fabric decisions.
- Do not authorize tool use without Agent Registry grants.
- Do not release outputs without evidence and source citations.
- Do not treat warnings as demo acceptance for governed steps.
