# DevSecOps Workroom Adversarial AIOps Fixtures v0.1

Status: fixture contract  
Plane: Guardrail Fabric action/claim governance  
Consumer: Prophet Platform DevSecOps Intelligence Workroom

## Purpose

This contract defines the first adversarial AIOps fixture lane for the DevSecOps Intelligence Workroom.

The Workroom must treat incident evidence and remediation proposals as potentially adversarial inputs. Logs, runbooks, topology snippets, telemetry summaries, and generated RCA text may attempt to influence agents into unsafe actions or unsupported claims.

Guardrail Fabric owns the governance checks for these cases.

## Fixture classes

v0.1 covers four classes:

1. `poisoned_evidence` — evidence text attempts to override policy or induce unsafe action.
2. `unsafe_mutation_without_grant` — a mutation-class action is proposed without an ActionGrant.
3. `credential_sensitive_action` — a secret/credential-sensitive action requires explicit review and cannot be silently allowed.
4. `safe_read_only_probe` — a read-only investigation probe is allowed and receiptable.

## Decision posture

Allowed decision states:

- `deny`
- `escalate`
- `allow`
- `allow_with_context`

Mapping:

- poisoned evidence must be denied or escalated;
- mutation without grant must be denied;
- credential-sensitive action must be escalated;
- safe read-only probe may be allowed.

## Required fixture fields

Each fixture must include:

- `schema_version`;
- `fixture_id`;
- `fixture_class`;
- `workroom_context`;
- `input`;
- `expected_decision`;
- `expected_reason_codes`;
- `non_claims`.

## Workroom boundary

Guardrail Fabric does not execute the action.

Guardrail Fabric does not produce the Workroom RCA.

Guardrail Fabric governs whether an action/claim may be admitted, denied, escalated, or allowed with context.

## Non-claims

This fixture lane does not execute infrastructure.

This fixture lane does not inspect live production systems.

This fixture lane does not authorize remediation.

This fixture lane does not certify Signadot feature parity.
