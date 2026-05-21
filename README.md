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
- baseline deterministic policy pack for shell, Git, secrets, package, infrastructure, database, and anti-tamper safety
- Claude Code-style agent hook adapter that normalizes hook payloads into SourceOS policy context
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

## Agent hook adapter

The `guardrail-fabric-hook` entry point reads a Claude Code-style hook payload from stdin, normalizes it into a `PolicyContext`, evaluates the SourceOS baseline policy pack, optionally logs the full SourceOS decision artifact, and prints a hook-compatible response.

Example denied hook response:

```bash
printf '%s' '{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"sudo rm -rf /tmp/example"}}' \
  | guardrail-fabric-hook
```

Debug the full SourceOS decision instead of the hook response:

```bash
printf '%s' '{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"sudo rm -rf /tmp/example"}}' \
  | guardrail-fabric-hook --debug-decision
```

Write hook decisions to the repo-local evidence log:

```bash
printf '%s' '{"session_id":"s1","cwd":"'"$(pwd)"'","tool_name":"Bash","tool_input":{"command":"git status"}}' \
  | guardrail-fabric-hook --write-log --debug-decision
```

Oversized or invalid hook payloads fail closed through `defer` or `quarantine` decisions rather than implicitly allowing the action.

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

## Governed-intelligence claim/action admission

guardrail-fabric owns the **`Govern`** step in the canonical loop:

```
Observe -> Anchor -> Normalize -> Propose -> Explain -> Verify
-> Govern -> Act -> Receipt -> Learn
```

The `Govern` step applies claim admission and action admission policies before any claim is treated as truth or any agent action is executed.

### Key invariants

- Raw model output is not admitted truth.
- Raw graph candidate is not admitted truth.
- Raw vector candidate is never admitted truth; `VectorCandidate.status` must remain `candidate_only`.
- Agent action requires action admission before effectful runtime execution.
- High-impact legal/security/world-state/runtime claims can require review even when evidence is strong.

### Admission decision states

| State | Canonical ABI `decision` | Meaning |
|---|---|---|
| `allow` | `allow` | All evidence requirements met; no review gate. |
| `deny` | `deny` | Invariant violation or missing required evidence. |
| `require_review` | `escalate` | Review gate applies; human approval required. |
| `provisional` | `allow_with_context` | Evidence met but source trust below minimum. |

### Quick start

```python
from guardrail_fabric import default_claim_policies, CandidateSource

policy = default_claim_policies()["technical_document"]
decision = policy.evaluate(
    claim_id="claim-001",
    candidate_source=CandidateSource.VERIFIED_CITATION,
    has_explanation_trace=True,
    has_citation=True,
    source_trust="medium",
)
print(decision.decision)  # allow
```

### Consumer catalogue

| Repo | Role |
|---|---|
| **Holmes** (`SocioProphet/holmes`) | Produces `ExplanationTrace` consumed as evidence by `ClaimAdmissionPolicy`. |
| **Sherlock** (`SocioProphet/sherlock-search`) | Produces retrieval evidence (`citationId`, `sourceTrust`) consumed by `ClaimAdmissionPolicy`. |
| **GAIA** (`SocioProphet/gaia-world-model`) | Produces world/GAIA claims admitted via `ClaimAdmissionPolicy`. |
| **Agentplane** | Consumes `ActionAdmission` `PolicyDecision` as a runtime execution gate; records `RuntimeReceipt`. |
| **Sociosphere** (`SocioProphet/sociosphere`) | Coordinates the parent workflow loop via `PolicyDecision` refs. |

See `docs/governed-intelligence-admission-policy.md` and `examples/governed-intelligence/` for full details.

## Documentation

- `docs/sourceos-agent-reliability-control-plane.md` defines the implementation lane.
- `docs/governed-intelligence-admission-policy.md` defines claim/action admission policies and repo boundaries.
- `schemas/sourceos.guardrail.decision.v0.1.schema.json` defines the machine-readable decision shape.

## Next implementation slices

1. Improve policy engine ordering and accumulate multiple instruct/allow-with-context decisions.
2. Add hardened agent-client installers for Claude Code, Codex, Cursor, Gemini CLI, OpenCode, and AgentPlane-native execution.
3. Add stop-gate integration with AgentPlane evidence artifacts.
4. Add PolicyFabric inheritance and signed break-glass integration.
5. Add TurtleTerm and SocioSphere local session review surfaces.
