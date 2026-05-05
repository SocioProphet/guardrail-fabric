# SourceOS Agent Reliability Control Plane

## Purpose

This document defines the guardrail-fabric lane for the SourceOS Agent Reliability Control Plane: a local-first, evidence-producing control substrate for AI coding agents, browser agents, model gateways, infrastructure tools, and governed human review flows.

The objective is not to vendor or clone third-party agent-safety tools. The objective is to implement a clean-room, SourceOS-native control plane that makes agent work auditable, repeatable, policy-bound, and completion-gated across SocioProphet and SourceOS repositories.

Core doctrine:

- Agents do not get to act without policy.
- Agents do not get to claim done without evidence.
- Agents do not get to publish externally without review.
- Agents do not get to mutate infrastructure without scoped authority.
- Agents do not get to forget repo-local learnings.
- Agents do not get to hide their actions.

## Scope

guardrail-fabric owns deterministic control decisions. It does not own workflow scheduling, executor placement, or long-running state orchestration. Those belong in AgentPlane. guardrail-fabric evaluates whether a requested action is allowed, denied, instructed, redacted, escalated, quarantined, or deferred for human approval.

Primary enforcement surfaces:

1. Agent CLI hooks: Claude Code, Codex, GitHub Copilot CLI, Cursor Agent, Gemini CLI, OpenCode, Pi, and AgentPlane-native executors.
2. Shell and terminal tools: Bash, zsh, PowerShell, package managers, Git, GitHub CLI, Docker/Podman, Nix, cloud CLIs, database CLIs, and test runners.
3. File tools: read, write, edit, delete, large-file writes, policy file edits, secret-adjacent paths, repo-local playbooks, and generated artifacts.
4. Browser and external-action tools: CDP/browser-use/Playwright-style readers, social surfaces, email, issue comments, PR comments, documentation systems, and public posting workflows.
5. Model gateway tools: provider routing, token/cost budgets, prompt redaction, provider allowlists, model fallback, and egress policy.
6. Runtime actions: AgentPlane state transitions, retries, prune/requeue signals, fanout/unite joins, stop gates, and approval waits.

## Control decision ABI

Every guardrail decision must be machine-readable and evidence-ready.

```json
{
  "schema": "sourceos.guardrail.decision.v0.1",
  "decisionId": "uuid-or-content-addressed-id",
  "timestamp": "2026-05-04T00:00:00Z",
  "policyId": "sourceos/git/block-protected-branch-push",
  "policyVersion": "0.1.0",
  "policyHash": "sha256:<policy-pack-hash>",
  "scope": "repo|user|org|enterprise|runtime",
  "severity": "info|low|medium|high|critical",
  "decision": "allow|allow_with_context|instruct|deny|redact|escalate|quarantine|defer",
  "reason": "human-readable reason",
  "remediation": "specific recovery path for the agent or human",
  "evidence": {
    "repo": "owner/name",
    "branch": "branch-name",
    "commit": "sha-or-null",
    "cwd": "path-or-hash",
    "tool": "Bash",
    "actionClass": "git|filesystem|network|model|browser|infra|database|package|runtime",
    "inputDigest": "sha256:<redacted-input-digest>",
    "outputDigest": "sha256:<redacted-output-digest-or-null>"
  },
  "effects": {
    "agentMayContinue": true,
    "requiresHumanApproval": false,
    "redacted": false,
    "logsRequired": true,
    "tamperSealRequired": true
  }
}
```

The decision ABI is intentionally richer than a simple allow/deny hook. The platform needs explainability, remediation, replay, audit export, policy simulation, and deterministic conformance testing.

## Policy scope model

Policy inheritance must be explicit and security-preserving.

Priority model:

1. Enterprise policy: may force-enable, force-deny, require audit, require fail-closed behavior, and restrict provider/tool classes.
2. Organization policy: may add or tighten controls; may not weaken enterprise controls.
3. Repository policy: may add repo-local constraints, completion gates, allowed tools, environment rules, and playbook requirements.
4. Local machine policy: may add local paths, environment adapters, and machine-specific constraints; may not weaken repo/org/enterprise controls.
5. User policy: may add personal constraints and preferred workflows; may not bypass higher scopes.
6. Runtime policy: may apply emergency stops, quarantine, budget exhaustion, incident mode, or break-glass requirements.

Conflict rule: stricter policy wins unless a signed break-glass decision exists. Break-glass decisions must expire, name the human approver, include a reason, and generate a tamper-evident audit event.

## Policy namespaces

Policy identifiers should be namespaced so internal, repo, enterprise, and third-party packs can coexist safely.

Recommended namespaces:

- `sourceos/*`: baseline SourceOS policies.
- `socioprophet/*`: SocioProphet platform and governance policies.
- `agentplane/*`: runtime and completion-gate policies.
- `policyfabric/*`: enterprise inheritance and compliance profiles.
- `memorymesh/*`: memory, provenance, and playbook-update policies.
- `project/*`: repository-local policies.
- `user/*`: personal local policies.
- `vendor/*`: quarantined third-party policy packs, disabled by default unless reviewed and signed.

## Baseline policy packs

### Shell and command safety

- Block privilege escalation by default: `sudo`, `runas`, PowerShell `Start-Process -Verb RunAs`.
- Block curl/wget/iwr/irm piped to shell or eval.
- Parse shell commands with token/AST logic rather than regex-only matching.
- Detect shell operator injection and command chaining bypasses.
- Warn or block detached/background processes unless the task explicitly requires a managed daemon.
- Require explicit approval for destructive filesystem commands.

### Git and repo safety

- Block direct commits, merges, rebases, cherry-picks, and pushes on protected branches.
- Block force pushes by default.
- Warn on amend, stash drop/clear, and broad `git add .` or `git add -A`.
- Require clean branch, committed changes, pushed branch, open PR, and green CI before stop gates can pass.
- Block agents from disabling CI, removing branch protections, editing release gates, or deleting audit evidence.

### Secret and environment safety

- Block reads of `.env` and secret-adjacent files by default.
- Redact JWTs, API keys, bearer tokens, private keys, cloud credentials, database URLs, and connection strings from outputs.
- Block broad environment dumps unless explicitly scoped.
- Prevent agents from writing secrets into source-controlled files.
- Route legitimate secret access through scoped, expiring, auditable broker flows.

### Package and supply-chain safety

- Warn or block global package installs.
- Warn or block package publishing.
- Enforce the repo's package manager and lockfile policy.
- Require provenance for generated artifacts and dependency changes.
- Flag install scripts, postinstall behavior, native extensions, and unpinned remote downloads.

### Infrastructure and database safety

- Treat `kubectl`, `terraform`, `tofu`, `aws`, `gcloud`, `az`, `helm`, `gh workflow`, database CLIs, and deployment scripts as high-risk surfaces.
- Separate read-only from mutating commands.
- Require plan-before-apply for Terraform/OpenTofu.
- Block production mutations without scoped approval.
- Require namespace/account/cluster/profile evidence for cloud and Kubernetes commands.

### Browser and external action safety

- Separate read, draft, and publish authorities.
- For public surfaces, default to draft-through-PR rather than direct post.
- Detect login walls, captchas, rate limits, account challenges, and moderation warnings; stop and escalate.
- Enforce human-pace cadence profiles where automation could be mistaken for abuse.
- Ban API shortcuts where browser-only operation is required for fingerprint coherence or policy reasons.

### Model gateway safety

- Enforce provider allowlists and deny lists.
- Track per-agent, per-repo, per-user, and per-org budgets.
- Redact before provider calls.
- Record model, provider, region, route, latency, cost, and prompt/output digests.
- Support local fallback and enterprise egress profiles.

### Anti-tamper controls

Agents may not weaken their own controls. Block or escalate attempts to:

- Edit guardrail hooks or policy config.
- Remove guardrail packages.
- Disable CI, tests, or branch protections.
- Delete logs, receipts, transcripts, replay artifacts, or policy decisions.
- Edit AgentPlane completion gates.
- Modify repo-local operating instructions without creating reviewable evidence.

## Fail-closed posture

Fail-open behavior must be an explicit low-risk configuration, not the default.

Default requirements:

- Oversized hook payloads produce `defer` or `quarantine`, not implicit allow.
- Policy loader errors fail closed for required enterprise/org/repo policies.
- Custom policy errors fail according to declared policy criticality.
- Control-signal delivery failures enter reconciliation, not silent success.
- Missing audit sink should block high-risk mutations.
- Missing GitHub CLI, CI status, or branch data should prevent stop-gate success.

## Local-first evidence log

Every policy decision should be appended to a local JSONL log and optionally sealed into AgentPlane evidence artifacts.

Minimum local files:

```text
.sourceos/
  policies/
  workflows/
  memory/
  logs/
    guardrail-decisions.jsonl
    tool-events.jsonl
    redactions.jsonl
    human-overrides.jsonl
  attestations/
```

Unlike lightweight hook systems, SourceOS should log meaningful allow decisions as well as non-allow decisions. Allows are necessary to reconstruct why an agent was permitted to act.

## Repo-local operating contract

Every governed repo should eventually support:

```text
SOURCEOS.md
AGENTS.md
.sourceos/policies/
.sourceos/workflows/
.sourceos/memory/
.sourceos/runtime.json
.sourceos/agentplane.json
.sourceos/handoff/
```

Agents may propose updates to repo-local playbooks when they learn durable operational facts, but those changes must be diffed, logged, and reviewable.

## AgentPlane integration

guardrail-fabric emits decisions. AgentPlane consumes them as evidence and state-transition controls.

Required integration points:

- `PolicyDecisionArtifact`
- `HumanOverrideArtifact`
- `StopGateArtifact`
- `ExternalActionDraftArtifact`
- `ModelRouteDecisionArtifact`
- `GuardrailReplayArtifact`

AgentPlane should treat guardrail decisions as first-class event stream entries, not incidental logs.

## Immediate implementation milestones

### Milestone 1: ABI and skeleton

- Define JSON schema for `PolicyDecisionArtifact`.
- Define TypeScript/Python interfaces for policy context and policy result.
- Implement local JSONL decision writer.
- Implement policy simulation CLI.

### Milestone 2: Baseline policy pack

- Add shell, Git, secret, environment, file, and package-manager policies.
- Add tokenized command parser.
- Add default fail-closed behavior for oversized payloads and required policy failures.

### Milestone 3: Agent hook adapters

- Add adapters for Claude Code, Codex, Cursor, Gemini CLI, OpenCode, and AgentPlane-native execution.
- Normalize tool events into the shared policy context.

### Milestone 4: Stop gates

- Require branch, commit, push, PR, CI green, tests, summary, and evidence artifact before an agent may claim completion.
- Emit explicit remediation when a stop gate fails.

### Milestone 5: External action safety

- Add draft-through-PR workflow for browser/social/email/document publication.
- Add human-pace cadence profiles.
- Add explicit read/draft/publish authority separation.

### Milestone 6: Model gateway controls

- Add provider route decision schema.
- Add budget and egress policies.
- Add prompt/output digest and redaction evidence.

## Non-goals

- Do not vendor third-party restricted-license control-plane code.
- Do not depend on cloud services for local guardrail enforcement.
- Do not make telemetry mandatory.
- Do not let dashboard UX become the source of truth; local evidence files and AgentPlane artifacts are the source of truth.

## Definition of done

This lane is demo-ready when a coding agent can be launched against a repo, intercepted by guardrail-fabric, blocked from dangerous actions, instructed through safe remediation, required to produce a PR and green CI before stopping, and reviewed through a local SourceOS/TurtleTerm/SocioSphere session surface with replayable evidence.
