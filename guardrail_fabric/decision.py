"""SourceOS guardrail decision ABI.

The ABI is deliberately model-free. High-risk policy enforcement must be able
stand up without an LLM call, hosted service, or dashboard process.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from typing import Any
from uuid import uuid4

SCHEMA_ID = "sourceos.guardrail.decision.v0.1"
DEFAULT_PAYLOAD_LIMIT_BYTES = 1_048_576


class Decision(str, Enum):
    """Canonical policy decisions emitted by guardrail-fabric."""

    ALLOW = "allow"
    ALLOW_WITH_CONTEXT = "allow_with_context"
    INSTRUCT = "instruct"
    DENY = "deny"
    REDACT = "redact"
    ESCALATE = "escalate"
    QUARANTINE = "quarantine"
    DEFER = "defer"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Scope(str, Enum):
    USER = "user"
    LOCAL = "local"
    REPO = "repo"
    ORG = "org"
    ENTERPRISE = "enterprise"
    RUNTIME = "runtime"


class ActionClass(str, Enum):
    SHELL = "shell"
    FILESYSTEM = "filesystem"
    GIT = "git"
    NETWORK = "network"
    MODEL = "model"
    BROWSER = "browser"
    INFRA = "infra"
    DATABASE = "database"
    PACKAGE = "package"
    RUNTIME = "runtime"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Evidence:
    """Redacted evidence block for a decision.

    Raw tool inputs and outputs should not be stored here. Use digests and
    concise redacted summaries in higher-level artifacts when needed.
    """

    repo: str | None = None
    branch: str | None = None
    commit: str | None = None
    cwd: str | None = None
    tool: str | None = None
    actionClass: ActionClass = ActionClass.UNKNOWN
    inputDigest: str | None = None
    outputDigest: str | None = None
    sessionId: str | None = None
    agentId: str | None = None
    taskId: str | None = None


@dataclass(frozen=True)
class Effects:
    """Operational consequences of a policy decision."""

    agentMayContinue: bool
    requiresHumanApproval: bool = False
    redacted: bool = False
    logsRequired: bool = True
    tamperSealRequired: bool = True


@dataclass(frozen=True)
class PolicyDecision:
    """SourceOS guardrail decision artifact."""

    schema: str
    decisionId: str
    timestamp: str
    policyId: str
    policyVersion: str
    policyHash: str | None
    scope: Scope
    severity: Severity
    decision: Decision
    reason: str
    remediation: str
    evidence: Evidence = field(default_factory=Evidence)
    effects: Effects = field(default_factory=lambda: Effects(agentMayContinue=True))

    @classmethod
    def create(
        cls,
        *,
        policy_id: str,
        decision: Decision,
        reason: str,
        remediation: str,
        severity: Severity = Severity.INFO,
        scope: Scope = Scope.REPO,
        policy_version: str = "0.1.0",
        policy_hash: str | None = None,
        evidence: Evidence | None = None,
        effects: Effects | None = None,
    ) -> "PolicyDecision":
        return cls(
            schema=SCHEMA_ID,
            decisionId=str(uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            policyId=policy_id,
            policyVersion=policy_version,
            policyHash=policy_hash,
            scope=scope,
            severity=severity,
            decision=decision,
            reason=reason,
            remediation=remediation,
            evidence=evidence or Evidence(),
            effects=effects or default_effects_for_decision(decision),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def stable_digest(value: Any) -> str:
    """Return a stable SHA-256 digest for redacted evidence."""

    data = json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return f"sha256:{sha256(data).hexdigest()}"


def default_effects_for_decision(decision: Decision) -> Effects:
    if decision == Decision.ALLOW:
        return Effects(agentMayContinue=True)
    if decision == Decision.ALLOW_WITH_CONTEXT:
        return Effects(agentMayContinue=True)
    if decision == Decision.INSTRUCT:
        return Effects(agentMayContinue=True)
    if decision == Decision.REDACT:
        return Effects(agentMayContinue=True, redacted=True)
    if decision == Decision.ESCALATE:
        return Effects(agentMayContinue=False, requiresHumanApproval=True)
    if decision == Decision.DEFER:
        return Effects(agentMayContinue=False, requiresHumanApproval=True)
    if decision == Decision.QUARANTINE:
        return Effects(agentMayContinue=False, requiresHumanApproval=True)
    return Effects(agentMayContinue=False)


def decision_from_event(
    *,
    policy_id: str,
    tool: str | None,
    action_class: ActionClass,
    tool_input: dict[str, Any] | None = None,
    tool_output: dict[str, Any] | None = None,
    repo: str | None = None,
    branch: str | None = None,
    commit: str | None = None,
    cwd: str | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    task_id: str | None = None,
    payload_size_bytes: int | None = None,
    payload_limit_bytes: int = DEFAULT_PAYLOAD_LIMIT_BYTES,
    required_policy_error: str | None = None,
) -> PolicyDecision:
    """Create a minimal policy decision from a normalized tool event.

    This is intentionally conservative. It gives adapters and tests a shared
    path before the full baseline policy pack lands.
    """

    evidence = Evidence(
        repo=repo,
        branch=branch,
        commit=commit,
        cwd=cwd,
        tool=tool,
        actionClass=action_class,
        inputDigest=stable_digest(tool_input or {}),
        outputDigest=stable_digest(tool_output) if tool_output is not None else None,
        sessionId=session_id,
        agentId=agent_id,
        taskId=task_id,
    )

    if payload_size_bytes is not None and payload_size_bytes > payload_limit_bytes:
        return PolicyDecision.create(
            policy_id="sourceos/core/oversized-payload",
            decision=Decision.DEFER,
            severity=Severity.HIGH,
            scope=Scope.RUNTIME,
            reason=f"Hook payload size {payload_size_bytes} bytes exceeds limit {payload_limit_bytes} bytes.",
            remediation="Do not implicitly allow the action. Re-run with chunked evidence, a redacted digest, or explicit human approval.",
            evidence=evidence,
        )

    if required_policy_error:
        return PolicyDecision.create(
            policy_id="sourceos/core/required-policy-load-failed",
            decision=Decision.QUARANTINE,
            severity=Severity.CRITICAL,
            scope=Scope.RUNTIME,
            reason=f"A required policy failed to load: {required_policy_error}",
            remediation="Stop the agent session, repair the required policy pack, and replay the action through policy simulation before continuing.",
            evidence=evidence,
        )

    return PolicyDecision.create(
        policy_id=policy_id,
        decision=Decision.ALLOW,
        severity=Severity.INFO,
        scope=Scope.REPO,
        reason="No blocking policy decision was produced for this normalized event.",
        remediation="Continue. If this action is high-risk, add a specific policy before enabling autonomous execution.",
        evidence=evidence,
    )
