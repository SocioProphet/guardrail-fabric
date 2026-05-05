"""Baseline deterministic SourceOS guardrail policies.

These policies are intentionally conservative and model-free. They are the
first policy pack for the SourceOS Agent Reliability Control Plane.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from .decision import (
    ActionClass,
    Decision,
    Evidence,
    Effects,
    PolicyDecision,
    Scope,
    Severity,
    stable_digest,
)

SHELL_OPERATORS = {"&&", "||", "|", ";"}
SHELL_METACHAR_RE = re.compile(r"[;&<>`$()\\]")

API_KEY_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "Anthropic API key"),
    (re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"), "OpenAI project API key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub personal access token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{40,}"), "GitHub fine-grained token"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "AWS access key ID"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API key"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"), "Stripe live secret key"),
    (re.compile(r"sk_test_[A-Za-z0-9]{24,}"), "Stripe test secret key"),
)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")
BEARER_RE = re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}", re.I)
CONNECTION_STRING_RE = re.compile(r"(?:postgresql|postgres|mysql|mongodb(?:\+srv)?|redis|amqps?|smtps?)://[^@\s]+@", re.I)

ENV_FILE_RE = re.compile(r"(?:^|[\s/\\])\.env(?:[\s.]|$)")
SECRET_FILE_RE = re.compile(r"(?:^|[\s/\\])(?:id_rsa|credentials)(?:$|[\s/\\])|\.(?:pem|key|p12|pfx)(?:$|\s)", re.I)

INFRA_TOOLS = {"kubectl", "terraform", "tofu", "aws", "gcloud", "az", "helm"}
DB_TOOLS = {"psql", "mysql", "sqlite3", "pgcli", "clickhouse-client"}
PACKAGE_TOOLS = {"npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "gem", "twine"}


@dataclass(frozen=True)
class PolicyContext:
    tool: str | None
    action_class: ActionClass
    tool_input: dict[str, Any]
    tool_output: dict[str, Any] | None = None
    repo: str | None = None
    branch: str | None = None
    commit: str | None = None
    cwd: str | None = None
    session_id: str | None = None
    agent_id: str | None = None
    task_id: str | None = None

    @property
    def command(self) -> str:
        value = self.tool_input.get("command", "")
        return value if isinstance(value, str) else ""

    @property
    def file_path(self) -> str:
        value = self.tool_input.get("file_path") or self.tool_input.get("path") or ""
        return value if isinstance(value, str) else ""

    def evidence(self, action_class: ActionClass | None = None) -> Evidence:
        return Evidence(
            repo=self.repo,
            branch=self.branch,
            commit=self.commit,
            cwd=self.cwd,
            tool=self.tool,
            actionClass=action_class or self.action_class,
            inputDigest=stable_digest(self.tool_input),
            outputDigest=stable_digest(self.tool_output) if self.tool_output is not None else None,
            sessionId=self.session_id,
            agentId=self.agent_id,
            taskId=self.task_id,
        )


@dataclass(frozen=True)
class BaselinePolicy:
    policy_id: str
    description: str
    evaluate: Callable[[PolicyContext], PolicyDecision | None]


def _decision(
    ctx: PolicyContext,
    *,
    policy_id: str,
    decision: Decision,
    severity: Severity,
    reason: str,
    remediation: str,
    action_class: ActionClass | None = None,
    scope: Scope = Scope.REPO,
) -> PolicyDecision:
    return PolicyDecision.create(
        policy_id=policy_id,
        decision=decision,
        severity=severity,
        scope=scope,
        reason=reason,
        remediation=remediation,
        evidence=ctx.evidence(action_class),
    )


def command_tokens(command: str) -> list[str]:
    """Parse a shell-like command into tokens.

    This is not a full shell AST. It is a conservative token pass used before
    policy matching. If parsing fails, fall back to whitespace splitting so the
    command is still inspectable.
    """

    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def first_command_token(command: str) -> str:
    tokens = command_tokens(command)
    return tokens[0] if tokens else ""


def has_shell_injection(command: str) -> bool:
    tokens = command_tokens(command)
    if any(token in SHELL_OPERATORS for token in tokens):
        return True
    return any(SHELL_METACHAR_RE.search(token) for token in tokens)


def output_text(ctx: PolicyContext) -> str:
    if ctx.tool_output is None:
        return ""
    return str(ctx.tool_output)


def policy_shell_operator_injection(ctx: PolicyContext) -> PolicyDecision | None:
    if ctx.tool != "Bash" or not ctx.command:
        return None
    if has_shell_injection(ctx.command):
        return _decision(
            ctx,
            policy_id="sourceos/shell/block-operator-injection",
            decision=Decision.DENY,
            severity=Severity.HIGH,
            reason="Command contains shell operators or embedded metacharacters that can bypass allowlist checks.",
            remediation="Split the operation into a single explicit command or request human approval for chained shell execution.",
            action_class=ActionClass.SHELL,
        )
    return None


def policy_block_privilege_escalation(ctx: PolicyContext) -> PolicyDecision | None:
    if ctx.tool != "Bash" or not ctx.command:
        return None
    lowered = ctx.command.lower().strip()
    if lowered.startswith("sudo ") or lowered.startswith("runas ") or "start-process" in lowered and "-verb runas" in lowered:
        return _decision(
            ctx,
            policy_id="sourceos/shell/block-privilege-escalation",
            decision=Decision.DENY,
            severity=Severity.CRITICAL,
            reason="Privilege escalation is blocked for autonomous agent sessions.",
            remediation="Use a human-approved scoped task, a prepared dev container, or an AgentPlane executor profile with explicit authority.",
            action_class=ActionClass.SHELL,
            scope=Scope.RUNTIME,
        )
    return None


def policy_block_download_pipe_shell(ctx: PolicyContext) -> PolicyDecision | None:
    if ctx.tool != "Bash" or not ctx.command:
        return None
    lowered = ctx.command.lower()
    if ("curl" in lowered or "wget" in lowered or "invoke-webrequest" in lowered or "invoke-restmethod" in lowered) and (
        "| sh" in lowered or "| bash" in lowered or "| zsh" in lowered or "| iex" in lowered or "invoke-expression" in lowered
    ):
        return _decision(
            ctx,
            policy_id="sourceos/shell/block-download-pipe-exec",
            decision=Decision.DENY,
            severity=Severity.CRITICAL,
            reason="Downloaded content is being piped directly to a shell or evaluator.",
            remediation="Download to a file, inspect/checksum it, and run only reviewed commands in a controlled environment.",
            action_class=ActionClass.SHELL,
        )
    return None


def policy_block_secret_file_access(ctx: PolicyContext) -> PolicyDecision | None:
    path = ctx.file_path
    command = ctx.command
    combined = f"{path} {command}"
    if not combined.strip():
        return None
    if ENV_FILE_RE.search(combined) or SECRET_FILE_RE.search(combined):
        return _decision(
            ctx,
            policy_id="sourceos/secrets/block-secret-file-access",
            decision=Decision.DENY,
            severity=Severity.CRITICAL,
            reason="The action references .env or secret-adjacent files.",
            remediation="Use a scoped secret broker or ask a human to provide a redacted value. Do not read or write raw secrets from the repo.",
            action_class=ActionClass.FILESYSTEM,
        )
    return None


def policy_block_environment_dump(ctx: PolicyContext) -> PolicyDecision | None:
    if ctx.tool != "Bash" or not ctx.command:
        return None
    lowered = ctx.command.lower().strip()
    if lowered in {"env", "printenv", "set"} or lowered.startswith("env ") or lowered.startswith("printenv "):
        return _decision(
            ctx,
            policy_id="sourceos/secrets/block-environment-dump",
            decision=Decision.DENY,
            severity=Severity.HIGH,
            reason="Broad environment variable dumps can expose secrets.",
            remediation="Request the specific non-secret variable needed, or use a redacted environment inspection policy.",
            action_class=ActionClass.SHELL,
        )
    if "echo $" in lowered or "echo %" in lowered or "$env:" in lowered:
        return _decision(
            ctx,
            policy_id="sourceos/secrets/block-env-var-echo",
            decision=Decision.DENY,
            severity=Severity.HIGH,
            reason="Command attempts to echo an environment variable.",
            remediation="Use a scoped non-secret variable lookup or ask the human to provide a redacted value.",
            action_class=ActionClass.SHELL,
        )
    return None


def policy_redact_secret_output(ctx: PolicyContext) -> PolicyDecision | None:
    text = output_text(ctx)
    if not text:
        return None
    detectors: Iterable[tuple[re.Pattern[str], str]] = (
        *API_KEY_PATTERNS,
        (JWT_RE, "JWT"),
        (PRIVATE_KEY_RE, "private key"),
        (BEARER_RE, "bearer token"),
        (CONNECTION_STRING_RE, "credentialed connection string"),
    )
    for pattern, label in detectors:
        if pattern.search(text):
            return _decision(
                ctx,
                policy_id="sourceos/secrets/redact-secret-output",
                decision=Decision.REDACT,
                severity=Severity.CRITICAL,
                reason=f"Tool output appears to contain a {label}.",
                remediation="Suppress the raw output, record only redaction evidence, rotate the exposed credential if it reached any non-local surface.",
                action_class=ActionClass.FILESYSTEM,
            )
    return None


def policy_git_protected_branch(ctx: PolicyContext) -> PolicyDecision | None:
    if ctx.tool != "Bash" or not ctx.command:
        return None
    branch = (ctx.branch or "").lower()
    command = ctx.command.lower()
    protected = branch in {"main", "master", "trunk", "prod", "production"}
    mutating = any(token in command for token in ("git commit", "git merge", "git rebase", "git cherry-pick", "git push"))
    if protected and mutating:
        return _decision(
            ctx,
            policy_id="sourceos/git/block-protected-branch-mutation",
            decision=Decision.DENY,
            severity=Severity.CRITICAL,
            reason=f"Git mutation attempted on protected branch '{ctx.branch}'.",
            remediation="Create a feature branch or AgentPlane workcell branch, then replay the action there.",
            action_class=ActionClass.GIT,
        )
    return None


def policy_git_force_push(ctx: PolicyContext) -> PolicyDecision | None:
    if ctx.tool != "Bash" or "git push" not in ctx.command.lower():
        return None
    tokens = command_tokens(ctx.command)
    if "--force" in tokens or "--force-with-lease" in tokens or "-f" in tokens:
        return _decision(
            ctx,
            policy_id="sourceos/git/block-force-push",
            decision=Decision.DENY,
            severity=Severity.CRITICAL,
            reason="Force push is blocked for autonomous agent sessions.",
            remediation="Open a PR or request a signed human override with the exact branch and reason.",
            action_class=ActionClass.GIT,
        )
    return None


def policy_git_risky_history(ctx: PolicyContext) -> PolicyDecision | None:
    command = ctx.command.lower()
    if ctx.tool != "Bash" or not command:
        return None
    if "git commit" in command and "--amend" in command:
        reason = "Git amend rewrites local history."
    elif "git stash drop" in command or "git stash clear" in command:
        reason = "Git stash deletion can destroy unrecovered work."
    elif "git add ." in command or "git add -a" in command or "git add --all" in command:
        reason = "Broad staging can accidentally include unrelated or generated files."
    else:
        return None
    return _decision(
        ctx,
        policy_id="sourceos/git/instruct-risky-history-or-staging",
        decision=Decision.INSTRUCT,
        severity=Severity.MEDIUM,
        reason=reason,
        remediation="Inspect the diff and stage only intentional paths before continuing.",
        action_class=ActionClass.GIT,
    )


def policy_package_global_install_or_publish(ctx: PolicyContext) -> PolicyDecision | None:
    if ctx.tool != "Bash" or not ctx.command:
        return None
    command = ctx.command.lower()
    first = first_command_token(command)
    if first not in PACKAGE_TOOLS:
        return None
    if " publish" in command or " upload" in command or "gem push" in command:
        return _decision(
            ctx,
            policy_id="sourceos/package/block-publish",
            decision=Decision.ESCALATE,
            severity=Severity.CRITICAL,
            reason="Package publication is an external action requiring human authority.",
            remediation="Create a release PR/artifact and request explicit publication approval.",
            action_class=ActionClass.PACKAGE,
        )
    if " -g" in command or " --global" in command or " global " in command or command.startswith("cargo install"):
        return _decision(
            ctx,
            policy_id="sourceos/package/instruct-global-install",
            decision=Decision.INSTRUCT,
            severity=Severity.MEDIUM,
            reason="Global package installation mutates the developer machine outside the repo boundary.",
            remediation="Prefer a repo-local tool, virtual environment, Nix dev shell, or containerized AgentPlane executor.",
            action_class=ActionClass.PACKAGE,
        )
    return None


def policy_infra_mutation_escalates(ctx: PolicyContext) -> PolicyDecision | None:
    if ctx.tool != "Bash" or not ctx.command:
        return None
    tokens = command_tokens(ctx.command.lower())
    if not tokens:
        return None
    first = tokens[0]
    if first not in INFRA_TOOLS and first != "gh":
        return None
    mutating_terms = {
        "apply",
        "destroy",
        "delete",
        "create",
        "patch",
        "replace",
        "rollout",
        "scale",
        "set",
        "merge",
        "workflow",
        "run",
        "rerun",
        "cancel",
        "release",
        "secret",
    }
    if any(term in tokens for term in mutating_terms):
        return _decision(
            ctx,
            policy_id="sourceos/infra/escalate-mutation",
            decision=Decision.ESCALATE,
            severity=Severity.CRITICAL,
            reason="Infrastructure or pipeline mutation requires scoped human approval.",
            remediation="Run a read-only inspection or plan first, then request approval with account, resource, command, and rollback evidence.",
            action_class=ActionClass.INFRA,
            scope=Scope.RUNTIME,
        )
    return None


def policy_database_destructive_sql(ctx: PolicyContext) -> PolicyDecision | None:
    if ctx.tool != "Bash" or not ctx.command:
        return None
    command = ctx.command.lower()
    if first_command_token(command) not in DB_TOOLS:
        return None
    destructive = "drop table" in command or "drop database" in command or "truncate" in command
    delete_without_where = "delete from" in command and " where " not in command
    alter_schema = "alter table" in command and any(term in command for term in ("drop column", "rename", "modify column"))
    if destructive or delete_without_where or alter_schema:
        return _decision(
            ctx,
            policy_id="sourceos/database/escalate-destructive-sql",
            decision=Decision.ESCALATE,
            severity=Severity.CRITICAL,
            reason="Destructive or schema-altering database operation detected.",
            remediation="Generate a migration/rollback plan and request scoped human approval before execution.",
            action_class=ActionClass.DATABASE,
        )
    return None


def baseline_policies() -> list[BaselinePolicy]:
    return [
        BaselinePolicy("sourceos/shell/block-privilege-escalation", "Block privilege escalation.", policy_block_privilege_escalation),
        BaselinePolicy("sourceos/shell/block-download-pipe-exec", "Block downloaded content piped to execution.", policy_block_download_pipe_shell),
        BaselinePolicy("sourceos/secrets/block-secret-file-access", "Block .env and secret-adjacent file access.", policy_block_secret_file_access),
        BaselinePolicy("sourceos/secrets/block-environment-dump", "Block broad environment dumps.", policy_block_environment_dump),
        BaselinePolicy("sourceos/secrets/block-env-var-echo", "Block direct environment-variable echo.", policy_block_environment_dump),
        BaselinePolicy("sourceos/secrets/redact-secret-output", "Redact secret-bearing outputs.", policy_redact_secret_output),
        BaselinePolicy("sourceos/git/block-protected-branch-mutation", "Block mutation on protected branches.", policy_git_protected_branch),
        BaselinePolicy("sourceos/git/block-force-push", "Block force push.", policy_git_force_push),
        BaselinePolicy("sourceos/git/instruct-risky-history-or-staging", "Instruct on risky Git history or staging operations.", policy_git_risky_history),
        BaselinePolicy("sourceos/package/block-publish", "Escalate package publication.", policy_package_global_install_or_publish),
        BaselinePolicy("sourceos/package/instruct-global-install", "Instruct on global package installs.", policy_package_global_install_or_publish),
        BaselinePolicy("sourceos/infra/escalate-mutation", "Escalate infrastructure and pipeline mutation.", policy_infra_mutation_escalates),
        BaselinePolicy("sourceos/database/escalate-destructive-sql", "Escalate destructive SQL.", policy_database_destructive_sql),
        BaselinePolicy("sourceos/shell/block-operator-injection", "Block shell operator/metacharacter bypasses.", policy_shell_operator_injection),
    ]


def evaluate_baseline(ctx: PolicyContext) -> PolicyDecision:
    """Evaluate baseline policies and return the first material decision.

    Deny, quarantine, defer, escalate, and redact decisions short-circuit. Instruct
    decisions return immediately for now; a later policy engine can accumulate
    multiple instruct/allow-with-context messages.
    """

    for policy in baseline_policies():
        decision = policy.evaluate(ctx)
        if decision is not None:
            return decision
    return PolicyDecision.create(
        policy_id="sourceos/core/baseline-allow",
        decision=Decision.ALLOW,
        severity=Severity.INFO,
        scope=Scope.REPO,
        reason="No baseline guardrail policy blocked this event.",
        remediation="Continue. Add a specific repo/org policy if this action should be constrained.",
        evidence=ctx.evidence(),
    )
