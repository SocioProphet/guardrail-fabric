"""TrustOps safety preflight decisions for governed runtime admission.

Safety preflight runs before any effectful agent/runtime attempt. It produces a
provider-neutral TrustOps gate decision that can be consumed by the runtime
action mapper in :mod:`guardrail_fabric.trustops_runtime_actions`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping

from .trustops_runtime_actions import (
    RuntimeGuardrailDecision,
    TrustOpsGateDecision,
    TrustOpsOutcome,
    map_trustops_to_runtime_action,
)


class NetworkMode(str, Enum):
    """Network policy for verifier/runtime preflight."""

    OFF = "off"
    ALLOWLISTED = "allowlisted"
    OPEN = "open"


class SafetyViolationKind(str, Enum):
    """Machine-readable safety preflight violation classes."""

    COMMAND_BLOCKED = "command_blocked"
    PATH_OUTSIDE_REPO = "path_outside_repo"
    PATH_NOT_ALLOWED = "path_not_allowed"
    PATH_DENIED = "path_denied"
    NETWORK_BLOCKED = "network_blocked"
    DEPENDENCY_APPROVAL_REQUIRED = "dependency_approval_required"
    MIGRATION_APPROVAL_REQUIRED = "migration_approval_required"
    CONFIG_APPROVAL_REQUIRED = "config_approval_required"
    SECRET_VALUE = "secret_value"
    PROTECTED_PATH = "protected_path"


@dataclass(frozen=True)
class SafetyPreflightViolation:
    """One safety preflight finding."""

    kind: SafetyViolationKind
    gate_id: str
    outcome: TrustOpsOutcome
    message: str
    evidence_ref: str
    command: str | None = None
    file: str | None = None
    match: str | None = None

    def to_dict(self) -> dict[str, str]:
        data = {
            "kind": self.kind.value,
            "gate_id": self.gate_id,
            "outcome": self.outcome.value,
            "message": self.message,
            "evidence_ref": self.evidence_ref,
        }
        if self.command is not None:
            data["command"] = self.command
        if self.file is not None:
            data["file"] = self.file
        if self.match is not None:
            data["match"] = self.match
        return data


@dataclass(frozen=True)
class SafetyPreflightDecision:
    """Safety preflight result before runtime admission."""

    receipt_id: str
    outcome: TrustOpsOutcome
    reason: str
    violations: tuple[SafetyPreflightViolation, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.outcome is TrustOpsOutcome.PASS

    def to_trustops_gate_decision(self) -> TrustOpsGateDecision:
        gate_id = (
            self.violations[0].gate_id
            if self.violations
            else "gate://trustops/safety-preflight/pass"
        )
        evidence_refs = tuple(
            violation.evidence_ref for violation in self.violations
        ) or ("evidence://trustops/safety-preflight/pass",)
        return TrustOpsGateDecision(
            outcome=self.outcome,
            receipt_id=self.receipt_id,
            gate_id=gate_id,
            evidence_refs=evidence_refs,
        )

    def to_runtime_guardrail_decision(self) -> RuntimeGuardrailDecision:
        return map_trustops_to_runtime_action([self.to_trustops_gate_decision()])

    def to_dict(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt_id,
            "outcome": self.outcome.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "violations": [violation.to_dict() for violation in self.violations],
        }


_BLOCKED_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("recursive_force_delete", re.compile(r"(^|\s)rm\s+-rf(\s|$)", re.I)),
    ("hard_reset", re.compile(r"git\s+reset\s+--hard", re.I)),
    ("git_clean_force", re.compile(r"git\s+clean\s+-f", re.I)),
    ("pipe_to_shell", re.compile(r"(curl|wget)\b[^\n|]*\|\s*(sh|bash)", re.I)),
    ("sudo", re.compile(r"(^|\s)sudo(\s|$)", re.I)),
    ("mkfs", re.compile(r"(^|\s)mkfs(\.|\s|$)", re.I)),
    ("dd_raw_device", re.compile(r"(^|\s)dd\s+if=", re.I)),
    ("system_power", re.compile(r"(shutdown|reboot)(\s|$)", re.I)),
    ("container_destructive", re.compile(r"(kubectl|docker)\s+.*\b(delete|prune|rm)\b", re.I)),
    ("remote_shell", re.compile(r"(^|\s)(ssh|scp)\s+", re.I)),
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_api_key_assignment", re.compile(r"\bOPENAI_API_KEY\s*=\s*[^\s\"'`]+", re.I)),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9_]{8,}\b")),
    ("api_key_like", re.compile(r"\b[A-Z0-9_]*API[_-]?KEY\s*=\s*[^\s\"'`]+", re.I)),
)

_PROTECTED_PATH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("env_file", re.compile(r"(^|/)\.env(?!\.example\b)(?:\.[A-Za-z0-9._-]+)?$", re.I)),
    ("private_key", re.compile(r"(^|/)id_rsa$", re.I)),
    ("key_material", re.compile(r"\.(pem|p12|key)$", re.I)),
)

_NETWORK_COMMAND_RE = re.compile(r"\b(curl|wget|invoke-webrequest|iwr|httpie|http)\b", re.I)
_NETWORK_TARGET_RE = re.compile(r"https?://([^/\s\"'`]+)", re.I)

_DEPENDENCY_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
    "Cargo.lock",
}

_CONFIG_FILES = {
    "vercel.json",
    "netlify.toml",
    "wrangler.toml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "fly.toml",
    "railway.json",
}


def evaluate_safety_preflight(
    *,
    verification_commands: Iterable[str] = (),
    changed_files: Iterable[str] = (),
    allowed_paths: Iterable[str] = (),
    denied_paths: Iterable[str] = (),
    network_mode: NetworkMode | str = NetworkMode.OFF,
    allowed_network_domains: Iterable[str] = (),
    approval_policy: Mapping[str, bool] | None = None,
    text_values: Iterable[str] = (),
    receipt_id: str = "trustops-receipt:safety-preflight",
) -> SafetyPreflightDecision:
    """Evaluate a proposed runtime attempt before execution.

    The function is intentionally pure and filesystem-independent. Callers pass
    verifier commands, proposed changed files, and policy boundaries; the result
    is a TrustOps-compatible receipt decision.
    """

    approvals = dict(approval_policy or {})
    normalized_network_mode = _coerce_network_mode(network_mode)
    violations: list[SafetyPreflightViolation] = []

    for command in verification_commands:
        violations.extend(_evaluate_command(command, normalized_network_mode, allowed_network_domains))

    normalized_allowed = tuple(allowed_paths)
    normalized_denied = tuple(denied_paths)
    for file in changed_files:
        normalized_file = _normalize_path(file)
        violations.extend(_evaluate_file_path(normalized_file, normalized_allowed, normalized_denied))
        violations.extend(_evaluate_change_approval(normalized_file, approvals))

    for value in text_values:
        violations.extend(_evaluate_secret_text(value))

    outcome = _controlling_outcome(violations)
    reason = _reason_for_outcome(outcome, violations)
    return SafetyPreflightDecision(
        receipt_id=receipt_id,
        outcome=outcome,
        reason=reason,
        violations=tuple(violations),
    )


def _evaluate_command(
    command: str,
    network_mode: NetworkMode,
    allowed_network_domains: Iterable[str],
) -> tuple[SafetyPreflightViolation, ...]:
    violations: list[SafetyPreflightViolation] = []
    for label, pattern in _BLOCKED_COMMAND_PATTERNS:
        if pattern.search(command):
            violations.append(
                SafetyPreflightViolation(
                    kind=SafetyViolationKind.COMMAND_BLOCKED,
                    gate_id="gate://trustops/safety-preflight/command-blocked",
                    outcome=TrustOpsOutcome.BLOCK,
                    message=f"Blocked unsafe verifier/runtime command pattern: {label}",
                    evidence_ref=f"evidence://trustops/safety-preflight/command/{label}",
                    command=command,
                    match=label,
                )
            )

    violations.extend(_evaluate_network_targets(command, network_mode, allowed_network_domains))
    violations.extend(_evaluate_secret_text(command))
    return tuple(violations)


def _evaluate_network_targets(
    command: str,
    network_mode: NetworkMode,
    allowed_network_domains: Iterable[str],
) -> tuple[SafetyPreflightViolation, ...]:
    if not _NETWORK_COMMAND_RE.search(command):
        return ()
    targets = tuple(match.group(1).lower() for match in _NETWORK_TARGET_RE.finditer(command))
    if not targets or network_mode is NetworkMode.OPEN:
        return ()

    allowed = tuple(domain.lower() for domain in allowed_network_domains)
    violations: list[SafetyPreflightViolation] = []
    for target in targets:
        if network_mode is NetworkMode.ALLOWLISTED and _domain_allowed(target, allowed):
            continue
        violations.append(
            SafetyPreflightViolation(
                kind=SafetyViolationKind.NETWORK_BLOCKED,
                gate_id="gate://trustops/safety-preflight/network-blocked",
                outcome=TrustOpsOutcome.BLOCK,
                message=f"Network target is not permitted in {network_mode.value} mode: {target}",
                evidence_ref=f"evidence://trustops/safety-preflight/network/{target}",
                command=command,
                match=target,
            )
        )
    return tuple(violations)


def _evaluate_file_path(
    file: str,
    allowed_paths: tuple[str, ...],
    denied_paths: tuple[str, ...],
) -> tuple[SafetyPreflightViolation, ...]:
    violations: list[SafetyPreflightViolation] = []
    if _is_outside_repo(file):
        return (
            SafetyPreflightViolation(
                kind=SafetyViolationKind.PATH_OUTSIDE_REPO,
                gate_id="gate://trustops/safety-preflight/path-outside-repo",
                outcome=TrustOpsOutcome.BLOCK,
                message=f"Changed file is outside the governed repo boundary: {file}",
                evidence_ref=f"evidence://trustops/safety-preflight/path-outside-repo/{file}",
                file=file,
            ),
        )

    for label, pattern in _PROTECTED_PATH_PATTERNS:
        if pattern.search(file):
            violations.append(
                SafetyPreflightViolation(
                    kind=SafetyViolationKind.PROTECTED_PATH,
                    gate_id="gate://trustops/safety-preflight/protected-path",
                    outcome=TrustOpsOutcome.BLOCK,
                    message=f"Changed file targets protected material: {file}",
                    evidence_ref=f"evidence://trustops/safety-preflight/protected-path/{label}",
                    file=file,
                    match=label,
                )
            )

    if any(_path_matches(file, pattern) for pattern in denied_paths):
        violations.append(
            SafetyPreflightViolation(
                kind=SafetyViolationKind.PATH_DENIED,
                gate_id="gate://trustops/safety-preflight/path-denied",
                outcome=TrustOpsOutcome.BLOCK,
                message=f"Changed file matches a denied path: {file}",
                evidence_ref=f"evidence://trustops/safety-preflight/path-denied/{file}",
                file=file,
            )
        )

    if allowed_paths and not any(_path_matches(file, pattern) for pattern in allowed_paths):
        violations.append(
            SafetyPreflightViolation(
                kind=SafetyViolationKind.PATH_NOT_ALLOWED,
                gate_id="gate://trustops/safety-preflight/path-not-allowed",
                outcome=TrustOpsOutcome.BLOCK,
                message=f"Changed file is outside allowed paths: {file}",
                evidence_ref=f"evidence://trustops/safety-preflight/path-not-allowed/{file}",
                file=file,
            )
        )
    return tuple(violations)


def _evaluate_change_approval(
    file: str,
    approvals: Mapping[str, bool],
) -> tuple[SafetyPreflightViolation, ...]:
    leaf = file.rsplit("/", 1)[-1]
    if leaf in _DEPENDENCY_FILES and not approvals.get("dependency_changes", False):
        return (_approval_violation(SafetyViolationKind.DEPENDENCY_APPROVAL_REQUIRED, "dependency", file),)
    if _is_migration_file(file) and not approvals.get("migration_changes", False):
        return (_approval_violation(SafetyViolationKind.MIGRATION_APPROVAL_REQUIRED, "migration", file),)
    if _is_config_file(file) and not approvals.get("config_changes", False):
        return (_approval_violation(SafetyViolationKind.CONFIG_APPROVAL_REQUIRED, "config", file),)
    return ()


def _approval_violation(kind: SafetyViolationKind, label: str, file: str) -> SafetyPreflightViolation:
    return SafetyPreflightViolation(
        kind=kind,
        gate_id=f"gate://trustops/safety-preflight/{label}-approval-required",
        outcome=TrustOpsOutcome.REQUIRE_REVIEW,
        message=f"{label.title()} change requires approval before execution: {file}",
        evidence_ref=f"evidence://trustops/safety-preflight/{label}-approval/{file}",
        file=file,
    )


def _evaluate_secret_text(value: str) -> tuple[SafetyPreflightViolation, ...]:
    violations: list[SafetyPreflightViolation] = []
    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(value):
            violations.append(
                SafetyPreflightViolation(
                    kind=SafetyViolationKind.SECRET_VALUE,
                    gate_id="gate://trustops/safety-preflight/secret-value",
                    outcome=TrustOpsOutcome.BLOCK,
                    message="Secret-like value detected in runtime context.",
                    evidence_ref=f"evidence://trustops/safety-preflight/secret/{label}",
                    match=label,
                )
            )
    return tuple(violations)


def _controlling_outcome(violations: Iterable[SafetyPreflightViolation]) -> TrustOpsOutcome:
    outcomes = tuple(violation.outcome for violation in violations)
    if TrustOpsOutcome.BLOCK in outcomes:
        return TrustOpsOutcome.BLOCK
    if TrustOpsOutcome.REQUIRE_REVIEW in outcomes:
        return TrustOpsOutcome.REQUIRE_REVIEW
    if TrustOpsOutcome.WARN in outcomes:
        return TrustOpsOutcome.WARN
    return TrustOpsOutcome.PASS


def _reason_for_outcome(outcome: TrustOpsOutcome, violations: tuple[SafetyPreflightViolation, ...]) -> str:
    if outcome is TrustOpsOutcome.PASS:
        return "Safety preflight passed."
    return f"Safety preflight produced {outcome.value} with {len(violations)} finding(s)."


def _coerce_network_mode(value: NetworkMode | str) -> NetworkMode:
    if isinstance(value, NetworkMode):
        return value
    try:
        return NetworkMode(str(value))
    except ValueError as exc:
        raise ValueError(f"unknown network mode: {value!r}") from exc


def _normalize_path(value: str) -> str:
    return value.strip().replace("\\", "/")


def _is_outside_repo(file: str) -> bool:
    return file.startswith("/") or file == ".." or file.startswith("../") or "/../" in file


def _path_matches(file: str, pattern: str) -> bool:
    normalized = pattern.strip().replace("\\", "/")
    if normalized.endswith("/**"):
        return file.startswith(normalized[:-3].rstrip("/") + "/")
    if normalized.endswith("*"):
        return file.startswith(normalized.rstrip("*"))
    return file == normalized or file.startswith(normalized.rstrip("/") + "/")


def _domain_allowed(target: str, allowed_domains: tuple[str, ...]) -> bool:
    return any(target == domain or target.endswith(f".{domain}") for domain in allowed_domains)


def _is_migration_file(file: str) -> bool:
    return file.startswith("migrations/") or "/migrations/" in file or "prisma/migrations/" in file


def _is_config_file(file: str) -> bool:
    leaf = file.rsplit("/", 1)[-1]
    return leaf in _CONFIG_FILES or file.startswith((".github/workflows/", "deploy/", "deployment/", "infra/", "infrastructure/", "ops/"))
