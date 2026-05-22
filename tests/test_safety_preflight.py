"""Tests for TrustOps safety preflight decisions."""

from __future__ import annotations

from guardrail_fabric.safety_preflight import (
    NetworkMode,
    SafetyViolationKind,
    evaluate_safety_preflight,
)
from guardrail_fabric.trustops_runtime_actions import RuntimeGuardrailAction, TrustOpsOutcome


def test_safe_preflight_passes_and_maps_to_allow() -> None:
    decision = evaluate_safety_preflight(
        verification_commands=("python -m pytest tests/test_safe.py",),
        changed_files=("src/app.py", "tests/test_app.py"),
        allowed_paths=("src/**", "tests/**"),
        denied_paths=(".env*", "secrets/**"),
        network_mode=NetworkMode.OFF,
        text_values=("normal objective",),
    )

    assert decision.allowed is True
    assert decision.outcome == TrustOpsOutcome.PASS
    assert decision.violations == ()
    assert decision.to_runtime_guardrail_decision().action == RuntimeGuardrailAction.ALLOW


def test_destructive_verifier_command_blocks() -> None:
    decision = evaluate_safety_preflight(
        verification_commands=("rm -rf build && pytest",),
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    assert decision.to_runtime_guardrail_decision().action == RuntimeGuardrailAction.BLOCK
    assert decision.violations[0].kind == SafetyViolationKind.COMMAND_BLOCKED


def test_git_reset_hard_blocks() -> None:
    decision = evaluate_safety_preflight(
        verification_commands=("git reset --hard HEAD",),
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    assert any(v.kind == SafetyViolationKind.COMMAND_BLOCKED for v in decision.violations)


def test_path_escape_blocks() -> None:
    decision = evaluate_safety_preflight(
        changed_files=("../outside.py",),
        allowed_paths=("src/**",),
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    assert decision.violations[0].kind == SafetyViolationKind.PATH_OUTSIDE_REPO


def test_denied_path_blocks() -> None:
    decision = evaluate_safety_preflight(
        changed_files=("secrets/prod.key",),
        denied_paths=("secrets/**",),
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    assert any(v.kind == SafetyViolationKind.PATH_DENIED for v in decision.violations)


def test_allowed_path_boundary_blocks_out_of_scope_file() -> None:
    decision = evaluate_safety_preflight(
        changed_files=("docs/notes.md",),
        allowed_paths=("src/**", "tests/**"),
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    assert decision.violations[0].kind == SafetyViolationKind.PATH_NOT_ALLOWED


def test_protected_path_blocks_env_file() -> None:
    decision = evaluate_safety_preflight(
        changed_files=(".env.production",),
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    assert any(v.kind == SafetyViolationKind.PROTECTED_PATH for v in decision.violations)


def test_network_off_blocks_curl_target() -> None:
    decision = evaluate_safety_preflight(
        verification_commands=("curl https://example.com/health",),
        network_mode=NetworkMode.OFF,
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    assert decision.violations[0].kind == SafetyViolationKind.NETWORK_BLOCKED


def test_allowlisted_network_allows_matching_domain() -> None:
    decision = evaluate_safety_preflight(
        verification_commands=("curl https://api.example.com/health",),
        network_mode=NetworkMode.ALLOWLISTED,
        allowed_network_domains=("example.com",),
    )

    assert decision.outcome == TrustOpsOutcome.PASS


def test_allowlisted_network_blocks_nonmatching_domain() -> None:
    decision = evaluate_safety_preflight(
        verification_commands=("curl https://evil.example.net/health",),
        network_mode=NetworkMode.ALLOWLISTED,
        allowed_network_domains=("example.com",),
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    assert decision.violations[0].kind == SafetyViolationKind.NETWORK_BLOCKED


def test_dependency_change_requires_review_without_approval() -> None:
    decision = evaluate_safety_preflight(changed_files=("package.json",))

    assert decision.outcome == TrustOpsOutcome.REQUIRE_REVIEW
    assert decision.to_runtime_guardrail_decision().action == RuntimeGuardrailAction.REQUIRE_REVIEW
    assert decision.violations[0].kind == SafetyViolationKind.DEPENDENCY_APPROVAL_REQUIRED


def test_dependency_change_passes_with_approval() -> None:
    decision = evaluate_safety_preflight(
        changed_files=("package.json",),
        approval_policy={"dependency_changes": True},
    )

    assert decision.outcome == TrustOpsOutcome.PASS


def test_config_change_requires_review_without_approval() -> None:
    decision = evaluate_safety_preflight(changed_files=(".github/workflows/ci.yml",))

    assert decision.outcome == TrustOpsOutcome.REQUIRE_REVIEW
    assert decision.violations[0].kind == SafetyViolationKind.CONFIG_APPROVAL_REQUIRED


def test_migration_change_requires_review_without_approval() -> None:
    decision = evaluate_safety_preflight(changed_files=("db/migrations/001_init.sql",))

    assert decision.outcome == TrustOpsOutcome.REQUIRE_REVIEW
    assert decision.violations[0].kind == SafetyViolationKind.MIGRATION_APPROVAL_REQUIRED


def test_secret_like_text_blocks() -> None:
    decision = evaluate_safety_preflight(
        text_values=("OPENAI_API_KEY=sk-testsecret",),
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    assert decision.violations[0].kind == SafetyViolationKind.SECRET_VALUE


def test_block_dominates_require_review() -> None:
    decision = evaluate_safety_preflight(
        verification_commands=("sudo pytest",),
        changed_files=("package.json",),
    )

    assert decision.outcome == TrustOpsOutcome.BLOCK
    kinds = {violation.kind for violation in decision.violations}
    assert SafetyViolationKind.COMMAND_BLOCKED in kinds
    assert SafetyViolationKind.DEPENDENCY_APPROVAL_REQUIRED in kinds
