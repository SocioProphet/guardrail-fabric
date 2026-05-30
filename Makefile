.PHONY: validate test emit-demo-decision release-dry-run validate-superconscious-reasoning-policy validate-preflight-handoff validate-trustops-guardrail-action-decision validate-wallguard-guardrail-binding

validate: validate-superconscious-reasoning-policy validate-preflight-handoff validate-trustops-guardrail-action-decision validate-wallguard-guardrail-binding
	python3 tools/validate_guardrail_examples.py

validate-superconscious-reasoning-policy:
	python3 tools/validate_superconscious_reasoning_policy.py

validate-preflight-handoff:
	python3 -m json.tool tests/fixtures/preflight-handoff/pass-allow.valid.json >/dev/null
	python3 -m json.tool tests/fixtures/preflight-handoff/require-review.valid.json >/dev/null
	python3 -m json.tool tests/fixtures/preflight-handoff/block.valid.json >/dev/null
	python3 -m json.tool tests/fixtures/preflight-handoff/rollback-degraded-to-warn.invalid.json >/dev/null
	python3 -m json.tool tests/fixtures/preflight-handoff/quarantine-missing-evidence.invalid.json >/dev/null
	python3 tools/validate_preflight_handoff.py tests/fixtures/preflight-handoff/pass-allow.valid.json
	python3 tools/validate_preflight_handoff.py tests/fixtures/preflight-handoff/require-review.valid.json
	python3 tools/validate_preflight_handoff.py tests/fixtures/preflight-handoff/block.valid.json
	! python3 tools/validate_preflight_handoff.py tests/fixtures/preflight-handoff/rollback-degraded-to-warn.invalid.json
	! python3 tools/validate_preflight_handoff.py tests/fixtures/preflight-handoff/quarantine-missing-evidence.invalid.json

validate-trustops-guardrail-action-decision:
	python3 -m json.tool schemas/trustops-guardrail-action-decision.v0.1.schema.json >/dev/null
	python3 -m json.tool tests/fixtures/trustops-guardrail-action-decision/block.valid.json >/dev/null
	python3 -m json.tool tests/fixtures/trustops-guardrail-action-decision/authority-mutated.invalid.json >/dev/null
	python3 -m json.tool tests/fixtures/trustops-guardrail-action-decision/rollback-degraded-to-warn.invalid.json >/dev/null
	python3 tools/validate_trustops_guardrail_action_decision.py tests/fixtures/trustops-guardrail-action-decision/block.valid.json
	! python3 tools/validate_trustops_guardrail_action_decision.py tests/fixtures/trustops-guardrail-action-decision/authority-mutated.invalid.json
	! python3 tools/validate_trustops_guardrail_action_decision.py tests/fixtures/trustops-guardrail-action-decision/rollback-degraded-to-warn.invalid.json

validate-wallguard-guardrail-binding:
	python3 -m json.tool schemas/wallguard-guardrail-binding.v0.1.schema.json >/dev/null
	python3 -m json.tool tests/fixtures/wallguard-guardrail-binding/allow.valid.json >/dev/null
	python3 -m json.tool tests/fixtures/wallguard-guardrail-binding/deny-degraded-to-allow.invalid.json >/dev/null
	python3 -m json.tool tests/fixtures/wallguard-guardrail-binding/authority-mutated.invalid.json >/dev/null
	python3 tools/validate_wallguard_guardrail_binding.py


test:
	python3 -m pytest -q tools/tests
	python3 -m pytest -q tests

emit-demo-decision:
	python3 tools/guardrail_fabric.py emit-demo-decision --output dist/guardrail-decision.demo.json
	@cat dist/guardrail-decision.demo.json

release-dry-run: validate test
	python3 tools/release_dry_run.py
