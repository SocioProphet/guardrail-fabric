.PHONY: validate test emit-demo-decision release-dry-run validate-superconscious-reasoning-policy validate-preflight-handoff

validate: validate-superconscious-reasoning-policy validate-preflight-handoff
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

test:
	python3 -m pytest -q tools/tests
	python3 -m pytest -q tests

emit-demo-decision:
	python3 tools/guardrail_fabric.py emit-demo-decision --output dist/guardrail-decision.demo.json
	@cat dist/guardrail-decision.demo.json

release-dry-run: validate test
	python3 tools/release_dry_run.py