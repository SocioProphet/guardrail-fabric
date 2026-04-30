.PHONY: validate test emit-demo-decision release-dry-run

validate:
	python3 tools/validate_guardrail_examples.py

test:
	python3 -m pytest -q tools/tests

emit-demo-decision:
	python3 tools/guardrail_fabric.py emit-demo-decision --output dist/guardrail-decision.demo.json
	@cat dist/guardrail-decision.demo.json

release-dry-run: validate test
	python3 tools/release_dry_run.py
