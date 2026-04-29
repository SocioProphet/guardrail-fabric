.PHONY: validate test emit-demo-decision

validate:
	python3 tools/validate_guardrail_examples.py

test:
	python3 -m pytest -q tools/tests

emit-demo-decision:
	python3 tools/guardrail_fabric.py emit-demo-decision --output dist/guardrail-decision.demo.json
	@cat dist/guardrail-decision.demo.json
