.PHONY: install check convert test coverage lab-validate

install:
	pip install -r requirements.txt

check:            ## lint rules with sigma-cli (same as CI)
	sigma check --fail-on-issues rules/

convert:          ## prove rules compile for Splunk
	sigma convert -t splunk -p splunk_windows rules/ > /dev/null

test:             ## sample-log tests + metadata hygiene
	python -m pytest -q

coverage:         ## ATT&CK coverage table + Navigator layer
	python tools/coverage_report.py --navigator attack-layer.json

lab-validate:     ## usage: make lab-validate EVENTS=lab/results/<run>/events.jsonl
	python tools/validate_lab.py $(EVENTS)
