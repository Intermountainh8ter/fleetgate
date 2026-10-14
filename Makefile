PY ?= python
MMDC ?=

.PHONY: help install lint test cov docs docs-check diagrams evals evals-quick gate quality check clean docker

help:
	@echo "targets: install lint test cov docs docs-check diagrams evals evals-quick gate quality check clean docker"

install:
	$(PY) -m pip install -e ".[dev]"

lint:
	ruff check .

test:
	$(PY) -m pytest -q

cov:
	$(PY) -m pytest -q --cov --cov-report=term --cov-fail-under=90

docs:
	$(PY) scripts/gen_docs.py

docs-check:
	$(PY) scripts/gen_docs.py --check

diagrams:
	MMDC="$(MMDC)" bash scripts/render_diagrams.sh

evals:
	$(PY) evals/run_evals.py

evals-quick:
	$(PY) evals/run_evals.py --quick --no-write

gate:
	$(PY) evals/regression_gate.py

quality:
	$(PY) scripts/record_quality.py

check: lint cov docs-check

clean:
	rm -rf .pytest_cache .ruff_cache .coverage coverage.xml htmlcov build dist src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

docker:
	docker build -t fleetgate .
