.PHONY: install test lint type check demo clean

install:
	pip install -e ".[dev]"

test:
	pytest --cov=condor_scan --cov-report=term-missing

lint:
	ruff check src tests

type:
	mypy

# Full quality gate: lint, types, and tests must all pass.
check: lint type test

demo:
	condor-scan scan examples/sample_export.json --format table

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
