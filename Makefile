# f8 test suite
#
# Usage:
#   make test          Run all tests (unit + integration, no root needed)
#   make test-unit     Run unit tests only
#   make test-cov      Run with coverage report
#   make test-e2e      Run end-to-end tests (requires sudo)
#   make verify        Quick validation: categories, colors, no duplicates

.PHONY: test test-unit test-cov test-e2e verify clean

test:
	python3 -m pytest tests/ -v

test-unit:
	python3 -m pytest tests/unit/ -v

test-cov:
	python3 -m pytest tests/ -v --cov=. --cov-report=term-missing \
		--cov-config=.coveragerc

test-e2e:
	@echo "E2E tests require sudo and will trace real programs."
	sudo python3 -m pytest tests/e2e/ -v

verify:
	python3 f8_categories.py --verify

clean:
	rm -rf .pytest_cache tests/__pycache__ tests/unit/__pycache__ \
		tests/integration/__pycache__ .coverage htmlcov/
