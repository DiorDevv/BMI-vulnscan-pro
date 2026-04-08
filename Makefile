.PHONY: install test lint scan-dvwa clean format type-check

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=vulnscan --cov-report=term --asyncio-mode=auto

lint:
	ruff check vulnscan/ && ruff check tests/

format:
	ruff format vulnscan/ tests/

type-check:
	mypy vulnscan/ --strict

scan-dvwa:
	docker compose -f docker-compose.dvwa.yml up

clean:
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf .mypy_cache .ruff_cache .pytest_cache htmlcov .coverage

check: lint type-check test
