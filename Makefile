.PHONY: ci-lint ci-test

ci-lint:
	uv run ruff check .
	uv run ruff format --check .

ci-test:
	uv run pytest packages/autobot/tests
