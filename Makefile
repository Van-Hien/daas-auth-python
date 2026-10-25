# One command for the gates every commit must pass
# Recipe lines start with a TAB, not spaces.
.PHONY: check fmt

check: ## run the five gates; stops at the first failure
	uv run mypy src
	uv run ruff check
	uv run ruff format --check
	uv run lint-imports
	uv run pytest

fmt: ## rewrite files: format, then apply ruff's safe fixes
	uv run ruff format
	uv run ruff check --fix
