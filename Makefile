# One command for the gates every commit must pass
# Recipe lines start with a TAB, not spaces.
.PHONY: check fmt

check: ## run all six gates, then print a summary; fails if any gate failed
	@bash scripts/check.sh


fmt: ## rewrite files: format, then apply ruff's safe fixes
	uv run ruff format
	uv run ruff check --fix
