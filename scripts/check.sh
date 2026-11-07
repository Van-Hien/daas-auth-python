#!/usr/bin/env bash
# Run every gate, even after one fails, then print one summary line per gate.
# Exit code is 0 only if all gates passed, so `make check` still fails.
set -u

# Colours only on a terminal, and not if NO_COLOR is set (no-color.org).
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  green=$'\e[32m' red=$'\e[31m' reset=$'\e[0m'
else
  green='' red='' reset=''
fi

# pip-audit gate: §11.1 of WHY-REWRITE.md measured 33 open advisories in PHP's locked
# dependency set because no recurring audit gate existed. This gate turns the audit
# from a one-time snapshot into a commit-blocking check so the Python rewrite cannot
# drift the same way.
gates=(
  "mypy|uv run mypy src tests"
  "ruff|uv run ruff check"
  "format|uv run ruff format --check"
  "imports|uv run lint-imports"
  "pytest|DAAS_AUTH_REQUIRE_MARIADB=1 uv run pytest"
  "pip-audit|uv run pip-audit"
)

# The tests' own MariaDB lives only for this run. If it can't start, pytest fails.
trap 'docker compose --profile test rm -fsv mariadb-test >/dev/null 2>&1' EXIT
docker compose --profile test up -d --wait mariadb-test >/dev/null 2>&1

summary=()
failed=0
for gate in "${gates[@]}"; do
  name=${gate%%|*}   # text before the |
  cmd=${gate#*|}     # text after the |
  printf '\n===== %s: %s =====\n' "$name" "$cmd"
  if bash -c "$cmd"; then
    summary+=("${green}PASS${reset}  $name")
  else
    summary+=("${red}FAIL${reset}  $name    -> scroll up to '===== $name'")
    failed=1
  fi
done

printf '\n===== summary =====\n'
printf '%s\n' "${summary[@]}"

# Source - https://stackoverflow.com/a/35619927
# Posted by Bruce
# Retrieved 2026-11-02, License - CC BY-SA 3.0

#!/bin/bash

current_date_time="`date +"%c"`";

printf "\nmake check ran on \n\t${green}${current_date_time}${reset}\n"

exit "$failed"
