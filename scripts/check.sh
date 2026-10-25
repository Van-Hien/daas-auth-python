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

gates=(
  "mypy|uv run mypy src"
  "ruff|uv run ruff check"
  "format|uv run ruff format --check"
  "imports|uv run lint-imports"
  "pytest|uv run pytest"
)

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
exit "$failed"
