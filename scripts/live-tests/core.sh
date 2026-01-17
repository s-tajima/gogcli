#!/usr/bin/env bash

set -euo pipefail

run_core_tests() {
  run_required "time" "time now" "$BIN" time now --json >/dev/null

  if ! skip "auth-alias"; then
    local alias_name
    alias_name="smoke-$TS"
    run_required "auth-alias" "auth alias set" "$BIN" auth alias set "$alias_name" "$ACCOUNT" --json >/dev/null
    run_required "auth-alias" "auth alias list" "$BIN" auth alias list --json >/dev/null
    run_required "auth-alias" "auth alias unset" "$BIN" auth alias unset "$alias_name" --json >/dev/null
  fi

  if ! skip "enable-commands"; then
    run_required "enable-commands" "enable-commands allow time" "$BIN" --enable-commands time time now --json >/dev/null
    if $BIN --enable-commands time gmail labels list >/dev/null 2>&1; then
      echo "Expected enable-commands to block gmail, but it succeeded" >&2
      exit 1
    else
      echo "enable-commands block OK"
    fi
  fi
}
