#!/usr/bin/env bash
#
# Convenience runner for the msldap test suite.
#
# Usage:
#   tests/test.sh                 # offline suite + coverage (default, safe)
#   tests/test.sh offline         # same as above
#   tests/test.sh live            # offline + live (needs --run-live target)
#   tests/test.sh destructive     # offline + live + destructive (disposable lab!)
#   tests/test.sh all             # everything incl. slow (bloodhound)
#   tests/test.sh -- <pytest args>  # pass-through arbitrary pytest args
#
# Environment:
#   MSLDAP_TEST_PROFILE   path to a YAML profile (defaults to profile.local.yml
#                         then profile.example.yml under tests/interop/live)
#   MSLDAP_TEST_HOST / MSLDAP_TEST_USERNAME / MSLDAP_TEST_PASSWORD /
#   MSLDAP_TEST_DOMAIN    override individual profile fields.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

MODE="${1:-offline}"
shift || true

COV=(--cov=msldap --cov-branch --cov-report=term-missing --cov-report=html:reports/htmlcov)

case "$MODE" in
  offline)
    exec python3 -m pytest tests/unit "${COV[@]}" "$@"
    ;;
  live)
    exec python3 -m pytest tests "${COV[@]}" --run-live "$@"
    ;;
  destructive)
    exec python3 -m pytest tests "${COV[@]}" --run-live --run-destructive "$@"
    ;;
  all)
    exec python3 -m pytest tests "${COV[@]}" --run-live --run-destructive --run-slow "$@"
    ;;
  --)
    exec python3 -m pytest "$@"
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    echo "Use one of: offline | live | destructive | all | -- <pytest args>" >&2
    exit 2
    ;;
esac
