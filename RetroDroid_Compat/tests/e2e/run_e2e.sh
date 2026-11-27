#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="$(command -v python3)"
fi

TIER="all"
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier|-t)
      if [[ $# -lt 2 ]]; then
        echo "Error: --tier requires a value (1|2|3|4|5|all)" >&2
        exit 2
      fi
      TIER="$2"
      shift 2
      ;;
    --tier=*)
      TIER="${1#*=}"
      shift
      ;;
    -h|--help)
      echo "Usage: bash tests/e2e/run_e2e.sh [--tier 1|2|3|4|5|all] [pytest args...]"
      exit 0
      ;;
    *)
      EXTRA_ARGS+=("$1")
      shift
      ;;
  esac
done

case "${TIER}" in
  1) TARGETS=("${SCRIPT_DIR}/test_tier1_features.py") ;;
  2) TARGETS=("${SCRIPT_DIR}/test_tier2_boundaries.py") ;;
  3) TARGETS=("${SCRIPT_DIR}/test_tier3_interactions.py") ;;
  4) TARGETS=("${SCRIPT_DIR}/test_tier4_workloads.py") ;;
  5) TARGETS=("${SCRIPT_DIR}/test_tier5_adversarial.py") ;;
  all)
    TARGETS=(
      "${SCRIPT_DIR}/test_tier1_features.py"
      "${SCRIPT_DIR}/test_tier2_boundaries.py"
      "${SCRIPT_DIR}/test_tier3_interactions.py"
      "${SCRIPT_DIR}/test_tier4_workloads.py"
      "${SCRIPT_DIR}/test_tier5_adversarial.py"
    )
    ;;
  *)
    echo "Error: unknown tier '${TIER}'. Expected one of: 1, 2, 3, 4, 5, all." >&2
    exit 2
    ;;
esac

RUN_TMP="$(mktemp -d -- "${TMPDIR:-/tmp}/retrodroid_e2e.XXXXXX")"
chmod 700 "${RUN_TMP}"
trap 'rm -rf "${RUN_TMP}"' EXIT

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPYCACHEPREFIX="${RUN_TMP}/pycache"
export PYTHONPATH="${REPO_ROOT}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/ms-playwright}"

echo "=== RetroDroid Compat v5.4.0 E2E Runner (tier=${TIER}) ==="
"${PYTHON_BIN}" -B -m pytest \
  -v \
  -p no:cacheprovider \
  --basetemp="${RUN_TMP}/pytest" \
  "${TARGETS[@]}" \
  "${EXTRA_ARGS[@]}"
