#!/usr/bin/env bash
# Quick live API check using .env credentials. Does not print tokens.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
	echo "error: .env not found (copy .env.example and add your token)" >&2
	exit 1
fi

if [[ ! -x bin/abnormal-mcp ]]; then
	echo "building bin/abnormal-mcp..."
	make build
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

if [[ -z "${ABNORMAL_API_TOKEN:-}" ]]; then
	echo "error: ABNORMAL_API_TOKEN is empty in .env" >&2
	exit 1
fi

echo "abnormal-mcp: $(./bin/abnormal-mcp version)"
echo "base_url: ${ABNORMAL_BASE_URL:-https://api.abnormalplatform.com/v1}"
echo "token: set (prefix $(printf '%.4s' "$ABNORMAL_API_TOKEN")..., length ${#ABNORMAL_API_TOKEN})"
echo
echo "calling ListThreats (limit 1)..."

go run ./scripts/test-access/main.go
