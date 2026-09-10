#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
	echo "error: .env not found" >&2
	exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

if [[ -z "${ABNORMAL_API_TOKEN:-}" ]]; then
	echo "error: ABNORMAL_API_TOKEN is empty" >&2
	exit 1
fi

go run ./scripts/test-phase34/main.go
