# Development

Requires **Go 1.27** or later.

```bash
cp .env.example .env
# Add ABNORMAL_API_TOKEN

make test    # unit tests — no live token required
make build   # bin/abnormal-mcp
make check   # fmt, vet, test
```

## stdio

```bash
export ABNORMAL_API_TOKEN="..."
./bin/abnormal-mcp serve
```

Or use `scripts/mcp-serve.sh` with a `.env` file.

## HTTP

```bash
export ABNORMAL_API_TOKEN="..."
export ABNORMAL_MCP_TRANSPORT=http
./bin/abnormal-mcp serve
```

## Verify MCP registration

```bash
make build
bash scripts/mcp-verify.sh
```

## Live API smoke test

```bash
make test-access
```

Uses `ABNORMAL_API_TOKEN` from `.env` and calls `ListThreats` with a 24-hour window.
