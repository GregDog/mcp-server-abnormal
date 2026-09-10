# Contributing

Thanks for considering a contribution.

This is a small MCP server. Prefer a narrow change that is easy to review.

## Governance

The repository is maintained by [@GregDog](https://github.com/GregDog). Pull requests are reviewed on a best-effort basis.

## How to contribute

1. **Check existing work** — search [open issues](https://github.com/GregDog/mcp-server-abnormal/issues) and open PRs.
2. **Fork** the repository on GitHub.
3. **Clone** your fork and create a branch from `main`.
4. **Install Go 1.27** — required by `go.mod`.
5. **Develop and test** locally (see [docs/development.md](docs/development.md)).
6. **Push** to your fork and **open a pull request** against `main` on `GregDog/mcp-server-abnormal`.
7. Ensure **CI passes** (`gofmt`, `go vet`, `go test`, `go build`, `govulncheck`).

For new MCP tools, follow [docs/adding-tools.md](docs/adding-tools.md).

## Before you start

- Read [docs/architecture.md](docs/architecture.md).
- Do not invent Abnormal API behaviour. Verify against the official SwaggerHub spec.
- Response and evidence tools must stay opt-in.
- Do not commit secrets, `.env`, or `.local/` test artifacts.

## Development

```bash
make test   # unit tests — no Abnormal token required
make check  # fmt, vet, test
make build
```
