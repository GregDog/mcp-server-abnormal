# Publishing

Tagged releases (`v*`) trigger GoReleaser via `.github/workflows/release.yml`.

Artifacts:

- GitHub Release binaries and checksums
- GHCR images: `ghcr.io/gregdog/mcp-server-abnormal`
- MCP Registry: `io.github.GregDog/mcp-server-abnormal`

Before tagging, update `server.json` version if needed. The release workflow syncs the OCI identifier from the tag.

```bash
git tag v0.1.0
git push origin v0.1.0
```
