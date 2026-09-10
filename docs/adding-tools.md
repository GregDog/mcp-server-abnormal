# Adding a tool

Read [architecture.md](architecture.md) first.

## Rules

- Verify behaviour against the [official Abnormal Client API](https://app.swaggerhub.com/apis-docs/abnormal-security/abx/1.4.3). Do not invent endpoints.
- Read tools are always registered. Response tools stay behind `ABNORMAL_ALLOW_RESPONSE`. Evidence download tools stay behind `ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD`.
- High-impact mutations require `confirm: true`.
- Update [tools.md](tools.md), [security.md](security.md), and the README tool table.

## Layout

| Path | Role |
| --- | --- |
| `internal/tools/<domain>.go` | Read tools |
| `internal/tools/register.go` | Registration and capability gating |
| `internal/tools/addtool.go` | Typed `addTool` helper |
| `internal/abnormal/client.go` | `API` interface |
| `internal/tools/*_test.go` | Handler tests with `fakeAPI` |

## Checklist

1. Add method(s) to `API` in `internal/abnormal/client.go`.
2. Add handler(s) with `addTool` and `readOnly()` (or response/evidence annotations).
3. Register in `register.go`.
4. Extend `fakeAPI` and add tests.
5. Document in `docs/tools.md` and README.
