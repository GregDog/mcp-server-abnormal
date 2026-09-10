package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

// Register adds Abnormal MCP tools to the server.
func Register(server *mcp.Server, api abnormal.API, opts Options) {
	h := &handlers{
		api:                   api,
		allowResponse:         opts.AllowResponse,
		allowEvidenceDownload: opts.AllowEvidenceDownload,
	}
	registerThreats(server, h)
	registerSearch(server, h)
	registerMessages(server, h)
	registerMailbox(server, h)
	registerEmployees(server, h)
	registerCases(server, h)
	registerVendors(server, h)
	if opts.AllowEvidenceDownload {
		registerEvidence(server, h)
	}
	if opts.AllowResponse {
		registerResponse(server, h)
		registerCaseResponse(server, h)
	}
}

type handlers struct {
	api                   abnormal.API
	allowResponse         bool
	allowEvidenceDownload bool
}
