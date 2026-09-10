package tools

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

// Register adds Abnormal MCP tools to the server.
func Register(server *mcp.Server, api abnormal.API, opts Options) {
	h := &handlers{api: api}
	registerThreats(server, h)
	registerSearch(server, h)
	registerMessages(server, h)
	registerMailbox(server, h)
	// Response and evidence tools are registered in later phases behind opts.AllowResponse / opts.AllowEvidenceDownload.
}

type handlers struct {
	api abnormal.API
}
