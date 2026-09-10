package main

import (
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
	"github.com/GregDog/mcp-server-abnormal/internal/config"
	"github.com/GregDog/mcp-server-abnormal/internal/tools"
)

func newMCPServer(cfg config.Config, client abnormal.API) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "abnormal-mcp",
		Title:   "Abnormal MCP Server",
		Version: version,
	}, nil)
	tools.Register(server, client, tools.Options{
		AllowResponse:         cfg.AllowResponse,
		AllowEvidenceDownload: cfg.AllowEvidenceDownload,
	})
	return server
}
