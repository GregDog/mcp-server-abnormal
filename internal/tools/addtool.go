package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// addTool registers a tool handler without an output schema in tools/list.
func addTool[In, Out any](server *mcp.Server, t *mcp.Tool, h func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, Out, error)) {
	mcp.AddTool(server, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		return h(ctx, req, in)
	})
}
