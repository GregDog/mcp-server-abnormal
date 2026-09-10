package tools

import "github.com/modelcontextprotocol/go-sdk/mcp"

func responseAnnotations(destructive bool) *mcp.ToolAnnotations {
	openWorld := true
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: &destructive,
		OpenWorldHint:   &openWorld,
		IdempotentHint:  false,
	}
}
