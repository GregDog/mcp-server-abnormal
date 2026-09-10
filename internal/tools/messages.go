package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type messageRemediationHistoryInput struct {
	MessageID int64 `json:"message_id" jsonschema:"ABX message ID from threat or search results."`
}

type folderLocationItem struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type messageRemediationHistory struct {
	RemediationHistory map[string]string    `json:"remediation_history"`
	FolderLocations    []folderLocationItem `json:"folder_locations"`
}

func registerMessages(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_message_remediation_history",
		Title:       "Get Abnormal message remediation history",
		Description: "Get remediation history and folder locations for a threat log message by ABX message ID.",
		Annotations: readOnly(),
	}, h.getMessageRemediationHistory)
}

func (h *handlers) getMessageRemediationHistory(ctx context.Context, _ *mcp.CallToolRequest, in messageRemediationHistoryInput) (*mcp.CallToolResult, messageRemediationHistory, error) {
	if in.MessageID <= 0 {
		return nil, messageRemediationHistory{}, errMessageIDRequired
	}
	resp, err := h.api.GetRemediationHistory(ctx, in.MessageID)
	if err != nil {
		return nil, messageRemediationHistory{}, abnormal.APIError(err)
	}
	folders := make([]folderLocationItem, 0, len(resp.FolderLocations))
	for _, f := range resp.FolderLocations {
		folders = append(folders, folderLocationItem{
			Name:        f.Name,
			DisplayName: f.DisplayName,
		})
	}
	return nil, messageRemediationHistory{
		RemediationHistory: resp.RemediationHistory,
		FolderLocations:    folders,
	}, nil
}
