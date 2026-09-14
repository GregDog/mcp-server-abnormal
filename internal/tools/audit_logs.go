package tools

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type auditLogsListInput struct {
	listInput
	Since    string `json:"since,omitempty" jsonschema:"Start of timestamp filter (RFC3339). Default last 24 hours."`
	Until    string `json:"until,omitempty" jsonschema:"End of timestamp filter (RFC3339). Default now."`
	Action   string `json:"action,omitempty" jsonschema:"Space-delimited action filters (e.g. view_message_content)."`
	Category string `json:"category,omitempty" jsonschema:"Space-delimited category filters (e.g. abuse_mailbox threat_log)."`
	Status   string `json:"status,omitempty" jsonschema:"SUCCESS or FAILURE."`
	SourceIP string `json:"source_ip,omitempty" jsonschema:"Filter by source IP address."`
}

type auditLogItem struct {
	Timestamp     string                `json:"timestamp"`
	Category      string                `json:"category"`
	Action        string                `json:"action,omitempty"`
	Status        string                `json:"status"`
	SourceIP      string                `json:"source_ip"`
	TenantName    string                `json:"tenant_name"`
	UserEmail     string                `json:"user_email"`
	ActionDetails *auditLogActionDetail `json:"action_details,omitempty"`
}

type auditLogActionDetail struct {
	MessageID      string `json:"message_id,omitempty"`
	ProvidedReason string `json:"provided_reason,omitempty"`
	RequestURL     string `json:"request_url,omitempty"`
}

func registerAuditLogs(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_audit_logs_list",
		Title:       "List Abnormal portal audit logs",
		Description: "List Abnormal portal audit logs for analyst accountability and correlation. Results are paginated.",
		Annotations: readOnly(),
	}, h.listAuditLogs)
}

func (h *handlers) listAuditLogs(ctx context.Context, _ *mcp.CallToolRequest, in auditLogsListInput) (*mcp.CallToolResult, abnormal.Page[auditLogItem], error) {
	since, until, err := defaultSinceUntil(in.Since, in.Until)
	if err != nil {
		return nil, abnormal.Page[auditLogItem]{}, err
	}
	filter := abnormal.FormatTimeFilter("timestamp", since, until)

	pageSize, pageNumber := pageArgs(in.Limit, in.Cursor)
	resp, err := h.api.ListAuditLogs(ctx, abnormal.ListAuditLogsParams{
		Filter:     filter,
		Action:     strings.TrimSpace(in.Action),
		Category:   strings.TrimSpace(in.Category),
		Status:     strings.TrimSpace(in.Status),
		SourceIP:   strings.TrimSpace(in.SourceIP),
		PageSize:   pageSize,
		PageNumber: pageNumber,
	})
	if err != nil {
		return nil, abnormal.Page[auditLogItem]{}, abnormal.APIError(err)
	}

	items := make([]auditLogItem, 0, len(resp.AuditLogs))
	for _, log := range resp.AuditLogs {
		items = append(items, mapAuditLogItem(log))
	}
	return nil, mapPage(items, len(items), resp.PageNumber, resp.NextPageNumber), nil
}

func mapAuditLogItem(log abnormal.AuditLog) auditLogItem {
	item := auditLogItem{
		Timestamp:  log.Timestamp,
		Category:   log.Category,
		Action:     log.Action,
		Status:     log.Status,
		SourceIP:   log.SourceIP,
		TenantName: log.TenantName,
		UserEmail:  log.User.Email,
	}
	if log.ActionDetails != nil {
		item.ActionDetails = &auditLogActionDetail{
			MessageID:      log.ActionDetails.MessageID,
			ProvidedReason: log.ActionDetails.ProvidedReason,
			RequestURL:     log.ActionDetails.RequestURL,
		}
	}
	return item
}
