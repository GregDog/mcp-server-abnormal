package abnormal

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// ListAuditLogsParams are query parameters for GET /auditlogs.
type ListAuditLogsParams struct {
	Filter     string
	Action     string
	Category   string
	Status     string
	SourceIP   string
	PageSize   int
	PageNumber int
}

// AuditLogResponse is the paginated response for portal audit logs.
type AuditLogResponse struct {
	AuditLogs      []AuditLog `json:"auditLogs"`
	PageNumber     int        `json:"pageNumber"`
	NextPageNumber int        `json:"nextPageNumber"`
}

// AuditLog is a single Abnormal portal audit log entry.
type AuditLog struct {
	Action        string                 `json:"action"`
	ActionDetails *AuditLogActionDetails `json:"actionDetails"`
	Category      string                 `json:"category"`
	SourceIP      string                 `json:"sourceIp"`
	Status        string                 `json:"status"`
	TenantName    string                 `json:"tenantName"`
	Timestamp     string                 `json:"timestamp"`
	User          AuditLogUser           `json:"user"`
}

// AuditLogActionDetails holds optional details for an audit log action.
type AuditLogActionDetails struct {
	MessageID      string `json:"messageId"`
	ProvidedReason string `json:"providedReason"`
	RequestURL     string `json:"requestUrl"`
}

// AuditLogUser identifies the user who performed an audited action.
type AuditLogUser struct {
	Email string `json:"email"`
}

func (c *client) ListAuditLogs(ctx context.Context, params ListAuditLogsParams) (AuditLogResponse, error) {
	q := url.Values{}
	if params.Filter != "" {
		q.Set("filter", params.Filter)
	}
	if params.Action != "" {
		q.Set("action", params.Action)
	}
	if params.Category != "" {
		q.Set("category", params.Category)
	}
	if params.Status != "" {
		q.Set("status", params.Status)
	}
	if params.SourceIP != "" {
		q.Set("sourceIp", params.SourceIP)
	}
	if params.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(params.PageSize))
	}
	if params.PageNumber > 0 {
		q.Set("pageNumber", strconv.Itoa(params.PageNumber))
	}
	var out AuditLogResponse
	err := c.doJSON(ctx, http.MethodGet, "/auditlogs", q, nil, &out)
	return out, err
}
