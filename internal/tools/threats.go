package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type threatListInput struct {
	listInput
	Since      string `json:"since,omitempty" jsonschema:"Start of receivedTime filter (RFC3339). Default last 24 hours."`
	Until      string `json:"until,omitempty" jsonschema:"End of receivedTime filter (RFC3339). Default now."`
	Source     string `json:"source,omitempty" jsonschema:"Threat source filter: all, attacks, borderline, or spam."`
	Sender     string `json:"sender,omitempty" jsonschema:"Filter by sender name or email."`
	Recipient  string `json:"recipient,omitempty" jsonschema:"Filter by recipient name or email."`
	Subject    string `json:"subject,omitempty" jsonschema:"Filter by email subject."`
	AttackType string `json:"attack_type,omitempty" jsonschema:"Filter by attack type."`
}

type threatItem struct {
	ThreatID string `json:"threat_id"`
}

type threatDetail struct {
	ThreatID       string              `json:"threat_id"`
	RecipientCount int                 `json:"recipient_count"`
	TenantID       *int                `json:"tenant_id,omitempty"`
	TenantName     *string             `json:"tenant_name,omitempty"`
	Messages       []threatMessageItem `json:"messages"`
}

type threatMessageItem struct {
	ThreatID          string   `json:"threat_id"`
	AbxMessageID      int64    `json:"abx_message_id"`
	AbxMessageIDStr   string   `json:"abx_message_id_str,omitempty"`
	AbxPortalURL      string   `json:"abx_portal_url,omitempty"`
	Subject           string   `json:"subject,omitempty"`
	FromAddress       string   `json:"from_address,omitempty"`
	FromName          string   `json:"from_name,omitempty"`
	RecipientAddress  string   `json:"recipient_address,omitempty"`
	RecipientName     string   `json:"recipient_name,omitempty"`
	ReceivedTime      string   `json:"received_time,omitempty"`
	SentTime          string   `json:"sent_time,omitempty"`
	RemediationStatus string   `json:"remediation_status,omitempty"`
	AttackType        string   `json:"attack_type,omitempty"`
	AttackVector      string   `json:"attack_vector,omitempty"`
	SenderDomain      string   `json:"sender_domain,omitempty"`
	ToAddresses       []string `json:"to_addresses,omitempty"`
}

type threatActionGetInput struct {
	ThreatID string `json:"threat_id" jsonschema:"Threat ID (UUID)."`
	ActionID string `json:"action_id" jsonschema:"Action ID returned from abnormal_threat_remediate."`
}

type threatLinksInput struct {
	ThreatID string `json:"threat_id" jsonschema:"Threat ID (UUID)."`
}

type threatLinkItem struct {
	AbxMessageID    int64  `json:"abx_message_id"`
	AbxMessageIDStr string `json:"abx_message_id_str,omitempty"`
	DomainLink      string `json:"domain_link,omitempty"`
	LinkType        string `json:"link_type,omitempty"`
	Source          string `json:"source,omitempty"`
	DisplayText     string `json:"display_text,omitempty"`
	LinkURL         string `json:"link_url,omitempty"`
}

type threatLinksResult struct {
	ThreatID   string           `json:"threat_id"`
	Links      []threatLinkItem `json:"links"`
	TenantID   *int             `json:"tenant_id,omitempty"`
	TenantName string           `json:"tenant_name,omitempty"`
}

type threatAttachmentItem struct {
	AbxMessageID    int64  `json:"abx_message_id"`
	AbxMessageIDStr string `json:"abx_message_id_str,omitempty"`
	AttachmentName  string `json:"attachment_name,omitempty"`
}

type threatAttachmentsResult struct {
	ThreatID    string                 `json:"threat_id"`
	Attachments []threatAttachmentItem `json:"attachments"`
	TenantID    *int                   `json:"tenant_id,omitempty"`
	TenantName  string                 `json:"tenant_name,omitempty"`
}

type threatActionStatus struct {
	ThreatID    string `json:"threat_id"`
	ActionID    string `json:"action_id"`
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
	TenantID    *int   `json:"tenant_id,omitempty"`
	TenantName  string `json:"tenant_name,omitempty"`
}

func registerThreats(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_threats_list",
		Title:       "List Abnormal threats",
		Description: "List threat campaigns from the Abnormal Threat Log. Always applies a receivedTime filter so pagination works. Results are paginated.",
		Annotations: readOnly(),
	}, h.listThreats)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_threat_get",
		Title:       "Get an Abnormal threat",
		Description: "Get threat campaign details including bounded message metadata. The API currently returns at most about 10 messages per threat.",
		Annotations: readOnly(),
	}, h.getThreat)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_threat_action_get",
		Title:       "Get Abnormal threat action status",
		Description: "Poll the status of a threat remediate or unremediate action returned by abnormal_threat_remediate.",
		Annotations: readOnly(),
	}, h.getThreatAction)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_threat_links_list",
		Title:       "List links in an Abnormal threat",
		Description: "Get URLs and link metadata embedded in email messages of a threat campaign.",
		Annotations: readOnly(),
	}, h.listThreatLinks)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_threat_attachments_list",
		Title:       "List attachments in an Abnormal threat",
		Description: "Get attachment metadata for email messages in a threat campaign.",
		Annotations: readOnly(),
	}, h.listThreatAttachments)
}

func (h *handlers) listThreats(ctx context.Context, _ *mcp.CallToolRequest, in threatListInput) (*mcp.CallToolResult, abnormal.Page[threatItem], error) {
	since, until, err := defaultSinceUntil(in.Since, in.Until)
	if err != nil {
		return nil, abnormal.Page[threatItem]{}, err
	}
	pageSize, pageNumber := pageArgs(in.Limit, in.Cursor)
	filter := abnormal.FormatTimeFilter("receivedTime", since, until)

	resp, err := h.api.ListThreats(ctx, abnormal.ListThreatsParams{
		Filter:     filter,
		PageSize:   pageSize,
		PageNumber: pageNumber,
		Source:     in.Source,
		Sender:     in.Sender,
		Recipient:  in.Recipient,
		Subject:    in.Subject,
		AttackType: in.AttackType,
	})
	if err != nil {
		return nil, abnormal.Page[threatItem]{}, abnormal.APIError(err)
	}

	items := make([]threatItem, 0, len(resp.Threats))
	for _, t := range resp.Threats {
		items = append(items, threatItem{ThreatID: t.ThreatID})
	}
	total := len(items)
	if resp.NextPageNumber > 0 {
		total = pageNumber * pageSize
	}
	return nil, mapPage(items, total, resp.PageNumber, resp.NextPageNumber), nil
}

func (h *handlers) getThreat(ctx context.Context, _ *mcp.CallToolRequest, in getInput) (*mcp.CallToolResult, threatDetail, error) {
	if in.ID == "" {
		return nil, threatDetail{}, errIDRequired
	}
	resp, err := h.api.GetThreat(ctx, in.ID, abnormal.MaxPageSize, 1)
	if err != nil {
		return nil, threatDetail{}, abnormal.APIError(err)
	}
	return nil, mapThreatDetail(resp), nil
}

func (h *handlers) getThreatAction(ctx context.Context, _ *mcp.CallToolRequest, in threatActionGetInput) (*mcp.CallToolResult, threatActionStatus, error) {
	if in.ThreatID == "" {
		return nil, threatActionStatus{}, errIDRequired
	}
	if in.ActionID == "" {
		return nil, threatActionStatus{}, errActionIDRequired
	}
	resp, err := h.api.GetThreatActionStatus(ctx, in.ThreatID, in.ActionID)
	if err != nil {
		return nil, threatActionStatus{}, abnormal.APIError(err)
	}
	out := threatActionStatus{
		ThreatID:    in.ThreatID,
		ActionID:    in.ActionID,
		Status:      resp.Status,
		Description: resp.Description,
		TenantID:    resp.TenantID,
	}
	if resp.TenantName != nil {
		out.TenantName = *resp.TenantName
	}
	return nil, out, nil
}

func (h *handlers) listThreatLinks(ctx context.Context, _ *mcp.CallToolRequest, in threatLinksInput) (*mcp.CallToolResult, threatLinksResult, error) {
	if in.ThreatID == "" {
		return nil, threatLinksResult{}, errIDRequired
	}
	resp, err := h.api.GetThreatLinks(ctx, in.ThreatID)
	if err != nil {
		return nil, threatLinksResult{}, abnormal.APIError(err)
	}
	out := threatLinksResult{ThreatID: in.ThreatID, TenantID: resp.TenantID}
	if resp.TenantName != nil {
		out.TenantName = *resp.TenantName
	}
	for i, l := range resp.Links {
		if i >= maxBoundedItems {
			break
		}
		out.Links = append(out.Links, threatLinkItem{
			AbxMessageID: l.AbxMessageID, AbxMessageIDStr: l.AbxMessageIDStr,
			DomainLink: l.DomainLink, LinkType: l.LinkType, Source: l.Source,
			DisplayText: trimString(l.DisplayText, maxBoundedString),
			LinkURL:     trimString(l.LinkURL, maxBoundedString),
		})
	}
	return nil, out, nil
}

func (h *handlers) listThreatAttachments(ctx context.Context, _ *mcp.CallToolRequest, in threatLinksInput) (*mcp.CallToolResult, threatAttachmentsResult, error) {
	if in.ThreatID == "" {
		return nil, threatAttachmentsResult{}, errIDRequired
	}
	resp, err := h.api.GetThreatAttachments(ctx, in.ThreatID)
	if err != nil {
		return nil, threatAttachmentsResult{}, abnormal.APIError(err)
	}
	out := threatAttachmentsResult{ThreatID: in.ThreatID, TenantID: resp.TenantID}
	if resp.TenantName != nil {
		out.TenantName = *resp.TenantName
	}
	for i, a := range resp.Attachments {
		if i >= maxBoundedItems {
			break
		}
		out.Attachments = append(out.Attachments, threatAttachmentItem{
			AbxMessageID: a.AbxMessageID, AbxMessageIDStr: a.AbxMessageIDStr,
			AttachmentName: trimString(a.AttachmentName, maxBoundedString),
		})
	}
	return nil, out, nil
}

func mapThreatDetail(t abnormal.ThreatDetails) threatDetail {
	messages := make([]threatMessageItem, 0, len(t.Messages))
	for _, m := range t.Messages {
		messages = append(messages, threatMessageItem{
			ThreatID:          m.ThreatID,
			AbxMessageID:      m.AbxMessageID,
			AbxMessageIDStr:   m.AbxMessageIDStr,
			AbxPortalURL:      m.AbxPortalURL,
			Subject:           m.Subject,
			FromAddress:       m.FromAddress,
			FromName:          m.FromName,
			RecipientAddress:  m.RecipientAddress,
			RecipientName:     m.RecipientName,
			ReceivedTime:      m.ReceivedTime,
			SentTime:          m.SentTime,
			RemediationStatus: m.RemediationStatus,
			AttackType:        m.AttackType,
			AttackVector:      m.AttackVector,
			SenderDomain:      m.SenderDomain,
			ToAddresses:       m.ToAddresses,
		})
	}
	return threatDetail{
		ThreatID:       t.ThreatID,
		RecipientCount: t.RecipientCount,
		TenantID:       t.TenantID,
		TenantName:     t.TenantName,
		Messages:       messages,
	}
}
