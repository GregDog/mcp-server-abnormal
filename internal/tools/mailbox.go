package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type mailboxCampaignsInput struct {
	listInput
	Since      string `json:"since,omitempty" jsonschema:"Start of lastReportedTime filter (RFC3339). Default last 24 hours."`
	Until      string `json:"until,omitempty" jsonschema:"End of lastReportedTime filter (RFC3339). Default now."`
	Sender     string `json:"sender,omitempty" jsonschema:"Filter by sender name or email."`
	Recipient  string `json:"recipient,omitempty" jsonschema:"Filter by recipient name or email."`
	Subject    string `json:"subject,omitempty" jsonschema:"Filter by email subject."`
	Reporter   string `json:"reporter,omitempty" jsonschema:"Filter by reporter name or email."`
	AttackType string `json:"attack_type,omitempty" jsonschema:"Filter by attack type."`
	ThreatType string `json:"threat_type,omitempty" jsonschema:"Filter by threat type: All, Malicious, Safe, or Spam."`
}

type mailboxCampaignItem struct {
	CampaignID string `json:"campaign_id"`
}

type mailboxCampaignDetail struct {
	CampaignID       string `json:"campaign_id"`
	FirstReported    string `json:"first_reported,omitempty"`
	LastReported     string `json:"last_reported,omitempty"`
	MessageID        string `json:"message_id,omitempty"`
	Subject          string `json:"subject,omitempty"`
	FromName         string `json:"from_name,omitempty"`
	FromAddress      string `json:"from_address,omitempty"`
	RecipientName    string `json:"recipient_name,omitempty"`
	RecipientAddress string `json:"recipient_address,omitempty"`
	JudgementStatus  string `json:"judgement_status,omitempty"`
	OverallStatus    string `json:"overall_status,omitempty"`
	AttackType       string `json:"attack_type,omitempty"`
}

type mailboxUnanalyzedInput struct {
	Since string `json:"since,omitempty" jsonschema:"Start of datetime range (RFC3339). Defaults to 90 days before end."`
	Until string `json:"until,omitempty" jsonschema:"End of datetime range (RFC3339). Defaults to now."`
}

type mailboxUnanalyzedItem struct {
	Subject           string `json:"subject"`
	AbxMessageID      int64  `json:"abx_message_id"`
	ReportedDatetime  string `json:"reported_datetime"`
	RecipientName     string `json:"recipient_name,omitempty"`
	RecipientEmail    string `json:"recipient_email,omitempty"`
	ReporterName      string `json:"reporter_name,omitempty"`
	ReporterEmail     string `json:"reporter_email,omitempty"`
	NotAnalyzedReason string `json:"not_analyzed_reason"`
}

type mailboxUnanalyzedResult struct {
	Items []mailboxUnanalyzedItem `json:"items"`
}

func registerMailbox(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_mailbox_campaigns_list",
		Title:       "List AI Security Mailbox campaigns",
		Description: "List user-reported phishing campaigns from the AI Security Mailbox (formerly Abuse Mailbox). Results are paginated.",
		Annotations: readOnly(),
	}, h.listMailboxCampaigns)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_mailbox_campaign_get",
		Title:       "Get an AI Security Mailbox campaign",
		Description: "Get details of a user-reported phishing campaign by campaign ID.",
		Annotations: readOnly(),
	}, h.getMailboxCampaign)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_mailbox_unanalyzed_list",
		Title:       "List unanalyzed AI Security Mailbox reports",
		Description: "List messages submitted to the AI Security Mailbox that were not analyzed.",
		Annotations: readOnly(),
	}, h.listMailboxUnanalyzed)
}

func (h *handlers) listMailboxCampaigns(ctx context.Context, _ *mcp.CallToolRequest, in mailboxCampaignsInput) (*mcp.CallToolResult, abnormal.Page[mailboxCampaignItem], error) {
	since, until, err := defaultSinceUntil(in.Since, in.Until)
	if err != nil {
		return nil, abnormal.Page[mailboxCampaignItem]{}, err
	}
	pageSize, pageNumber := pageArgs(in.Limit, in.Cursor)
	filter := abnormal.FormatTimeFilter("lastReportedTime", since, until)

	resp, err := h.api.ListAbuseCampaigns(ctx, abnormal.ListAbuseCampaignsParams{
		Filter:     filter,
		PageSize:   pageSize,
		PageNumber: pageNumber,
		Sender:     in.Sender,
		Recipient:  in.Recipient,
		Subject:    in.Subject,
		Reporter:   in.Reporter,
		AttackType: in.AttackType,
		ThreatType: in.ThreatType,
	})
	if err != nil {
		return nil, abnormal.Page[mailboxCampaignItem]{}, abnormal.APIError(err)
	}

	items := make([]mailboxCampaignItem, 0, len(resp.Campaigns))
	for _, c := range resp.Campaigns {
		items = append(items, mailboxCampaignItem{CampaignID: c.CampaignID})
	}
	return nil, mapPage(items, len(items), resp.PageNumber, resp.NextPageNumber), nil
}

func (h *handlers) getMailboxCampaign(ctx context.Context, _ *mcp.CallToolRequest, in getInput) (*mcp.CallToolResult, mailboxCampaignDetail, error) {
	if in.ID == "" {
		return nil, mailboxCampaignDetail{}, errIDRequired
	}
	resp, err := h.api.GetAbuseCampaign(ctx, in.ID)
	if err != nil {
		return nil, mailboxCampaignDetail{}, abnormal.APIError(err)
	}
	return nil, mailboxCampaignDetail{
		CampaignID:       resp.CampaignID,
		FirstReported:    resp.FirstReported,
		LastReported:     resp.LastReported,
		MessageID:        resp.MessageID,
		Subject:          resp.Subject,
		FromName:         resp.FromName,
		FromAddress:      resp.FromAddress,
		RecipientName:    resp.RecipientName,
		RecipientAddress: resp.RecipientAddress,
		JudgementStatus:  resp.JudgementStatus,
		OverallStatus:    resp.OverallStatus,
		AttackType:       resp.AttackType,
	}, nil
}

func (h *handlers) listMailboxUnanalyzed(ctx context.Context, _ *mcp.CallToolRequest, in mailboxUnanalyzedInput) (*mcp.CallToolResult, mailboxUnanalyzedResult, error) {
	resp, err := h.api.ListUnanalyzedMailbox(ctx, in.Since, in.Until)
	if err != nil {
		return nil, mailboxUnanalyzedResult{}, abnormal.APIError(err)
	}
	items := make([]mailboxUnanalyzedItem, 0, len(resp.Results))
	for _, r := range resp.Results {
		items = append(items, mailboxUnanalyzedItem{
			Subject:           r.Subject,
			AbxMessageID:      r.AbxMessageID,
			ReportedDatetime:  r.ReportedDatetime,
			RecipientName:     r.Recipient.Name,
			RecipientEmail:    r.Recipient.Email,
			ReporterName:      r.Reporter.Name,
			ReporterEmail:     r.Reporter.Email,
			NotAnalyzedReason: r.NotAnalyzedReason,
		})
	}
	return nil, mailboxUnanalyzedResult{Items: items}, nil
}
