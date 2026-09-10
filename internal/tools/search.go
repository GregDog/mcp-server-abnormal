package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type searchMessagesInput struct {
	listInput
	Since             string `json:"since,omitempty" jsonschema:"Start time (RFC3339). Default last 24 hours."`
	Until             string `json:"until,omitempty" jsonschema:"End time (RFC3339). Default now."`
	Sender            string `json:"sender,omitempty" jsonschema:"Sender email address."`
	SenderDomain      string `json:"sender_domain,omitempty" jsonschema:"Sender domain (matched via sender_email regex)."`
	Recipient         string `json:"recipient,omitempty" jsonschema:"Recipient email address."`
	Subject           string `json:"subject,omitempty" jsonschema:"Email subject."`
	URL               string `json:"url,omitempty" jsonschema:"URL found in the email body."`
	Attachment        string `json:"attachment,omitempty" jsonschema:"Attachment file name."`
	SenderIP          string `json:"sender_ip,omitempty" jsonschema:"Sender IP address."`
	Judgement         string `json:"judgement,omitempty" jsonschema:"Threat judgement: attack, borderline, spam, graymail, or safe."`
	JudgementSource   string `json:"judgement_source,omitempty" jsonschema:"Detection source: ABNORMAL_SYSTEM or CUSTOMER_AI_MODEL."`
	InternetMessageID string `json:"internet_message_id,omitempty" jsonschema:"Internet message ID."`
	Source            string `json:"source,omitempty" jsonschema:"Search source: abnormal (default) or quarantine."`
}

type searchMessageItem struct {
	TenantID          *int     `json:"tenant_id,omitempty"`
	ReceivedTime      *string  `json:"received_time,omitempty"`
	Subject           *string  `json:"subject,omitempty"`
	Sender            *string  `json:"sender,omitempty"`
	SenderDisplayName *string  `json:"sender_display_name,omitempty"`
	MailboxName       *string  `json:"mailbox_name,omitempty"`
	CurrentFolderName *string  `json:"current_folder_name,omitempty"`
	RawMessageID      *string  `json:"raw_message_id,omitempty"`
	CloudMessageID    *string  `json:"cloud_message_id,omitempty"`
	InternetMessageID *string  `json:"internet_message_id,omitempty"`
	AbnormalMessageID *string  `json:"abnormal_message_id,omitempty"`
	Judgement         *string  `json:"judgement,omitempty"`
	JudgementSource   *string  `json:"judgement_source,omitempty"`
	AttachmentNames   []string `json:"attachment_names,omitempty"`
	BodyLinks         []string `json:"body_links,omitempty"`
	SenderIPAddresses []string `json:"sender_ip_addresses,omitempty"`
}

type searchActivitiesInput struct {
	listInput
	Action    string `json:"action,omitempty" jsonschema:"Filter by remediation action (e.g. delete, move_to_inbox)."`
	TenantIDs string `json:"tenant_ids,omitempty" jsonschema:"Comma-separated tenant IDs."`
}

type searchActivityItem struct {
	ActivityID  int    `json:"activity_id"`
	Action      string `json:"action"`
	Status      string `json:"status"`
	PerformedBy string `json:"performed_by,omitempty"`
	Timestamp   string `json:"timestamp"`
	ResultCount int    `json:"result_count"`
}

type searchActivityGetInput struct {
	ActivityLogID int `json:"activity_log_id" jsonschema:"Activity log ID from a remediation or search operation."`
}

type searchActivityDetail struct {
	ActivityID         int                     `json:"activity_id"`
	Action             string                  `json:"action"`
	Status             string                  `json:"status"`
	PerformedBy        string                  `json:"performed_by,omitempty"`
	Timestamp          string                  `json:"timestamp"`
	ResultCount        int                     `json:"result_count"`
	RemediationDetails []remediationDetailItem `json:"remediation_details,omitempty"`
}

type remediationDetailItem struct {
	TenantID     int    `json:"tenant_id"`
	RawMessageID string `json:"raw_message_id"`
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func registerSearch(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_search_messages",
		Title:       "Search Abnormal messages",
		Description: "Search email messages across Abnormal and quarantine sources using ergonomic filters. Results are paginated.",
		Annotations: readOnly(),
	}, h.searchMessages)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_search_activities_list",
		Title:       "List Abnormal search activities",
		Description: "List activity logs for search and remediation operations. Results are paginated.",
		Annotations: readOnly(),
	}, h.listSearchActivities)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_search_activity_get",
		Title:       "Get Abnormal search activity status",
		Description: "Get detailed status of a search or remediation activity, including per-message remediation results when available.",
		Annotations: readOnly(),
	}, h.getSearchActivity)
}

func (h *handlers) searchMessages(ctx context.Context, _ *mcp.CallToolRequest, in searchMessagesInput) (*mcp.CallToolResult, abnormal.Page[searchMessageItem], error) {
	filters, err := buildSearchFilters(searchFiltersInput{
		Since: in.Since, Until: in.Until, Sender: in.Sender, SenderDomain: in.SenderDomain,
		Recipient: in.Recipient, Subject: in.Subject, URL: in.URL, Attachment: in.Attachment,
		SenderIP: in.SenderIP, Judgement: in.Judgement, JudgementSource: in.JudgementSource,
		InternetMessageID: in.InternetMessageID,
	})
	if err != nil {
		return nil, abnormal.Page[searchMessageItem]{}, err
	}

	source := in.Source
	if source == "" {
		source = "abnormal"
	}

	pageSize, pageNumber := pageArgs(in.Limit, in.Cursor)
	resp, err := h.api.SearchMessages(ctx, abnormal.SearchRequest{
		Source:  source,
		Filters: filters,
	}, pageSize, pageNumber)
	if err != nil {
		return nil, abnormal.Page[searchMessageItem]{}, abnormal.APIError(err)
	}

	items := make([]searchMessageItem, 0, len(resp.Results))
	for _, r := range resp.Results {
		var attachmentNames []string
		for name := range r.Attachments {
			attachmentNames = append(attachmentNames, name)
		}
		items = append(items, searchMessageItem{
			TenantID:          r.TenantID,
			ReceivedTime:      r.ReceivedTime,
			Subject:           r.Subject,
			Sender:            r.Sender,
			SenderDisplayName: r.SenderDisplayName,
			MailboxName:       r.MailboxName,
			CurrentFolderName: r.CurrentFolderName,
			RawMessageID:      r.RawMessageID,
			CloudMessageID:    r.CloudMessageID,
			InternetMessageID: r.InternetMessageID,
			AbnormalMessageID: r.AbnormalMessageID,
			Judgement:         r.Judgement,
			JudgementSource:   r.JudgementSource,
			AttachmentNames:   attachmentNames,
			BodyLinks:         r.BodyLinks,
			SenderIPAddresses: r.SenderIPAddresses,
		})
	}
	return nil, searchPage(items, resp.Total, resp.PageNumber, resp.NextPageNumber), nil
}

func (h *handlers) listSearchActivities(ctx context.Context, _ *mcp.CallToolRequest, in searchActivitiesInput) (*mcp.CallToolResult, abnormal.Page[searchActivityItem], error) {
	pageSize, pageNumber := pageArgs(in.Limit, in.Cursor)
	resp, err := h.api.ListSearchActivities(ctx, abnormal.ListActivitiesParams{
		TenantIDs:  in.TenantIDs,
		PageSize:   pageSize,
		PageNumber: pageNumber,
		Action:     in.Action,
	})
	if err != nil {
		return nil, abnormal.Page[searchActivityItem]{}, abnormal.APIError(err)
	}
	items := make([]searchActivityItem, 0, len(resp.Activities))
	for _, a := range resp.Activities {
		items = append(items, searchActivityItem{
			ActivityID:  a.ActivityID,
			Action:      a.Action,
			Status:      a.Status,
			PerformedBy: a.PerformedBy,
			Timestamp:   a.Timestamp,
			ResultCount: a.ResultCount,
		})
	}
	return nil, mapPage(items, resp.Total, resp.PageNumber, 0), nil
}

func (h *handlers) getSearchActivity(ctx context.Context, _ *mcp.CallToolRequest, in searchActivityGetInput) (*mcp.CallToolResult, searchActivityDetail, error) {
	if in.ActivityLogID <= 0 {
		return nil, searchActivityDetail{}, errActivityIDRequired
	}
	resp, err := h.api.GetSearchActivityStatus(ctx, in.ActivityLogID)
	if err != nil {
		return nil, searchActivityDetail{}, abnormal.APIError(err)
	}
	details := make([]remediationDetailItem, 0, len(resp.RemediationDetails))
	for _, d := range resp.RemediationDetails {
		details = append(details, remediationDetailItem{
			TenantID:     d.TenantID,
			RawMessageID: d.RawMessageID,
			Status:       d.Status,
			ErrorMessage: d.ErrorMessage,
		})
	}
	return nil, searchActivityDetail{
		ActivityID:         resp.ActivityID,
		Action:             resp.Action,
		Status:             resp.Status,
		PerformedBy:        resp.PerformedBy,
		Timestamp:          resp.Timestamp,
		ResultCount:        resp.ResultCount,
		RemediationDetails: details,
	}, nil
}
