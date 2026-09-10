package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type messageToRemediateInput struct {
	TenantID            int    `json:"tenant_id"`
	RawMessageID        string `json:"raw_message_id"`
	AbnormalMessageID   string `json:"abnormal_message_id,omitempty"`
	AbnormalMessageUUID string `json:"abnormal_message_uuid,omitempty"`
	MailboxName         string `json:"mailbox_name"`
	NativeUserID        string `json:"native_user_id"`
	Subject             string `json:"subject"`
	Sender              string `json:"sender"`
	ReceivedTime        string `json:"received_time"`
}

type searchRemediateInput struct {
	Confirm           bool                      `json:"confirm" jsonschema:"Must be true to execute. If false, returns a preview only."`
	Action            string                    `json:"action" jsonschema:"Remediation action: delete or move_to_inbox."`
	Source            string                    `json:"source,omitempty" jsonschema:"Message source: abnormal (default) or quarantine."`
	RemediationReason string                    `json:"remediation_reason" jsonschema:"Reason: false_negative, unsolicited, other, groups_remediation, or quarantine_release."`
	TargetFolder      string                    `json:"target_folder,omitempty" jsonschema:"Required when action is move_to_inbox."`
	SubmitD360Case    bool                      `json:"submit_d360_case,omitempty" jsonschema:"Submit a Detection 360 case (requires false_negative)."`
	RemediateAll      bool                      `json:"remediate_all,omitempty" jsonschema:"Remediate all messages matching search_filters instead of explicit messages."`
	Messages          []messageToRemediateInput `json:"messages,omitempty" jsonschema:"Specific messages to remediate when remediate_all is false."`
	TenantIDs         []int                     `json:"tenant_ids,omitempty" jsonschema:"Optional tenant IDs to scope remediation."`
	Since             string                    `json:"since,omitempty" jsonschema:"Search filter start (RFC3339) for remediate_all."`
	Until             string                    `json:"until,omitempty" jsonschema:"Search filter end (RFC3339) for remediate_all."`
	Sender            string                    `json:"sender,omitempty"`
	SenderDomain      string                    `json:"sender_domain,omitempty"`
	Recipient         string                    `json:"recipient,omitempty"`
	Subject           string                    `json:"subject,omitempty"`
	URL               string                    `json:"url,omitempty"`
	Attachment        string                    `json:"attachment,omitempty"`
	SenderIP          string                    `json:"sender_ip,omitempty"`
	Judgement         string                    `json:"judgement,omitempty"`
	JudgementSource   string                    `json:"judgement_source,omitempty"`
	InternetMessageID string                    `json:"internet_message_id,omitempty"`
}

type searchRemediateResult struct {
	Confirmed     bool   `json:"confirmed"`
	Error         string `json:"error,omitempty"`
	Summary       string `json:"summary,omitempty"`
	Action        string `json:"action,omitempty"`
	RemediateAll  bool   `json:"remediate_all,omitempty"`
	MessageCount  int    `json:"message_count,omitempty"`
	ActivityLogID int    `json:"activity_log_id,omitempty"`
}

type threatRemediateInput struct {
	ID      string `json:"id" jsonschema:"Threat ID (UUID)."`
	Action  string `json:"action" jsonschema:"remediate or unremediate."`
	Confirm bool   `json:"confirm" jsonschema:"Must be true to execute. If false, returns a preview only."`
}

type threatRemediateResult struct {
	Confirmed  bool   `json:"confirmed"`
	Error      string `json:"error,omitempty"`
	Summary    string `json:"summary,omitempty"`
	ThreatID   string `json:"threat_id,omitempty"`
	Action     string `json:"action,omitempty"`
	ActionID   string `json:"action_id,omitempty"`
	StatusURL  string `json:"status_url,omitempty"`
	TenantID   *int   `json:"tenant_id,omitempty"`
	TenantName string `json:"tenant_name,omitempty"`
}

func registerResponse(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_search_remediate",
		Title:       "Remediate Abnormal search messages",
		Description: "Delete or move email messages identified by search. Returns an activity_log_id; poll abnormal_search_activity_get for results. Requires ABNORMAL_ALLOW_RESPONSE=true and confirm: true.",
		Annotations: responseAnnotations(true),
	}, h.searchRemediate)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_threat_remediate",
		Title:       "Remediate or unremediate an Abnormal threat",
		Description: "Remediate or restore (unremediate) all messages in a threat campaign. Returns action_id; poll abnormal_threat_action_get for status. Requires ABNORMAL_ALLOW_RESPONSE=true and confirm: true.",
		Annotations: responseAnnotations(true),
	}, h.threatRemediate)
}

func (h *handlers) searchRemediate(ctx context.Context, _ *mcp.CallToolRequest, in searchRemediateInput) (*mcp.CallToolResult, searchRemediateResult, error) {
	if !h.allowResponse {
		return nil, searchRemediateResult{}, errResponseDisabled
	}
	if in.Action == "" {
		return nil, searchRemediateResult{}, errRemediationActionRequired
	}
	if in.RemediationReason == "" {
		return nil, searchRemediateResult{}, errRemediationReasonRequired
	}
	if in.Action == "move_to_inbox" && in.TargetFolder == "" {
		return nil, searchRemediateResult{}, errTargetFolderRequired
	}
	if in.RemediateAll {
		if _, err := buildSearchFilters(searchFiltersInput{
			Since: in.Since, Until: in.Until, Sender: in.Sender, SenderDomain: in.SenderDomain,
			Recipient: in.Recipient, Subject: in.Subject, URL: in.URL, Attachment: in.Attachment,
			SenderIP: in.SenderIP, Judgement: in.Judgement, JudgementSource: in.JudgementSource,
			InternetMessageID: in.InternetMessageID,
		}); err != nil {
			return nil, searchRemediateResult{}, err
		}
	} else if len(in.Messages) == 0 {
		return nil, searchRemediateResult{}, errMessagesRequired
	}

	preview := searchRemediateResult{
		Action:       in.Action,
		RemediateAll: in.RemediateAll,
		MessageCount: len(in.Messages),
		Summary:      remediationPreviewSummary(in),
	}
	if !in.Confirm {
		preview.Error = errConfirmationRequired
		return nil, preview, nil
	}

	req, err := h.buildRemediationRequest(in)
	if err != nil {
		return nil, searchRemediateResult{}, err
	}
	resp, err := h.api.RemediateSearch(ctx, req)
	if err != nil {
		return nil, searchRemediateResult{}, abnormal.APIError(err)
	}
	preview.Confirmed = true
	preview.ActivityLogID = resp.ActivityLogID
	preview.Summary = fmt.Sprintf("Remediation accepted (activity_log_id=%d). Poll abnormal_search_activity_get for status.", resp.ActivityLogID)
	logResponseAction("abnormal_search_remediate", "search", fmt.Sprintf("activity_log_id=%d", resp.ActivityLogID), in.Action)
	return nil, preview, nil
}

func (h *handlers) threatRemediate(ctx context.Context, _ *mcp.CallToolRequest, in threatRemediateInput) (*mcp.CallToolResult, threatRemediateResult, error) {
	if !h.allowResponse {
		return nil, threatRemediateResult{}, errResponseDisabled
	}
	if in.ID == "" {
		return nil, threatRemediateResult{}, errIDRequired
	}
	if in.Action != "remediate" && in.Action != "unremediate" {
		return nil, threatRemediateResult{}, errThreatActionRequired
	}

	preview := threatRemediateResult{
		ThreatID: in.ID,
		Action:   in.Action,
		Summary:  fmt.Sprintf("Would %s threat %s", in.Action, in.ID),
	}
	if !in.Confirm {
		preview.Error = errConfirmationRequired
		return nil, preview, nil
	}

	resp, err := h.api.RemediateThreat(ctx, in.ID, in.Action)
	if err != nil {
		return nil, threatRemediateResult{}, abnormal.APIError(err)
	}
	preview.Confirmed = true
	preview.ActionID = resp.ActionID
	preview.StatusURL = resp.StatusURL
	if resp.TenantID != nil {
		preview.TenantID = resp.TenantID
	}
	if resp.TenantName != nil {
		preview.TenantName = *resp.TenantName
	}
	preview.Summary = fmt.Sprintf("Threat %s %s (action_id=%s). Poll abnormal_threat_action_get for status.", in.ID, in.Action, resp.ActionID)
	logResponseAction("abnormal_threat_remediate", "threat", in.ID, in.Action)
	return nil, preview, nil
}

func remediationPreviewSummary(in searchRemediateInput) string {
	if in.RemediateAll {
		return fmt.Sprintf("Would remediate all messages matching search filters via %s (%s)", in.Action, in.RemediationReason)
	}
	return fmt.Sprintf("Would remediate %d message(s) via %s (%s)", len(in.Messages), in.Action, in.RemediationReason)
}

func (h *handlers) buildRemediationRequest(in searchRemediateInput) (abnormal.RemediationRequest, error) {
	source := in.Source
	if source == "" {
		source = "abnormal"
	}
	req := abnormal.RemediationRequest{
		Action:            in.Action,
		Source:            source,
		RemediationReason: in.RemediationReason,
		TargetFolder:      strPtr(in.TargetFolder),
		SubmitD360Case:    boolPtr(in.SubmitD360Case),
		RemediateAll:      boolPtr(in.RemediateAll),
		TenantIDs:         in.TenantIDs,
	}
	if in.RemediateAll {
		filters, err := buildSearchFilters(searchFiltersInput{
			Since: in.Since, Until: in.Until, Sender: in.Sender, SenderDomain: in.SenderDomain,
			Recipient: in.Recipient, Subject: in.Subject, URL: in.URL, Attachment: in.Attachment,
			SenderIP: in.SenderIP, Judgement: in.Judgement, JudgementSource: in.JudgementSource,
			InternetMessageID: in.InternetMessageID,
		})
		if err != nil {
			return abnormal.RemediationRequest{}, err
		}
		req.SearchFilters = &filters
		return req, nil
	}
	messages := make([]abnormal.MessageToRemediate, 0, len(in.Messages))
	for _, m := range in.Messages {
		messages = append(messages, abnormal.MessageToRemediate{
			TenantID:            m.TenantID,
			RawMessageID:        m.RawMessageID,
			AbnormalMessageID:   strPtr(m.AbnormalMessageID),
			AbnormalMessageUUID: strPtr(m.AbnormalMessageUUID),
			MailboxName:         m.MailboxName,
			NativeUserID:        m.NativeUserID,
			Subject:             m.Subject,
			Sender:              m.Sender,
			ReceivedTime:        m.ReceivedTime,
		})
	}
	req.Messages = messages
	return req, nil
}
