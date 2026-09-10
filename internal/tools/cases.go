package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type casesListInput struct {
	listInput
	Since string `json:"since,omitempty" jsonschema:"Start of lastModifiedTime filter (RFC3339). Default last 24 hours."`
	Until string `json:"until,omitempty" jsonschema:"End of lastModifiedTime filter (RFC3339). Default now."`
}

type caseItem struct {
	CaseID        string `json:"case_id"`
	Description   string `json:"description,omitempty"`
	SeverityLevel string `json:"severity_level,omitempty"`
	Confidence    string `json:"confidence,omitempty"`
	LastModified  string `json:"last_modified,omitempty"`
	FirstObserved string `json:"first_observed,omitempty"`
	Created       string `json:"created,omitempty"`
	Tenant        string `json:"tenant,omitempty"`
}

type caseDetail struct {
	CaseID              string   `json:"case_id"`
	CaseStatus          string   `json:"case_status,omitempty"`
	Severity            string   `json:"severity,omitempty"`
	AffectedEmployee    string   `json:"affected_employee,omitempty"`
	CustomerVisibleTime string   `json:"customer_visible_time,omitempty"`
	FirstObserved       string   `json:"first_observed,omitempty"`
	ThreatIDs           []string `json:"threat_ids,omitempty"`
	Analysis            string   `json:"analysis,omitempty"`
	RemediationStatus   string   `json:"remediation_status,omitempty"`
	SeverityLevel       string   `json:"severity_level,omitempty"`
	Confidence          string   `json:"confidence,omitempty"`
	GenAISummary        []string `json:"genai_summary,omitempty"`
}

type caseAnalysisResult struct {
	CaseID        string           `json:"case_id"`
	Insights      []map[string]any `json:"insights"`
	EventTimeline []map[string]any `json:"event_timeline"`
}

type caseActionGetInput struct {
	CaseID   string `json:"case_id" jsonschema:"ATO case ID."`
	ActionID string `json:"action_id" jsonschema:"Action ID returned from abnormal_case_update."`
}

type caseActionStatus struct {
	CaseID      string `json:"case_id"`
	ActionID    string `json:"action_id"`
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
	TenantID    *int   `json:"tenant_id,omitempty"`
	TenantName  string `json:"tenant_name,omitempty"`
}

type caseUpdateInput struct {
	ID      string `json:"id" jsonschema:"ATO case ID."`
	Action  string `json:"action" jsonschema:"action_required, acknowledge_resolved, acknowledge_in_progress, or acknowledge_not_an_attack."`
	Confirm bool   `json:"confirm" jsonschema:"Must be true to execute. If false, returns a preview only."`
}

type caseUpdateResult struct {
	Confirmed bool   `json:"confirmed"`
	Error     string `json:"error,omitempty"`
	Summary   string `json:"summary,omitempty"`
	CaseID    string `json:"case_id,omitempty"`
	Action    string `json:"action,omitempty"`
	ActionID  string `json:"action_id,omitempty"`
	StatusURL string `json:"status_url,omitempty"`
}

func registerCases(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_cases_list",
		Title:       "List Abnormal ATO cases",
		Description: "List Account Takeover cases. Requires ATO license. Always applies a lastModifiedTime filter so pagination works.",
		Annotations: readOnly(),
	}, h.listCases)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_case_get",
		Title:       "Get an Abnormal ATO case",
		Description: "Get Account Takeover case details by case ID.",
		Annotations: readOnly(),
	}, h.getCase)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_case_analysis_get",
		Title:       "Get Abnormal ATO case analysis",
		Description: "Get analysis insights and event timeline for an Account Takeover case.",
		Annotations: readOnly(),
	}, h.getCaseAnalysis)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_case_action_get",
		Title:       "Get Abnormal ATO case action status",
		Description: "Poll the status of a case status update returned by abnormal_case_update.",
		Annotations: readOnly(),
	}, h.getCaseAction)
}

func registerCaseResponse(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_case_update",
		Title:       "Update an Abnormal ATO case status",
		Description: "Update ATO case status. Returns action_id; poll abnormal_case_action_get. Requires ABNORMAL_ALLOW_RESPONSE=true and confirm: true.",
		Annotations: responseAnnotations(false),
	}, h.updateCase)
}

func (h *handlers) listCases(ctx context.Context, _ *mcp.CallToolRequest, in casesListInput) (*mcp.CallToolResult, abnormal.Page[caseItem], error) {
	since, until, err := defaultSinceUntil(in.Since, in.Until)
	if err != nil {
		return nil, abnormal.Page[caseItem]{}, err
	}
	pageSize, pageNumber := pageArgs(in.Limit, in.Cursor)
	filter := abnormal.FormatTimeFilter("lastModifiedTime", since, until)
	resp, err := h.api.ListCases(ctx, abnormal.ListCasesParams{
		Filter: filter, PageSize: pageSize, PageNumber: pageNumber,
	})
	if err != nil {
		return nil, abnormal.Page[caseItem]{}, abnormal.APIError(err)
	}
	items := make([]caseItem, 0, len(resp.Cases))
	for _, c := range resp.Cases {
		items = append(items, caseItem{
			CaseID: c.CaseID, Description: c.Description, SeverityLevel: c.SeverityLevel,
			Confidence: c.Confidence, LastModified: c.LastModified,
			FirstObserved: c.FirstObserved, Created: c.Created, Tenant: c.Tenant,
		})
	}
	total := len(items)
	if resp.NextPageNumber > 0 {
		total = pageNumber * pageSize
	}
	return nil, mapPage(items, total, resp.PageNumber, resp.NextPageNumber), nil
}

func (h *handlers) getCase(ctx context.Context, _ *mcp.CallToolRequest, in getInput) (*mcp.CallToolResult, caseDetail, error) {
	if in.ID == "" {
		return nil, caseDetail{}, errIDRequired
	}
	resp, err := h.api.GetCase(ctx, in.ID)
	if err != nil {
		return nil, caseDetail{}, abnormal.APIError(err)
	}
	return nil, caseDetail{
		CaseID: resp.CaseID, CaseStatus: resp.CaseStatus, Severity: resp.Severity,
		AffectedEmployee: resp.AffectedEmployee, CustomerVisibleTime: resp.CustomerVisibleTime,
		FirstObserved: resp.FirstObserved, ThreatIDs: resp.ThreatIDs, Analysis: resp.Analysis,
		RemediationStatus: resp.RemediationStatus, SeverityLevel: resp.SeverityLevel,
		Confidence: resp.Confidence, GenAISummary: resp.GenAISummary,
	}, nil
}

func (h *handlers) getCaseAnalysis(ctx context.Context, _ *mcp.CallToolRequest, in getInput) (*mcp.CallToolResult, caseAnalysisResult, error) {
	if in.ID == "" {
		return nil, caseAnalysisResult{}, errIDRequired
	}
	resp, err := h.api.GetCaseAnalysis(ctx, in.ID)
	if err != nil {
		return nil, caseAnalysisResult{}, abnormal.APIError(err)
	}
	return nil, caseAnalysisResult{
		CaseID: in.ID, Insights: resp.Insights, EventTimeline: resp.EventTimeline,
	}, nil
}

func (h *handlers) getCaseAction(ctx context.Context, _ *mcp.CallToolRequest, in caseActionGetInput) (*mcp.CallToolResult, caseActionStatus, error) {
	if in.CaseID == "" {
		return nil, caseActionStatus{}, errIDRequired
	}
	if in.ActionID == "" {
		return nil, caseActionStatus{}, errActionIDRequired
	}
	resp, err := h.api.GetCaseActionStatus(ctx, in.CaseID, in.ActionID)
	if err != nil {
		return nil, caseActionStatus{}, abnormal.APIError(err)
	}
	out := caseActionStatus{
		CaseID: in.CaseID, ActionID: in.ActionID,
		Status: resp.Status, Description: resp.Description, TenantID: resp.TenantID,
	}
	if resp.TenantName != nil {
		out.TenantName = *resp.TenantName
	}
	return nil, out, nil
}

func (h *handlers) updateCase(ctx context.Context, _ *mcp.CallToolRequest, in caseUpdateInput) (*mcp.CallToolResult, caseUpdateResult, error) {
	if !h.allowResponse {
		return nil, caseUpdateResult{}, errResponseDisabled
	}
	if in.ID == "" {
		return nil, caseUpdateResult{}, errIDRequired
	}
	if in.Action == "" {
		return nil, caseUpdateResult{}, errCaseActionRequired
	}
	preview := caseUpdateResult{
		CaseID: in.ID, Action: in.Action,
		Summary: fmt.Sprintf("Would update case %s to %s", in.ID, in.Action),
	}
	if !in.Confirm {
		preview.Error = errConfirmationRequired
		return nil, preview, nil
	}
	resp, err := h.api.UpdateCase(ctx, in.ID, in.Action)
	if err != nil {
		return nil, caseUpdateResult{}, abnormal.APIError(err)
	}
	preview.Confirmed = true
	preview.ActionID = resp.ActionID
	preview.StatusURL = resp.StatusURL
	preview.Summary = fmt.Sprintf("Updated case %s (action_id=%s). Poll abnormal_case_action_get for status.", in.ID, resp.ActionID)
	return nil, preview, nil
}
