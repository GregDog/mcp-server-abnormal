package abnormal

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type ThreatLinksResponse struct {
	Links      []ThreatLink `json:"links"`
	TenantID   *int         `json:"tenantId"`
	TenantName *string      `json:"tenantName"`
}

type ThreatLink struct {
	AbxMessageID    int64  `json:"abxMessageId"`
	AbxMessageIDStr string `json:"abxMessageIdStr"`
	DomainLink      string `json:"domainLink"`
	LinkType        string `json:"linkType"`
	Source          string `json:"source"`
	DisplayText     string `json:"displayText"`
	LinkURL         string `json:"linkUrl"`
}

type ThreatAttachmentsResponse struct {
	Attachments []ThreatAttachment `json:"attachments"`
	TenantID    *int               `json:"tenantId"`
	TenantName  *string            `json:"tenantName"`
}

type ThreatAttachment struct {
	AbxMessageID    int64  `json:"abxMessageId"`
	AbxMessageIDStr string `json:"abxMessageIdStr"`
	AttachmentName  string `json:"attachmentName"`
}

type EmployeeDetails struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Title   string `json:"title"`
	Manager string `json:"manager"`
}

type EmployeeIdentityDetails struct {
	Data []EmployeeGenomeDetail `json:"data"`
}

type EmployeeGenomeDetail struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type EmployeeLoginRow struct {
	Timestamp           string `json:"timestamp,omitempty"`
	UserPrincipalName   string `json:"user_principal_name,omitempty"`
	UserDisplayName     string `json:"user_display_name,omitempty"`
	Status              string `json:"status,omitempty"`
	IPAddress           string `json:"ip_address,omitempty"`
	City                string `json:"city,omitempty"`
	State               string `json:"state,omitempty"`
	CountryOrRegion     string `json:"country_or_region,omitempty"`
	Latitude            string `json:"latitude,omitempty"`
	Longitude           string `json:"longitude,omitempty"`
	AppDisplayName      string `json:"app_display_name,omitempty"`
	AppID               string `json:"app_id,omitempty"`
	ClientAppUsed       string `json:"client_app_used,omitempty"`
	Browser             string `json:"browser,omitempty"`
	OperatingSystem     string `json:"operating_system,omitempty"`
	DeviceID            string `json:"device_id,omitempty"`
	ResourceDisplayName string `json:"resource_display_name,omitempty"`
}

type ListCasesParams struct {
	Filter     string
	PageSize   int
	PageNumber int
}

type PaginatedCases struct {
	Cases          []AbnormalCaseRef `json:"cases"`
	PageNumber     int               `json:"pageNumber"`
	NextPageNumber int               `json:"nextPageNumber"`
}

type AbnormalCaseRef struct {
	CaseID        string `json:"caseId"`
	Description   string `json:"description"`
	SeverityLevel string `json:"severity_level"`
	Confidence    string `json:"confidence"`
	LastModified  string `json:"last_modified"`
	FirstObserved string `json:"first_observed"`
	Created       string `json:"created"`
	Tenant        string `json:"tenant"`
}

type AbnormalCaseDetails struct {
	CaseID              string   `json:"caseId"`
	CaseStatus          string   `json:"case_status"`
	Severity            string   `json:"severity"`
	AffectedEmployee    string   `json:"affectedEmployee"`
	CustomerVisibleTime string   `json:"customerVisibleTime"`
	FirstObserved       string   `json:"firstObserved"`
	ThreatIDs           []string `json:"threatIds"`
	Analysis            string   `json:"analysis"`
	RemediationStatus   string   `json:"remediation_status"`
	SeverityLevel       string   `json:"severity_level"`
	Confidence          string   `json:"confidence"`
	GenAISummary        []string `json:"genai_summary"`
}

type CaseAnalysis struct {
	Insights      []map[string]any `json:"insights"`
	EventTimeline []map[string]any `json:"eventTimeline"`
}

type CaseActionStatus struct {
	Status      string  `json:"status"`
	Description string  `json:"description"`
	TenantID    *int    `json:"tenantId"`
	TenantName  *string `json:"tenantName"`
}

type PostCaseRequest struct {
	Action string `json:"action"`
}

type PostCaseResponse struct {
	ActionID  string `json:"actionId"`
	StatusURL string `json:"statusUrl"`
}

func (c *client) GetThreatLinks(ctx context.Context, threatID string) (ThreatLinksResponse, error) {
	var out ThreatLinksResponse
	err := c.doJSON(ctx, http.MethodGet, "/threats/"+url.PathEscape(threatID)+"/links", nil, nil, &out)
	return out, err
}

func (c *client) GetThreatAttachments(ctx context.Context, threatID string) (ThreatAttachmentsResponse, error) {
	var out ThreatAttachmentsResponse
	err := c.doJSON(ctx, http.MethodGet, "/threats/"+url.PathEscape(threatID)+"/attachments", nil, nil, &out)
	return out, err
}

func (c *client) GetEmployee(ctx context.Context, email string) (EmployeeDetails, error) {
	var out EmployeeDetails
	err := c.doJSON(ctx, http.MethodGet, "/employee/"+url.PathEscape(email), nil, nil, &out)
	return out, err
}

func (c *client) GetEmployeeIdentity(ctx context.Context, email string) (EmployeeIdentityDetails, error) {
	var out EmployeeIdentityDetails
	err := c.doJSON(ctx, http.MethodGet, "/employee/"+url.PathEscape(email)+"/identity", nil, nil, &out)
	return out, err
}

func (c *client) GetEmployeeLogins(ctx context.Context, email string, maxRows int) ([]EmployeeLoginRow, error) {
	data, err := c.doText(ctx, http.MethodGet, "/employee/"+url.PathEscape(email)+"/logins", nil, "text/csv")
	if err != nil {
		return nil, err
	}
	return parseEmployeeLoginCSV(data, maxRows)
}

func (c *client) ListCases(ctx context.Context, params ListCasesParams) (PaginatedCases, error) {
	q := url.Values{}
	if params.Filter != "" {
		q.Set("filter", params.Filter)
	}
	if params.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(params.PageSize))
	}
	if params.PageNumber > 0 {
		q.Set("pageNumber", strconv.Itoa(params.PageNumber))
	}
	var out PaginatedCases
	err := c.doJSON(ctx, http.MethodGet, "/cases", q, nil, &out)
	return out, err
}

func (c *client) GetCase(ctx context.Context, caseID string) (AbnormalCaseDetails, error) {
	var out AbnormalCaseDetails
	err := c.doJSON(ctx, http.MethodGet, "/cases/"+url.PathEscape(caseID), nil, nil, &out)
	return out, err
}

func (c *client) GetCaseAnalysis(ctx context.Context, caseID string) (CaseAnalysis, error) {
	var out CaseAnalysis
	err := c.doJSON(ctx, http.MethodGet, "/cases/"+url.PathEscape(caseID)+"/analysis", nil, nil, &out)
	return out, err
}

func (c *client) GetCaseActionStatus(ctx context.Context, caseID, actionID string) (CaseActionStatus, error) {
	var out CaseActionStatus
	path := "/cases/" + url.PathEscape(caseID) + "/actions/" + url.PathEscape(actionID)
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out)
	return out, err
}

func (c *client) UpdateCase(ctx context.Context, caseID, action string) (PostCaseResponse, error) {
	var out PostCaseResponse
	err := c.doJSON(ctx, http.MethodPost, "/cases/"+url.PathEscape(caseID), nil, PostCaseRequest{Action: action}, &out)
	return out, err
}

func parseEmployeeLoginCSV(data string, maxRows int) ([]EmployeeLoginRow, error) {
	if maxRows <= 0 {
		maxRows = 50
	}
	reader := csv.NewReader(strings.NewReader(data))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return []EmployeeLoginRow{}, nil
	}
	header := records[0]
	rows := make([]EmployeeLoginRow, 0, min(len(records)-1, maxRows))
	for _, rec := range records[1:] {
		if len(rows) >= maxRows {
			break
		}
		row := EmployeeLoginRow{}
		for i, col := range header {
			if i >= len(rec) {
				continue
			}
			switch strings.TrimSpace(col) {
			case "Timestamp":
				row.Timestamp = rec[i]
			case "User Principal Name":
				row.UserPrincipalName = rec[i]
			case "User Display Name":
				row.UserDisplayName = rec[i]
			case "Status":
				row.Status = rec[i]
			case "IP Address":
				row.IPAddress = rec[i]
			case "City":
				row.City = rec[i]
			case "State":
				row.State = rec[i]
			case "Country or Region":
				row.CountryOrRegion = rec[i]
			case "Latitude":
				row.Latitude = rec[i]
			case "Longitude":
				row.Longitude = rec[i]
			case "App Display Name":
				row.AppDisplayName = rec[i]
			case "App ID":
				row.AppID = rec[i]
			case "Client App Used":
				row.ClientAppUsed = rec[i]
			case "Browser":
				row.Browser = rec[i]
			case "Operating System":
				row.OperatingSystem = rec[i]
			case "Device ID":
				row.DeviceID = rec[i]
			case "Resource Display Name":
				row.ResourceDisplayName = rec[i]
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
