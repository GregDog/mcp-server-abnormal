package abnormal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/GregDog/mcp-server-abnormal/internal/config"
)

const httpTimeout = 30 * time.Second

// API is the subset of the Abnormal REST API used by MCP tools.
type API interface {
	ListThreats(ctx context.Context, params ListThreatsParams) (PaginatedThreats, error)
	GetThreat(ctx context.Context, threatID string, pageSize, pageNumber int) (ThreatDetails, error)
	SearchMessages(ctx context.Context, req SearchRequest, pageSize, pageNumber int) (SearchResponse, error)
	ListSearchActivities(ctx context.Context, params ListActivitiesParams) (ActivitiesResponse, error)
	GetSearchActivityStatus(ctx context.Context, activityLogID int) (ActivityStatusResponse, error)
	GetRemediationHistory(ctx context.Context, messageID int64) (RemediationHistory, error)
	ListAbuseCampaigns(ctx context.Context, params ListAbuseCampaignsParams) (PaginatedAbuseCampaigns, error)
	GetAbuseCampaign(ctx context.Context, campaignID string) (AbuseCampaignDetails, error)
	ListUnanalyzedMailbox(ctx context.Context, start, end string) (AbuseMailboxUnanalyzedResponse, error)
	RemediateSearch(ctx context.Context, req RemediationRequest) (RemediationResponse, error)
	RemediateThreat(ctx context.Context, threatID string, action string) (PostThreatResponse, error)
	GetThreatActionStatus(ctx context.Context, threatID, actionID string) (ThreatActionStatus, error)
	GetThreatLinks(ctx context.Context, threatID string) (ThreatLinksResponse, error)
	GetThreatAttachments(ctx context.Context, threatID string) (ThreatAttachmentsResponse, error)
	GetEmployee(ctx context.Context, email string) (EmployeeDetails, error)
	GetEmployeeIdentity(ctx context.Context, email string) (EmployeeIdentityDetails, error)
	GetEmployeeLogins(ctx context.Context, email string, maxRows int) ([]EmployeeLoginRow, error)
	ListCases(ctx context.Context, params ListCasesParams) (PaginatedCases, error)
	GetCase(ctx context.Context, caseID string) (AbnormalCaseDetails, error)
	GetCaseAnalysis(ctx context.Context, caseID string) (CaseAnalysis, error)
	GetCaseActionStatus(ctx context.Context, caseID, actionID string) (CaseActionStatus, error)
	UpdateCase(ctx context.Context, caseID, action string) (PostCaseResponse, error)
	ListVendors(ctx context.Context, params ListVendorsParams) (PaginatedVendors, error)
	GetVendorDetails(ctx context.Context, vendorDomain string) (VendorDetail, error)
	GetVendorActivity(ctx context.Context, vendorDomain string) (VendorActivity, error)
	ListVendorCases(ctx context.Context, params ListVendorCasesParams) (PaginatedVendorCases, error)
	GetVendorCase(ctx context.Context, caseID string) (VendorCaseDetails, error)
}

// ListThreatsParams are query parameters for GET /threats.
type ListThreatsParams struct {
	Filter     string
	PageSize   int
	PageNumber int
	Source     string
	Sender     string
	Recipient  string
	Subject    string
	AttackType string
}

// ListActivitiesParams are query parameters for GET /search/activities.
type ListActivitiesParams struct {
	TenantIDs  string
	PageSize   int
	PageNumber int
	Action     string
}

// ListAbuseCampaignsParams are query parameters for GET /abusecampaigns.
type ListAbuseCampaignsParams struct {
	Filter     string
	PageSize   int
	PageNumber int
	Sender     string
	Recipient  string
	Subject    string
	Reporter   string
	AttackType string
	ThreatType string
}

// SearchRequest is the body for POST /search.
type SearchRequest struct {
	Source    string        `json:"source"`
	Filters   SearchFilters `json:"filters"`
	TenantIDs []int         `json:"tenant_ids,omitempty"`
}

// SearchFilters maps to the official Search and Respond API filters.
type SearchFilters struct {
	StartTime         string  `json:"start_time"`
	EndTime           string  `json:"end_time"`
	Subject           *string `json:"subject,omitempty"`
	SenderEmail       *string `json:"sender_email,omitempty"`
	SenderName        *string `json:"sender_name,omitempty"`
	RecipientEmail    *string `json:"recipient_email,omitempty"`
	RecipientName     *string `json:"recipient_name,omitempty"`
	AttachmentName    *string `json:"attachment_name,omitempty"`
	InternetMessageID *string `json:"internet_message_id,omitempty"`
	BodyLink          *string `json:"body_link,omitempty"`
	SenderIP          *string `json:"sender_ip,omitempty"`
	Judgement         *string `json:"judgement,omitempty"`
	JudgementSource   *string `json:"judgement_source,omitempty"`
	UseSenderRegex    *bool   `json:"use_sender_regex,omitempty"`
	UseRecipientRegex *bool   `json:"use_recipient_regex,omitempty"`
}

type ThreatRef struct {
	ThreatID string `json:"threatId"`
}

type PaginatedThreats struct {
	Threats        []ThreatRef `json:"threats"`
	PageNumber     int         `json:"pageNumber"`
	NextPageNumber int         `json:"nextPageNumber"`
}

type ThreatDetails struct {
	ThreatID       string          `json:"threatId"`
	RecipientCount int             `json:"recipientCount"`
	Messages       []ThreatMessage `json:"messages"`
	TenantID       *int            `json:"tenantId"`
	TenantName     *string         `json:"tenantName"`
	PageNumber     int             `json:"pageNumber"`
	NextPageNumber int             `json:"nextPageNumber"`
}

type ThreatMessage struct {
	ThreatID          string   `json:"threatId"`
	AbxMessageID      int64    `json:"abxMessageId"`
	AbxMessageIDStr   string   `json:"abxMessageIdStr"`
	AbxPortalURL      string   `json:"abxPortalUrl"`
	Subject           string   `json:"subject"`
	FromAddress       string   `json:"fromAddress"`
	FromName          string   `json:"fromName"`
	RecipientAddress  string   `json:"recipientAddress"`
	RecipientName     string   `json:"recipientName"`
	ReceivedTime      string   `json:"receivedTime"`
	SentTime          string   `json:"sentTime"`
	RemediationStatus string   `json:"remediationStatus"`
	AttackType        string   `json:"attackType"`
	AttackVector      string   `json:"attackVector"`
	ToAddresses       []string `json:"toAddresses"`
	SenderDomain      string   `json:"senderDomain"`
}

type SearchResponse struct {
	Results        []SearchResult `json:"results"`
	Total          int            `json:"total"`
	PageNumber     int            `json:"pageNumber"`
	PageSize       int            `json:"pageSize"`
	NextPageNumber *int           `json:"nextPageNumber"`
}

type SearchResult struct {
	CustomerID          *int           `json:"customer_id"`
	TenantID            *int           `json:"tenant_id"`
	ReceivedTime        *string        `json:"received_time"`
	Subject             *string        `json:"subject"`
	Sender              *string        `json:"sender"`
	SenderDisplayName   *string        `json:"sender_display_name"`
	MailboxName         *string        `json:"mailbox_name"`
	MailboxDisplayName  *string        `json:"mailbox_display_name"`
	CurrentFolderName   *string        `json:"current_folder_name"`
	RawMessageID        *string        `json:"raw_message_id"`
	NativeUserID        *string        `json:"native_user_id"`
	CloudMessageID      *string        `json:"cloud_message_id"`
	InternetMessageID   *string        `json:"internet_message_id"`
	AbnormalMessageID   *string        `json:"abnormal_message_id"`
	AbnormalMessageUUID *string        `json:"abnormal_message_uuid"`
	DecisionCategory    *string        `json:"decision_category"`
	Judgement           *string        `json:"judgement"`
	JudgementSource     *string        `json:"judgement_source"`
	Attachments         map[string]any `json:"attachments"`
	BodyLinks           []string       `json:"body_links"`
	SenderIPAddresses   []string       `json:"sender_ip_addresses"`
}

type ActivitiesResponse struct {
	Activities []ActivityLogEntry `json:"activities"`
	Total      int                `json:"total"`
	PageNumber int                `json:"pageNumber"`
	PageSize   int                `json:"pageSize"`
}

type ActivityLogEntry struct {
	ActivityID  int    `json:"activity_id"`
	Action      string `json:"action"`
	Status      string `json:"status"`
	PerformedBy string `json:"performed_by"`
	Timestamp   string `json:"timestamp"`
	ResultCount int    `json:"result_count"`
}

type ActivityStatusResponse struct {
	ActivityID         int                 `json:"activity_id"`
	Action             string              `json:"action"`
	Status             string              `json:"status"`
	PerformedBy        string              `json:"performed_by"`
	Timestamp          string              `json:"timestamp"`
	ResultCount        int                 `json:"result_count"`
	RemediationDetails []RemediationDetail `json:"remediation_details"`
	Total              int                 `json:"total"`
	PageNumber         int                 `json:"pageNumber"`
	PageSize           int                 `json:"pageSize"`
}

type RemediationDetail struct {
	TenantID     int    `json:"tenant_id"`
	RawMessageID string `json:"raw_message_id"`
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message"`
}

type FolderLocation struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type RemediationHistory struct {
	RemediationHistory map[string]string `json:"remediation_history"`
	FolderLocations    []FolderLocation  `json:"folder_locations"`
}

type MessageToRemediate struct {
	TenantID            int     `json:"tenant_id"`
	RawMessageID        string  `json:"raw_message_id"`
	AbnormalMessageID   *string `json:"abnormal_message_id,omitempty"`
	AbnormalMessageUUID *string `json:"abnormal_message_uuid,omitempty"`
	MailboxName         string  `json:"mailbox_name"`
	NativeUserID        string  `json:"native_user_id"`
	Subject             string  `json:"subject"`
	Sender              string  `json:"sender"`
	ReceivedTime        string  `json:"received_time"`
}

type RemediationRequest struct {
	Action            string               `json:"action"`
	Source            string               `json:"source"`
	RemediationReason string               `json:"remediation_reason"`
	TargetFolder      *string              `json:"target_folder,omitempty"`
	SubmitD360Case    *bool                `json:"submit_d360_case,omitempty"`
	Messages          []MessageToRemediate `json:"messages,omitempty"`
	RemediateAll      *bool                `json:"remediate_all,omitempty"`
	SearchFilters     *SearchFilters       `json:"search_filters,omitempty"`
	TenantIDs         []int                `json:"tenant_ids,omitempty"`
}

type RemediationResponse struct {
	ActivityLogID int `json:"activity_log_id"`
}

type PostThreatRequest struct {
	Action string `json:"action"`
}

type PostThreatResponse struct {
	ActionID   string  `json:"action_id"`
	StatusURL  string  `json:"status_url"`
	TenantID   *int    `json:"tenantId"`
	TenantName *string `json:"tenantName"`
}

type ThreatActionStatus struct {
	Status      string  `json:"status"`
	Description string  `json:"description"`
	TenantID    *int    `json:"tenantId"`
	TenantName  *string `json:"tenantName"`
}

type AbuseCampaignRef struct {
	CampaignID string `json:"campaignId"`
}

type PaginatedAbuseCampaigns struct {
	Campaigns      []AbuseCampaignRef `json:"campaigns"`
	PageNumber     int                `json:"pageNumber"`
	NextPageNumber int                `json:"nextPageNumber"`
}

type AbuseCampaignDetails struct {
	CampaignID       string `json:"campaignId"`
	FirstReported    string `json:"firstReported"`
	LastReported     string `json:"lastReported"`
	MessageID        string `json:"messageId"`
	Subject          string `json:"subject"`
	FromName         string `json:"fromName"`
	FromAddress      string `json:"fromAddress"`
	RecipientName    string `json:"recipientName"`
	RecipientAddress string `json:"recipientAddress"`
	JudgementStatus  string `json:"judgementStatus"`
	OverallStatus    string `json:"overallStatus"`
	AttackType       string `json:"attackType"`
}

type AbuseMailboxUnanalyzedResponse struct {
	Results []AbuseMailboxUnanalyzedMessage `json:"results"`
}

type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type AbuseMailboxUnanalyzedMessage struct {
	Subject           string `json:"subject"`
	AbxMessageID      int64  `json:"abx_message_id"`
	ReportedDatetime  string `json:"reported_datetime"`
	Recipient         User   `json:"recipient"`
	Reporter          User   `json:"reporter"`
	NotAnalyzedReason string `json:"not_analyzed_reason"`
}

// New constructs the Abnormal API client. It does not call the API.
func New(cfg config.Config) (API, error) {
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	maxRetries := cfg.HTTPMaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	return &client{
		baseURL:    baseURL,
		token:      cfg.APIToken,
		mockData:   cfg.MockData,
		maxRetries: maxRetries,
		http: &http.Client{
			Timeout: httpTimeout,
		},
	}, nil
}

type client struct {
	baseURL    string
	token      string
	mockData   bool
	maxRetries int
	http       *http.Client
}

func (c *client) ListThreats(ctx context.Context, params ListThreatsParams) (PaginatedThreats, error) {
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
	if params.Source != "" {
		q.Set("source", params.Source)
	}
	if params.Sender != "" {
		q.Set("sender", params.Sender)
	}
	if params.Recipient != "" {
		q.Set("recipient", params.Recipient)
	}
	if params.Subject != "" {
		q.Set("subject", params.Subject)
	}
	if params.AttackType != "" {
		q.Set("attackType", params.AttackType)
	}
	var out PaginatedThreats
	err := c.doJSON(ctx, http.MethodGet, "/threats", q, nil, &out)
	return out, err
}

func (c *client) GetThreat(ctx context.Context, threatID string, pageSize, pageNumber int) (ThreatDetails, error) {
	q := url.Values{}
	if pageSize > 0 {
		q.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pageNumber > 0 {
		q.Set("pageNumber", strconv.Itoa(pageNumber))
	}
	var out ThreatDetails
	err := c.doJSON(ctx, http.MethodGet, "/threats/"+url.PathEscape(threatID), q, nil, &out)
	return out, err
}

func (c *client) SearchMessages(ctx context.Context, req SearchRequest, pageSize, pageNumber int) (SearchResponse, error) {
	q := url.Values{}
	if pageSize > 0 {
		q.Set("pageSize", strconv.Itoa(pageSize))
	}
	if pageNumber > 0 {
		q.Set("pageNumber", strconv.Itoa(pageNumber))
	}
	var out SearchResponse
	err := c.doJSON(ctx, http.MethodPost, "/search", q, req, &out)
	return out, err
}

func (c *client) ListSearchActivities(ctx context.Context, params ListActivitiesParams) (ActivitiesResponse, error) {
	q := url.Values{}
	if params.TenantIDs != "" {
		q.Set("tenant_ids", params.TenantIDs)
	}
	if params.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(params.PageSize))
	}
	if params.PageNumber > 0 {
		q.Set("pageNumber", strconv.Itoa(params.PageNumber))
	}
	if params.Action != "" {
		q.Set("action", params.Action)
	}
	var out ActivitiesResponse
	err := c.doJSON(ctx, http.MethodGet, "/search/activities", q, nil, &out)
	return out, err
}

func (c *client) GetSearchActivityStatus(ctx context.Context, activityLogID int) (ActivityStatusResponse, error) {
	var out ActivityStatusResponse
	err := c.doJSON(ctx, http.MethodGet, "/search/activities/"+strconv.Itoa(activityLogID)+"/status", nil, nil, &out)
	return out, err
}

func (c *client) GetRemediationHistory(ctx context.Context, messageID int64) (RemediationHistory, error) {
	var out RemediationHistory
	err := c.doJSON(ctx, http.MethodGet, "/messages/"+strconv.FormatInt(messageID, 10)+"/remediation_history", nil, nil, &out)
	return out, err
}

func (c *client) ListAbuseCampaigns(ctx context.Context, params ListAbuseCampaignsParams) (PaginatedAbuseCampaigns, error) {
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
	if params.Sender != "" {
		q.Set("sender", params.Sender)
	}
	if params.Recipient != "" {
		q.Set("recipient", params.Recipient)
	}
	if params.Subject != "" {
		q.Set("subject", params.Subject)
	}
	if params.Reporter != "" {
		q.Set("reporter", params.Reporter)
	}
	if params.AttackType != "" {
		q.Set("attackType", params.AttackType)
	}
	if params.ThreatType != "" {
		q.Set("threatType", params.ThreatType)
	}
	var out PaginatedAbuseCampaigns
	err := c.doJSON(ctx, http.MethodGet, "/abusecampaigns", q, nil, &out)
	return out, err
}

func (c *client) GetAbuseCampaign(ctx context.Context, campaignID string) (AbuseCampaignDetails, error) {
	var out AbuseCampaignDetails
	err := c.doJSON(ctx, http.MethodGet, "/abusecampaigns/"+url.PathEscape(campaignID), nil, nil, &out)
	return out, err
}

func (c *client) ListUnanalyzedMailbox(ctx context.Context, start, end string) (AbuseMailboxUnanalyzedResponse, error) {
	q := url.Values{}
	if start != "" {
		q.Set("start", start)
	}
	if end != "" {
		q.Set("end", end)
	}
	var out AbuseMailboxUnanalyzedResponse
	err := c.doJSON(ctx, http.MethodGet, "/abuse_mailbox/not_analyzed", q, nil, &out)
	return out, err
}

func (c *client) RemediateSearch(ctx context.Context, req RemediationRequest) (RemediationResponse, error) {
	var out RemediationResponse
	err := c.doJSON(ctx, http.MethodPost, "/search/remediate", nil, req, &out)
	return out, err
}

func (c *client) RemediateThreat(ctx context.Context, threatID, action string) (PostThreatResponse, error) {
	var out PostThreatResponse
	err := c.doJSON(ctx, http.MethodPost, "/threats/"+url.PathEscape(threatID), nil, PostThreatRequest{Action: action}, &out)
	return out, err
}

func (c *client) GetThreatActionStatus(ctx context.Context, threatID, actionID string) (ThreatActionStatus, error) {
	var out ThreatActionStatus
	path := "/threats/" + url.PathEscape(threatID) + "/actions/" + url.PathEscape(actionID)
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out)
	return out, err
}

func (c *client) doText(ctx context.Context, method, path string, query url.Values, accept string) (string, error) {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return "", fmt.Errorf("parse url: %w", RedactError(err))
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if c.mockData {
		req.Header.Set("Mock-Data", "True")
	}
	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := readLimitedBody(resp, MaxTextResponseBytes)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return "", HTTPStatusError{StatusCode: resp.StatusCode, Message: msg}
	}
	return string(data), nil
}

func (c *client) doJSON(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return fmt.Errorf("parse url: %w", RedactError(err))
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.mockData {
		req.Header.Set("Mock-Data", "True")
	}

	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := readLimitedBody(resp, MaxJSONResponseBytes)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return HTTPStatusError{StatusCode: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// FormatTimeFilter builds the Abnormal `filter` query value for receivedTime
// or lastReportedTime. The returned string is the parameter value only
// (for example `receivedTime gte ... lte ...`); callers pass it to
// url.Values.Set("filter", ...). Prefixing `filter=` here would make the API
// ignore the time window.
func FormatTimeFilter(key, since, until string) string {
	parts := []string{key}
	if since != "" {
		parts = append(parts, "gte", since)
	}
	if until != "" {
		parts = append(parts, "lte", until)
	}
	return strings.Join(parts, " ")
}
