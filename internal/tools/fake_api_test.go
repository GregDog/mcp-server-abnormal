package tools

import (
	"context"
	"errors"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type fakeAPI struct{}

func (f *fakeAPI) ListThreats(_ context.Context, _ abnormal.ListThreatsParams) (abnormal.PaginatedThreats, error) {
	return abnormal.PaginatedThreats{
		Threats:    []abnormal.ThreatRef{{ThreatID: "threat-1"}},
		PageNumber: 1,
	}, nil
}

func (f *fakeAPI) GetThreat(_ context.Context, id string, _, _ int) (abnormal.ThreatDetails, error) {
	if id == "" {
		return abnormal.ThreatDetails{}, errors.New("missing id")
	}
	return abnormal.ThreatDetails{
		ThreatID:       id,
		RecipientCount: 1,
		Messages: []abnormal.ThreatMessage{{
			ThreatID:     id,
			AbxMessageID: 123,
			Subject:      "test",
		}},
	}, nil
}

func (f *fakeAPI) SearchMessages(_ context.Context, req abnormal.SearchRequest, _, _ int) (abnormal.SearchResponse, error) {
	return abnormal.SearchResponse{
		Results: []abnormal.SearchResult{{
			Subject: strPtr("hello"),
		}},
		Total:      1,
		PageNumber: 1,
		PageSize:   20,
	}, nil
}

func (f *fakeAPI) ListSearchActivities(_ context.Context, _ abnormal.ListActivitiesParams) (abnormal.ActivitiesResponse, error) {
	return abnormal.ActivitiesResponse{
		Activities: []abnormal.ActivityLogEntry{{ActivityID: 1, Action: "search", Status: "completed"}},
		Total:      1,
		PageNumber: 1,
		PageSize:   20,
	}, nil
}

func (f *fakeAPI) GetSearchActivityStatus(_ context.Context, id int) (abnormal.ActivityStatusResponse, error) {
	return abnormal.ActivityStatusResponse{ActivityID: id, Action: "delete", Status: "completed"}, nil
}

func (f *fakeAPI) GetRemediationHistory(_ context.Context, messageID int64) (abnormal.RemediationHistory, error) {
	return abnormal.RemediationHistory{
		RemediationHistory: map[string]string{"Auto-Remediated": "2024-01-01T00:00:00Z"},
		FolderLocations:    []abnormal.FolderLocation{{Name: "junk", DisplayName: "Junk"}},
	}, nil
}

func (f *fakeAPI) ListAbuseCampaigns(_ context.Context, _ abnormal.ListAbuseCampaignsParams) (abnormal.PaginatedAbuseCampaigns, error) {
	return abnormal.PaginatedAbuseCampaigns{
		Campaigns:  []abnormal.AbuseCampaignRef{{CampaignID: "camp-1"}},
		PageNumber: 1,
	}, nil
}

func (f *fakeAPI) GetAbuseCampaign(_ context.Context, id string) (abnormal.AbuseCampaignDetails, error) {
	return abnormal.AbuseCampaignDetails{CampaignID: id, Subject: "spam"}, nil
}

func (f *fakeAPI) ListUnanalyzedMailbox(_ context.Context, _, _ string) (abnormal.AbuseMailboxUnanalyzedResponse, error) {
	return abnormal.AbuseMailboxUnanalyzedResponse{
		Results: []abnormal.AbuseMailboxUnanalyzedMessage{{
			Subject:           "fwd",
			AbxMessageID:      99,
			NotAnalyzedReason: "timeout",
		}},
	}, nil
}

func (f *fakeAPI) RemediateSearch(_ context.Context, _ abnormal.RemediationRequest) (abnormal.RemediationResponse, error) {
	return abnormal.RemediationResponse{ActivityLogID: 42}, nil
}

func (f *fakeAPI) RemediateThreat(_ context.Context, id, action string) (abnormal.PostThreatResponse, error) {
	return abnormal.PostThreatResponse{
		ActionID:  "action-1",
		StatusURL: "/threats/" + id + "/actions/action-1",
	}, nil
}

func (f *fakeAPI) GetThreatActionStatus(_ context.Context, _, _ string) (abnormal.ThreatActionStatus, error) {
	return abnormal.ThreatActionStatus{Status: "completed", Description: "done"}, nil
}

func (f *fakeAPI) GetThreatLinks(_ context.Context, id string) (abnormal.ThreatLinksResponse, error) {
	return abnormal.ThreatLinksResponse{
		Links: []abnormal.ThreatLink{{AbxMessageID: 1, LinkURL: "http://evil.example", DomainLink: "evil.example"}},
	}, nil
}

func (f *fakeAPI) GetThreatAttachments(_ context.Context, id string) (abnormal.ThreatAttachmentsResponse, error) {
	return abnormal.ThreatAttachmentsResponse{
		Attachments: []abnormal.ThreatAttachment{{AbxMessageID: 1, AttachmentName: "invoice.pdf"}},
	}, nil
}

func (f *fakeAPI) GetEmployee(_ context.Context, email string) (abnormal.EmployeeDetails, error) {
	return abnormal.EmployeeDetails{Name: "Alice", Email: email, Title: "Analyst", Manager: "boss@example.com"}, nil
}

func (f *fakeAPI) GetEmployeeIdentity(_ context.Context, email string) (abnormal.EmployeeIdentityDetails, error) {
	return abnormal.EmployeeIdentityDetails{
		Data: []abnormal.EmployeeGenomeDetail{{Key: "ip_address", Value: "1.2.3.4"}},
	}, nil
}

func (f *fakeAPI) GetEmployeeLogins(_ context.Context, email string, _ int) ([]abnormal.EmployeeLoginRow, error) {
	return []abnormal.EmployeeLoginRow{{UserPrincipalName: email, Status: "Success"}}, nil
}

func (f *fakeAPI) ListCases(_ context.Context, _ abnormal.ListCasesParams) (abnormal.PaginatedCases, error) {
	return abnormal.PaginatedCases{
		Cases:      []abnormal.AbnormalCaseRef{{CaseID: "case-1", Description: "ATO"}},
		PageNumber: 1,
	}, nil
}

func (f *fakeAPI) GetCase(_ context.Context, id string) (abnormal.AbnormalCaseDetails, error) {
	return abnormal.AbnormalCaseDetails{CaseID: id, Severity: "High"}, nil
}

func (f *fakeAPI) GetCaseAnalysis(_ context.Context, id string) (abnormal.CaseAnalysis, error) {
	return abnormal.CaseAnalysis{
		Insights:      []map[string]any{{"type": "login"}},
		EventTimeline: []map[string]any{{"event": "sign-in"}},
	}, nil
}

func (f *fakeAPI) GetCaseActionStatus(_ context.Context, _, _ string) (abnormal.CaseActionStatus, error) {
	return abnormal.CaseActionStatus{Status: "completed", Description: "done"}, nil
}

func (f *fakeAPI) UpdateCase(_ context.Context, id, action string) (abnormal.PostCaseResponse, error) {
	return abnormal.PostCaseResponse{ActionID: "act-1", StatusURL: "/cases/" + id + "/actions/act-1"}, nil
}

func (f *fakeAPI) ListVendors(_ context.Context, _ abnormal.ListVendorsParams) (abnormal.PaginatedVendors, error) {
	return abnormal.PaginatedVendors{
		Vendors:    []abnormal.VendorRef{{VendorDomain: "vendor.com"}},
		PageNumber: 1,
	}, nil
}

func (f *fakeAPI) GetVendorDetails(_ context.Context, domain string) (abnormal.VendorDetail, error) {
	return abnormal.VendorDetail{VendorDomain: domain, RiskLevel: "High"}, nil
}

func (f *fakeAPI) GetVendorActivity(_ context.Context, domain string) (abnormal.VendorActivity, error) {
	return abnormal.VendorActivity{
		EventTimeline: []map[string]any{{"vendor": domain}},
	}, nil
}

func (f *fakeAPI) ListVendorCases(_ context.Context, _ abnormal.ListVendorCasesParams) (abnormal.PaginatedVendorCases, error) {
	return abnormal.PaginatedVendorCases{
		VendorCases: []abnormal.VendorCaseRef{{VendorCaseID: 99}},
		PageNumber:  1,
	}, nil
}

func (f *fakeAPI) GetVendorCase(_ context.Context, id string) (abnormal.VendorCaseDetails, error) {
	return abnormal.VendorCaseDetails{VendorCaseID: 99, VendorDomain: "vendor.com"}, nil
}

func (f *fakeAPI) DownloadMessageEML(_ context.Context, messageID int64) (abnormal.BinaryResponse, error) {
	return abnormal.BinaryResponse{
		ContentType: "message/rfc822",
		Data:        []byte("From: sender@example.com\r\nSubject: test\r\n"),
	}, nil
}

func (f *fakeAPI) DownloadSearchMessageEML(_ context.Context, cloudMessageID, _, _ string) (abnormal.BinaryResponse, error) {
	return abnormal.BinaryResponse{
		ContentType: "message/rfc822",
		Data:        []byte("From: sender@example.com\r\nSubject: " + cloudMessageID + "\r\n"),
	}, nil
}

func (f *fakeAPI) GetMessageAttachmentSignals(_ context.Context, messageID int64, attachmentName string) (abnormal.AttachmentSignals, error) {
	return abnormal.AttachmentSignals{
		"message_id":      messageID,
		"attachment_name": attachmentName,
		"risk_score":      0.9,
	}, nil
}

func (f *fakeAPI) DownloadMessageAttachment(_ context.Context, messageID int64, attachmentName string) (abnormal.BinaryResponse, error) {
	return abnormal.BinaryResponse{
		ContentType: "application/pdf",
		Data:        []byte("%PDF-1.4 fake " + attachmentName),
	}, nil
}

func (f *fakeAPI) DownloadSearchAttachment(_ context.Context, params abnormal.SearchAttachmentDownloadParams) (abnormal.BinaryResponse, error) {
	return abnormal.BinaryResponse{
		ContentType: "application/pdf",
		Data:        []byte("%PDF-1.4 " + params.AttachmentName),
	}, nil
}

func (f *fakeAPI) ListDetection360Reports(_ context.Context, params abnormal.ListDetection360ReportsParams) ([]abnormal.Detection360Case, error) {
	return []abnormal.Detection360Case{{
		ID:                 1,
		InquiryType:        params.InquiryType,
		Status:             "UNREVIEWED",
		SubmissionDatetime: "2026-01-01T00:00:00Z",
		SubmittedBy:        abnormal.User{Name: "Analyst", Email: "analyst@example.com"},
		Messages:           []int64{123},
	}}, nil
}

func (f *fakeAPI) SubmitDetection360Report(_ context.Context, req abnormal.Detection360SubmitRequest) error {
	if req.ReportType == "" {
		return errors.New("missing report_type")
	}
	return nil
}

func (f *fakeAPI) ListClickedEvents(_ context.Context, _ abnormal.ListClickedEventsParams) (abnormal.ClickedEventsResponse, error) {
	return abnormal.ClickedEventsResponse{
		Data: []abnormal.SoarClickedEvent{{
			Type:        "Click",
			Link:        "https://example.com",
			ClickedTime: 1704067200,
			User:        abnormal.SoarUserAddress{EmailAddress: "user@example.com"},
		}},
		Metadata: abnormal.ClickedEventsResponseMetadata{
			Pagination: abnormal.ClickedEventsPaginationMetadata{},
		},
	}, nil
}

func (f *fakeAPI) ListAuditLogs(_ context.Context, _ abnormal.ListAuditLogsParams) (abnormal.AuditLogResponse, error) {
	return abnormal.AuditLogResponse{
		AuditLogs: []abnormal.AuditLog{{
			Timestamp:  "2026-01-01T00:00:00Z",
			Category:   "threat_log",
			Action:     "view_message_content",
			Status:     "SUCCESS",
			SourceIP:   "1.2.3.4",
			TenantName: "Example",
			User:       abnormal.AuditLogUser{Email: "analyst@example.com"},
		}},
		PageNumber: 1,
	}, nil
}

func testHandlers() *handlers {
	return &handlers{api: &fakeAPI{}}
}

func testResponseHandlers() *handlers {
	return &handlers{api: &fakeAPI{}, allowResponse: true}
}

func testEvidenceHandlers() *handlers {
	return &handlers{api: &fakeAPI{}, allowEvidenceDownload: true}
}
