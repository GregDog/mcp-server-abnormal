package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type detection360ReportsListInput struct {
	InquiryType string   `json:"inquiry_type" jsonschema:"MISSED_ATTACK or FALSE_POSITIVE."`
	Since       string   `json:"since,omitempty" jsonschema:"Start time (RFC3339). Default last 30 days."`
	Until       string   `json:"until,omitempty" jsonschema:"End time (RFC3339). Default now."`
	Status      []string `json:"status,omitempty" jsonschema:"Optional status filters: UNREVIEWED, CONTAINING_ATTACK, IMPROVING_PLATFORM, RESOLVED, CORRECTING_JUDGEMENT."`
}

type detection360ReportItem struct {
	ID                 int      `json:"id"`
	InquiryType        string   `json:"inquiry_type"`
	Status             string   `json:"status"`
	SubmissionDatetime string   `json:"submission_datetime"`
	SubmittedByName    string   `json:"submitted_by_name,omitempty"`
	SubmittedByEmail   string   `json:"submitted_by_email,omitempty"`
	MessageIDs         []int64  `json:"message_ids,omitempty"`
	Analysis           string   `json:"analysis,omitempty"`
	RootCauseNames     []string `json:"root_cause_names,omitempty"`
}

type detection360ReportSubmitInput struct {
	Confirm        bool   `json:"confirm" jsonschema:"Must be true to execute. If false, returns a preview only."`
	ReportType     string `json:"report_type" jsonschema:"false-positive, false-negative, missed-attack, missed-spam, or missed-graymail."`
	PortalLink     string `json:"portal_link,omitempty" jsonschema:"Required for false-positive. Abnormal portal threat URL (abx_portal_url from threat results)."`
	RecipientEmail string `json:"recipient_email,omitempty" jsonschema:"Required for missed/false-negative reports."`
	SenderEmail    string `json:"sender_email,omitempty" jsonschema:"Required for missed/false-negative reports."`
	Subject        string `json:"subject,omitempty" jsonschema:"Required for missed/false-negative reports."`
	ReceivedDate   string `json:"received_date,omitempty" jsonschema:"Date received (YYYY-MM-DD)."`
	Description    string `json:"description,omitempty" jsonschema:"Optional analyst context for Abnormal."`
}

type detection360ReportSubmitResult struct {
	Confirmed  bool   `json:"confirmed"`
	Error      string `json:"error,omitempty"`
	Summary    string `json:"summary,omitempty"`
	ReportType string `json:"report_type,omitempty"`
}

func registerDetection360(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_detection360_reports_list",
		Title:       "List Abnormal Detection 360 reports",
		Description: "List submitted Detection 360 misclassification reports (false positives or missed attacks).",
		Annotations: readOnly(),
	}, h.listDetection360Reports)
}

func registerDetection360Response(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_detection360_report_submit",
		Title:       "Submit Abnormal Detection 360 report",
		Description: "Submit a Detection 360 false positive or missed email report. Requires ABNORMAL_ALLOW_RESPONSE=true and confirm: true.",
		Annotations: responseAnnotations(false),
	}, h.submitDetection360Report)
}

func (h *handlers) listDetection360Reports(ctx context.Context, _ *mcp.CallToolRequest, in detection360ReportsListInput) (*mcp.CallToolResult, abnormal.Page[detection360ReportItem], error) {
	inquiryType := strings.ToUpper(strings.TrimSpace(in.InquiryType))
	if inquiryType != "MISSED_ATTACK" && inquiryType != "FALSE_POSITIVE" {
		return nil, abnormal.Page[detection360ReportItem]{}, errDetection360InquiryTypeRequired
	}
	var since, until string
	var err error
	if in.Since == "" && in.Until == "" {
		since, until, err = defaultSinceUntilDays(30)
	} else {
		since, until, err = defaultSinceUntil(in.Since, in.Until)
	}
	if err != nil {
		return nil, abnormal.Page[detection360ReportItem]{}, err
	}

	resp, err := h.api.ListDetection360Reports(ctx, abnormal.ListDetection360ReportsParams{
		InquiryType: inquiryType,
		Start:       since,
		End:         until,
		Status:      in.Status,
	})
	if err != nil {
		return nil, abnormal.Page[detection360ReportItem]{}, abnormal.APIError(err)
	}

	items := make([]detection360ReportItem, 0, len(resp))
	for i, c := range resp {
		if i >= maxBoundedItems {
			break
		}
		item := detection360ReportItem{
			ID:                 c.ID,
			InquiryType:        c.InquiryType,
			Status:             c.Status,
			SubmissionDatetime: c.SubmissionDatetime,
			SubmittedByName:    c.SubmittedBy.Name,
			SubmittedByEmail:   c.SubmittedBy.Email,
			MessageIDs:         boundInt64s(c.Messages, maxBoundedItems),
		}
		if c.Report != nil {
			item.Analysis = trimString(c.Report.Analysis, maxBoundedString)
			for _, rc := range c.Report.RootCauses {
				if len(item.RootCauseNames) >= maxBoundedStrings {
					break
				}
				item.RootCauseNames = append(item.RootCauseNames, trimString(rc.Name, maxBoundedString))
			}
		}
		items = append(items, item)
	}
	return nil, abnormal.Page[detection360ReportItem]{
		Items:      items,
		TotalCount: int64(len(resp)),
	}, nil
}

func (h *handlers) submitDetection360Report(ctx context.Context, _ *mcp.CallToolRequest, in detection360ReportSubmitInput) (*mcp.CallToolResult, detection360ReportSubmitResult, error) {
	if !h.allowResponse {
		return nil, detection360ReportSubmitResult{}, errResponseDisabled
	}
	reportType := strings.ToLower(strings.TrimSpace(in.ReportType))
	if reportType == "" {
		return nil, detection360ReportSubmitResult{}, errDetection360ReportTypeRequired
	}

	preview := detection360ReportSubmitResult{
		ReportType: reportType,
		Summary:    fmt.Sprintf("Would submit Detection 360 %s report", reportType),
	}
	if err := validateDetection360Submit(in); err != nil {
		return nil, detection360ReportSubmitResult{}, err
	}
	if !in.Confirm {
		preview.Error = errConfirmationRequired
		return nil, preview, nil
	}

	req := abnormal.Detection360SubmitRequest{
		ReportType:     reportType,
		PortalLink:     strings.TrimSpace(in.PortalLink),
		RecipientEmail: strings.TrimSpace(in.RecipientEmail),
		SenderEmail:    strings.TrimSpace(in.SenderEmail),
		Subject:        strings.TrimSpace(in.Subject),
		ReceivedDate:   strings.TrimSpace(in.ReceivedDate),
		Description:    strings.TrimSpace(in.Description),
	}
	if err := h.api.SubmitDetection360Report(ctx, req); err != nil {
		return nil, detection360ReportSubmitResult{}, abnormal.APIError(err)
	}
	preview.Confirmed = true
	preview.Summary = fmt.Sprintf("Submitted Detection 360 %s report", reportType)
	logResponseAction("abnormal_detection360_report_submit", "detection360", reportType, "submit")
	return nil, preview, nil
}

func validateDetection360Submit(in detection360ReportSubmitInput) error {
	reportType := strings.ToLower(strings.TrimSpace(in.ReportType))
	switch reportType {
	case "false-positive":
		if strings.TrimSpace(in.PortalLink) == "" {
			return errDetection360PortalLinkRequired
		}
	case "false-negative", "missed-attack", "missed-spam", "missed-graymail":
		if strings.TrimSpace(in.RecipientEmail) == "" || strings.TrimSpace(in.SenderEmail) == "" || strings.TrimSpace(in.Subject) == "" {
			return errDetection360MessageFieldsRequired
		}
	default:
		return errDetection360ReportTypeInvalid
	}
	return nil
}

func boundInt64s(items []int64, max int) []int64 {
	if max <= 0 || len(items) <= max {
		return items
	}
	return items[:max]
}
