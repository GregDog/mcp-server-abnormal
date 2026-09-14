package abnormal

import (
	"context"
	"net/http"
	"net/url"
)

// ListDetection360ReportsParams are query parameters for GET /detection360/reports.
type ListDetection360ReportsParams struct {
	InquiryType string
	Start       string
	End         string
	Status      []string
}

// Detection360Case is a submitted Detection 360 report case.
type Detection360Case struct {
	ID                 int                 `json:"id"`
	InquiryType        string              `json:"inquiry_type"`
	Messages           []int64             `json:"messages"`
	Report             *Detection360Report `json:"report,omitempty"`
	Status             string              `json:"status"`
	SubmissionDatetime string              `json:"submission_datetime"`
	SubmittedBy        User                `json:"submitted_by"`
}

// Detection360Report is analysis returned for a Detection 360 case.
type Detection360Report struct {
	Analysis   string                   `json:"analysis"`
	RootCauses []PortalVisibleRootCause `json:"root_causes"`
}

// PortalVisibleRootCause describes a root cause on a Detection 360 case.
type PortalVisibleRootCause struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Detection360SubmitRequest is the body for POST /detection360/reports.
type Detection360SubmitRequest struct {
	ReportType     string `json:"report_type"`
	PortalLink     string `json:"portal_link,omitempty"`
	RecipientEmail string `json:"recipient_email,omitempty"`
	SenderEmail    string `json:"sender_email,omitempty"`
	Subject        string `json:"subject,omitempty"`
	ReceivedDate   string `json:"received_date,omitempty"`
	Description    string `json:"description,omitempty"`
}

func (c *client) ListDetection360Reports(ctx context.Context, params ListDetection360ReportsParams) ([]Detection360Case, error) {
	q := url.Values{}
	q.Set("inquiry_type", params.InquiryType)
	if params.Start != "" {
		q.Set("start", params.Start)
	}
	if params.End != "" {
		q.Set("end", params.End)
	}
	for _, status := range params.Status {
		if status != "" {
			q.Add("status", status)
		}
	}
	var out []Detection360Case
	err := c.doJSON(ctx, http.MethodGet, "/detection360/reports", q, nil, &out)
	return out, err
}

func (c *client) SubmitDetection360Report(ctx context.Context, req Detection360SubmitRequest) error {
	return c.doJSON(ctx, http.MethodPost, "/detection360/reports", nil, req, nil)
}
