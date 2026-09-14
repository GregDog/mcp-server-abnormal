package tools

import (
	"context"
	"testing"
)

func TestListDetection360ReportsRequiresInquiryType(t *testing.T) {
	h := testHandlers()
	_, _, err := h.listDetection360Reports(context.Background(), nil, detection360ReportsListInput{})
	if err != errDetection360InquiryTypeRequired {
		t.Fatalf("got %v", err)
	}
}

func TestListDetection360Reports(t *testing.T) {
	h := testHandlers()
	_, page, err := h.listDetection360Reports(context.Background(), nil, detection360ReportsListInput{
		InquiryType: "FALSE_POSITIVE",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != 1 {
		t.Fatalf("unexpected: %+v", page)
	}
}

func TestSubmitDetection360Disabled(t *testing.T) {
	h := testHandlers()
	_, _, err := h.submitDetection360Report(context.Background(), nil, detection360ReportSubmitInput{
		Confirm: true, ReportType: "false-positive", PortalLink: "https://example.com",
	})
	if err != errResponseDisabled {
		t.Fatalf("got %v", err)
	}
}

func TestSubmitDetection360Preview(t *testing.T) {
	h := testResponseHandlers()
	_, out, err := h.submitDetection360Report(context.Background(), nil, detection360ReportSubmitInput{
		ReportType:     "missed-attack",
		RecipientEmail: "user@example.com", SenderEmail: "bad@evil.com", Subject: "invoice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Error != errConfirmationRequired || out.Confirmed {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestSubmitDetection360FalsePositive(t *testing.T) {
	h := testResponseHandlers()
	_, out, err := h.submitDetection360Report(context.Background(), nil, detection360ReportSubmitInput{
		Confirm: true, ReportType: "false-positive",
		PortalLink: "https://eu.portal.abnormalsecurity.com/home/threat-center/remediation-history/123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Confirmed {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestSubmitDetection360MissedAttackFields(t *testing.T) {
	h := testResponseHandlers()
	_, _, err := h.submitDetection360Report(context.Background(), nil, detection360ReportSubmitInput{
		Confirm: true, ReportType: "missed-attack", SenderEmail: "a@b.com",
	})
	if err != errDetection360MessageFieldsRequired {
		t.Fatalf("got %v", err)
	}
}
