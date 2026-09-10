package tools

import (
	"context"
	"testing"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

func TestMessageEMLDisabled(t *testing.T) {
	h := testHandlers()
	_, _, err := h.getMessageEML(context.Background(), nil, messageEMLInput{MessageID: 1})
	if err != errEvidenceDisabled {
		t.Fatalf("got %v", err)
	}
}

func TestMessageEMLMetadata(t *testing.T) {
	h := testEvidenceHandlers()
	_, out, err := h.getMessageEML(context.Background(), nil, messageEMLInput{MessageID: 42})
	if err != nil {
		t.Fatal(err)
	}
	if out.SizeBytes == 0 || out.SHA256 == "" || out.Preview == "" {
		t.Fatalf("unexpected: %+v", out)
	}
	if out.ContentBase64 != "" {
		t.Fatalf("expected omitted base64 by default")
	}
}

func TestMessageEMLIncludeBase64(t *testing.T) {
	h := testEvidenceHandlers()
	_, out, err := h.getMessageEML(context.Background(), nil, messageEMLInput{
		MessageID:            42,
		IncludeContentBase64: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.ContentBase64 == "" {
		t.Fatalf("expected base64 content")
	}
}

func TestMessageAttachmentSignals(t *testing.T) {
	h := testEvidenceHandlers()
	_, out, err := h.getMessageAttachmentSignals(context.Background(), nil, messageAttachmentGetInput{
		MessageID: 1, AttachmentName: "invoice.pdf",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Signals["attachment_name"] != "invoice.pdf" {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestSearchAttachmentParamsRequired(t *testing.T) {
	h := testEvidenceHandlers()
	_, _, err := h.downloadSearchAttachment(context.Background(), nil, searchAttachmentDownloadInput{
		MessageID: 1, TenantID: 2, AttachmentName: "x.pdf",
	})
	if err != errSearchAttachmentParamsRequired {
		t.Fatalf("got %v", err)
	}
}

func TestPackageEvidencePreviewDisabled(t *testing.T) {
	includePreview := false
	out := packageEvidence(abnormal.BinaryResponse{
		ContentType: "message/rfc822",
		Data:        []byte("From: a@b.com\r\n"),
	}, evidenceContentInput{IncludePreview: &includePreview}.opts())
	if out.Preview != "" {
		t.Fatalf("expected no preview")
	}
}
