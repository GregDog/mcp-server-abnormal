package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type evidenceContentInput struct {
	IncludePreview       *bool `json:"include_preview,omitempty" jsonschema:"Include a bounded text preview when the payload is text-like. Default true."`
	IncludeContentBase64 bool  `json:"include_content_base64,omitempty" jsonschema:"Embed base64 content when under 1 MiB. Default false."`
}

type messageEMLInput struct {
	MessageID int64 `json:"message_id" jsonschema:"ABX message ID from threat or search results."`
	evidenceContentInput
}

type searchMessageEMLInput struct {
	CloudMessageID     string `json:"cloud_message_id" jsonschema:"cloud_message_id from abnormal_search_messages results."`
	QuarantineIdentity string `json:"quarantine_identity,omitempty" jsonschema:"Required for quarantine messages."`
	RecipientMailbox   string `json:"recipient_mailbox,omitempty" jsonschema:"Required for quarantine messages."`
	evidenceContentInput
}

type messageAttachmentGetInput struct {
	MessageID      int64  `json:"message_id" jsonschema:"ABX message ID."`
	AttachmentName string `json:"attachment_name" jsonschema:"Attachment file name."`
}

type messageAttachmentDownloadInput struct {
	MessageID      int64  `json:"message_id" jsonschema:"ABX message ID."`
	AttachmentName string `json:"attachment_name" jsonschema:"Attachment file name."`
	evidenceContentInput
}

type searchAttachmentDownloadInput struct {
	MessageID        int    `json:"message_id" jsonschema:"Numeric message ID from search results."`
	AttachmentName   string `json:"attachment_name" jsonschema:"Attachment file name."`
	TenantID         int    `json:"tenant_id" jsonschema:"Tenant ID from search results."`
	RawMessageID     string `json:"raw_message_id" jsonschema:"raw_message_id from search results."`
	NativeUserID     string `json:"native_user_id" jsonschema:"native_user_id from search results (mailbox native ID)."`
	RecipientMailbox string `json:"recipient_mailbox" jsonschema:"Recipient mailbox email from search results."`
	evidenceContentInput
}

type attachmentSignalsResult struct {
	MessageID      int64          `json:"message_id"`
	AttachmentName string         `json:"attachment_name"`
	Signals        map[string]any `json:"signals"`
}

func registerEvidence(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_message_eml_get",
		Title:       "Download Abnormal message EML",
		Description: "Download message contents in EML format by ABX message ID. Returns metadata and optional bounded preview/base64 — not raw binary by default. Requires ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD=true.",
		Annotations: evidenceAnnotations(),
	}, h.getMessageEML)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_search_message_eml_get",
		Title:       "Download Abnormal search message EML",
		Description: "Download EML by cloud_message_id from search results. Returns metadata and optional bounded preview/base64. Requires ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD=true.",
		Annotations: evidenceAnnotations(),
	}, h.getSearchMessageEML)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_message_attachment_get",
		Title:       "Get Abnormal message attachment analysis",
		Description: "Get attachment analysis signals for a message attachment. Requires ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD=true.",
		Annotations: evidenceAnnotations(),
	}, h.getMessageAttachmentSignals)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_message_attachment_download",
		Title:       "Download Abnormal message attachment",
		Description: "Download a message attachment file by ABX message ID and attachment name. Returns metadata and optional bounded base64. Requires ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD=true.",
		Annotations: evidenceAnnotations(),
	}, h.downloadMessageAttachment)

	addTool(server, &mcp.Tool{
		Name:        "abnormal_search_attachment_download",
		Title:       "Download Abnormal search message attachment",
		Description: "Download an attachment using search result identifiers. Returns metadata and optional bounded base64. Requires ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD=true.",
		Annotations: evidenceAnnotations(),
	}, h.downloadSearchAttachment)
}

func (h *handlers) getMessageEML(ctx context.Context, _ *mcp.CallToolRequest, in messageEMLInput) (*mcp.CallToolResult, evidencePackageResult, error) {
	if !h.allowEvidenceDownload {
		return nil, evidencePackageResult{}, errEvidenceDisabled
	}
	if in.MessageID <= 0 {
		return nil, evidencePackageResult{}, errMessageIDRequired
	}
	resp, err := h.api.DownloadMessageEML(ctx, in.MessageID)
	if err != nil {
		return nil, evidencePackageResult{}, abnormal.APIError(err)
	}
	logEvidenceAccess("abnormal_message_eml_get", fmt.Sprintf("message_id=%d", in.MessageID), len(resp.Data))
	return nil, packageEvidence(resp, in.opts()), nil
}

func (h *handlers) getSearchMessageEML(ctx context.Context, _ *mcp.CallToolRequest, in searchMessageEMLInput) (*mcp.CallToolResult, evidencePackageResult, error) {
	if !h.allowEvidenceDownload {
		return nil, evidencePackageResult{}, errEvidenceDisabled
	}
	if in.CloudMessageID == "" {
		return nil, evidencePackageResult{}, errCloudMessageIDRequired
	}
	resp, err := h.api.DownloadSearchMessageEML(ctx, in.CloudMessageID, in.QuarantineIdentity, in.RecipientMailbox)
	if err != nil {
		return nil, evidencePackageResult{}, abnormal.APIError(err)
	}
	logEvidenceAccess("abnormal_search_message_eml_get", "cloud_message_id="+in.CloudMessageID, len(resp.Data))
	return nil, packageEvidence(resp, in.opts()), nil
}

func (h *handlers) getMessageAttachmentSignals(ctx context.Context, _ *mcp.CallToolRequest, in messageAttachmentGetInput) (*mcp.CallToolResult, attachmentSignalsResult, error) {
	if !h.allowEvidenceDownload {
		return nil, attachmentSignalsResult{}, errEvidenceDisabled
	}
	if in.MessageID <= 0 {
		return nil, attachmentSignalsResult{}, errMessageIDRequired
	}
	if in.AttachmentName == "" {
		return nil, attachmentSignalsResult{}, errAttachmentNameRequired
	}
	signals, err := h.api.GetMessageAttachmentSignals(ctx, in.MessageID, in.AttachmentName)
	if err != nil {
		return nil, attachmentSignalsResult{}, abnormal.APIError(err)
	}
	logEvidenceAccess("abnormal_message_attachment_get", fmt.Sprintf("message_id=%d attachment=%s", in.MessageID, in.AttachmentName), 0)
	return nil, attachmentSignalsResult{
		MessageID:      in.MessageID,
		AttachmentName: in.AttachmentName,
		Signals:        abnormal.MarshalAttachmentSignals(signals, maxBoundedItems),
	}, nil
}

func (h *handlers) downloadMessageAttachment(ctx context.Context, _ *mcp.CallToolRequest, in messageAttachmentDownloadInput) (*mcp.CallToolResult, evidencePackageResult, error) {
	if !h.allowEvidenceDownload {
		return nil, evidencePackageResult{}, errEvidenceDisabled
	}
	if in.MessageID <= 0 {
		return nil, evidencePackageResult{}, errMessageIDRequired
	}
	if in.AttachmentName == "" {
		return nil, evidencePackageResult{}, errAttachmentNameRequired
	}
	resp, err := h.api.DownloadMessageAttachment(ctx, in.MessageID, in.AttachmentName)
	if err != nil {
		return nil, evidencePackageResult{}, abnormal.APIError(err)
	}
	logEvidenceAccess("abnormal_message_attachment_download", fmt.Sprintf("message_id=%d attachment=%s", in.MessageID, in.AttachmentName), len(resp.Data))
	return nil, packageEvidence(resp, in.opts()), nil
}

func (h *handlers) downloadSearchAttachment(ctx context.Context, _ *mcp.CallToolRequest, in searchAttachmentDownloadInput) (*mcp.CallToolResult, evidencePackageResult, error) {
	if !h.allowEvidenceDownload {
		return nil, evidencePackageResult{}, errEvidenceDisabled
	}
	if in.MessageID <= 0 || in.TenantID <= 0 || in.AttachmentName == "" ||
		in.RawMessageID == "" || in.NativeUserID == "" || in.RecipientMailbox == "" {
		return nil, evidencePackageResult{}, errSearchAttachmentParamsRequired
	}
	resp, err := h.api.DownloadSearchAttachment(ctx, abnormal.SearchAttachmentDownloadParams{
		MessageID: in.MessageID, AttachmentName: in.AttachmentName, TenantID: in.TenantID,
		RawMessageID: in.RawMessageID, NativeUserID: in.NativeUserID, RecipientMailbox: in.RecipientMailbox,
	})
	if err != nil {
		return nil, evidencePackageResult{}, abnormal.APIError(err)
	}
	logEvidenceAccess("abnormal_search_attachment_download", fmt.Sprintf("message_id=%d attachment=%s", in.MessageID, in.AttachmentName), len(resp.Data))
	return nil, packageEvidence(resp, in.opts()), nil
}

func (in evidenceContentInput) opts() evidencePackageOptions {
	includePreview := true
	if in.IncludePreview != nil {
		includePreview = *in.IncludePreview
	}
	return evidencePackageOptions{
		IncludePreview:       includePreview,
		IncludeContentBase64: in.IncludeContentBase64,
	}
}
