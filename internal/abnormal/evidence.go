package abnormal

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

type BinaryResponse struct {
	ContentType string
	Data        []byte
}

type SearchAttachmentDownloadParams struct {
	MessageID        int
	AttachmentName   string
	TenantID         int
	RawMessageID     string
	NativeUserID     string
	RecipientMailbox string
}

type AttachmentSignals map[string]any

func (c *client) DownloadMessageEML(ctx context.Context, messageID int64) (BinaryResponse, error) {
	path := "/messages/" + strconv.FormatInt(messageID, 10) + "/download"
	return c.doDownload(ctx, http.MethodGet, path, nil, c.maxEvidenceBytes)
}

func (c *client) DownloadSearchMessageEML(ctx context.Context, cloudMessageID, quarantineIdentity, recipientMailbox string) (BinaryResponse, error) {
	q := url.Values{}
	if quarantineIdentity != "" {
		q.Set("quarantineIdentity", quarantineIdentity)
	}
	if recipientMailbox != "" {
		q.Set("recipientMailbox", recipientMailbox)
	}
	path := "/search/messages/" + url.PathEscape(cloudMessageID) + "/eml"
	return c.doDownload(ctx, http.MethodGet, path, q, c.maxEvidenceBytes)
}

func (c *client) GetMessageAttachmentSignals(ctx context.Context, messageID int64, attachmentName string) (AttachmentSignals, error) {
	path := "/messages/" + strconv.FormatInt(messageID, 10) + "/attachment/" + url.PathEscape(attachmentName)
	var out AttachmentSignals
	err := c.doJSON(ctx, http.MethodGet, path, nil, nil, &out)
	return out, err
}

func (c *client) DownloadMessageAttachment(ctx context.Context, messageID int64, attachmentName string) (BinaryResponse, error) {
	path := "/messages/" + strconv.FormatInt(messageID, 10) + "/attachment/" + url.PathEscape(attachmentName) + "/download"
	return c.doDownload(ctx, http.MethodGet, path, nil, c.maxEvidenceBytes)
}

func (c *client) DownloadSearchAttachment(ctx context.Context, params SearchAttachmentDownloadParams) (BinaryResponse, error) {
	q := url.Values{}
	q.Set("message_id", strconv.Itoa(params.MessageID))
	q.Set("attachment_name", params.AttachmentName)
	q.Set("tenant_id", strconv.Itoa(params.TenantID))
	q.Set("raw_message_id", params.RawMessageID)
	q.Set("native_user_id", params.NativeUserID)
	q.Set("recipient_mailbox", params.RecipientMailbox)
	return c.doDownload(ctx, http.MethodGet, "/search/messages/attachments/download", q, c.maxEvidenceBytes)
}

// MarshalAttachmentSignals returns bounded JSON-friendly signals for tool output.
func MarshalAttachmentSignals(signals AttachmentSignals, maxFields int) map[string]any {
	if signals == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(signals))
	count := 0
	for k, v := range signals {
		if count >= maxFields {
			break
		}
		out[k] = v
		count++
	}
	return out
}

// PreviewText returns a bounded UTF-8 preview of text-like evidence.
func PreviewText(data []byte, max int) string {
	if max <= 0 || len(data) == 0 {
		return ""
	}
	if len(data) > max {
		data = data[:max]
	}
	return string(data)
}

// EncodeEvidenceBase64 returns base64 when within embed limit.
func EncodeEvidenceBase64(data []byte, maxEmbed int64) (string, bool) {
	if maxEmbed <= 0 || int64(len(data)) > maxEmbed {
		return "", false
	}
	return base64Encode(data), true
}

func base64Encode(data []byte) string {
	// local helper to keep evidence.go free of large imports in multiple files
	return encodeStdBase64(data)
}
