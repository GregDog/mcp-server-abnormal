package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

const (
	maxEvidencePreviewBytes = 4096
	maxEvidenceEmbedBytes   = 1 * 1024 * 1024 // 1 MiB base64 payload cap in MCP responses
)

type evidencePackageOptions struct {
	IncludePreview       bool
	IncludeContentBase64 bool
}

type evidencePackageResult struct {
	ContentType          string `json:"content_type"`
	SizeBytes            int    `json:"size_bytes"`
	SHA256               string `json:"sha256"`
	Preview              string `json:"preview,omitempty"`
	ContentBase64        string `json:"content_base64,omitempty"`
	ContentBase64Omitted bool   `json:"content_base64_omitted,omitempty"`
	Note                 string `json:"note,omitempty"`
}

func packageEvidence(resp abnormal.BinaryResponse, opts evidencePackageOptions) evidencePackageResult {
	sum := sha256.Sum256(resp.Data)
	out := evidencePackageResult{
		ContentType: resp.ContentType,
		SizeBytes:   len(resp.Data),
		SHA256:      hex.EncodeToString(sum[:]),
	}
	if opts.IncludePreview && isTextLikeContentType(resp.ContentType) {
		out.Preview = abnormal.PreviewText(resp.Data, maxEvidencePreviewBytes)
	}
	if opts.IncludeContentBase64 {
		if encoded, ok := abnormal.EncodeEvidenceBase64(resp.Data, maxEvidenceEmbedBytes); ok {
			out.ContentBase64 = encoded
		} else {
			out.ContentBase64Omitted = true
			out.Note = "content_base64 omitted because payload exceeds embed limit; metadata only"
		}
	} else {
		out.Note = "binary content omitted by default; set include_content_base64=true to embed (max 1 MiB)"
	}
	return out
}

func isTextLikeContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/") ||
		strings.Contains(ct, "message/rfc822") ||
		strings.Contains(ct, "application/json")
}
