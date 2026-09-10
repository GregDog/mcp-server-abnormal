package tools

import (
	"fmt"
	"strings"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type searchFiltersInput struct {
	Since             string
	Until             string
	Sender            string
	SenderDomain      string
	Recipient         string
	Subject           string
	URL               string
	Attachment        string
	SenderIP          string
	Judgement         string
	JudgementSource   string
	InternetMessageID string
}

func buildSearchFilters(in searchFiltersInput) (abnormal.SearchFilters, error) {
	if in.Sender != "" && in.SenderDomain != "" {
		return abnormal.SearchFilters{}, errSenderConflict
	}
	since, until, err := defaultSinceUntil(in.Since, in.Until)
	if err != nil {
		return abnormal.SearchFilters{}, err
	}

	filters := abnormal.SearchFilters{
		StartTime:         since,
		EndTime:           until,
		Subject:           strPtr(in.Subject),
		RecipientEmail:    strPtr(in.Recipient),
		AttachmentName:    strPtr(in.Attachment),
		BodyLink:          strPtr(in.URL),
		SenderIP:          strPtr(in.SenderIP),
		Judgement:         strPtr(in.Judgement),
		JudgementSource:   strPtr(in.JudgementSource),
		InternetMessageID: strPtr(in.InternetMessageID),
	}
	if in.Sender != "" {
		filters.SenderEmail = strPtr(in.Sender)
	}
	if in.SenderDomain != "" {
		domain := strings.TrimPrefix(strings.TrimSpace(in.SenderDomain), "@")
		domain = strings.ReplaceAll(domain, ".", "\\.")
		filters.SenderEmail = strPtr(fmt.Sprintf(".*@%s$", domain))
		filters.UseSenderRegex = boolPtr(true)
	}
	return filters, nil
}
