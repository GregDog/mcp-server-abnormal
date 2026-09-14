package tools

import (
	"context"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type urlRewriteClicksInput struct {
	listInput
	Since     string `json:"since,omitempty" jsonschema:"Start time (RFC3339). Default last 24 hours."`
	Until     string `json:"until,omitempty" jsonschema:"End time (RFC3339). Default now."`
	Recipient string `json:"recipient,omitempty" jsonschema:"Filter by recipient email address."`
	EventType string `json:"event_type,omitempty" jsonschema:"Filter by event type: click or clickthrough."`
}

type urlRewriteClickItem struct {
	EventType      string   `json:"event_type"`
	Link           string   `json:"link"`
	ClickedTime    string   `json:"clicked_time"`
	UserEmail      string   `json:"user_email"`
	UserName       string   `json:"user_name,omitempty"`
	Insights       []string `json:"insights,omitempty"`
	MessageSubject string   `json:"message_subject,omitempty"`
	MessageSender  string   `json:"message_sender_email,omitempty"`
	MessageTo      []string `json:"message_to,omitempty"`
	MessageCc      []string `json:"message_cc,omitempty"`
}

func registerURLRewrite(server *mcp.Server, h *handlers) {
	addTool(server, &mcp.Tool{
		Name:        "abnormal_url_rewrite_clicks_list",
		Title:       "List Abnormal URL rewrite click events",
		Description: "List users who clicked or clickthrough on Abnormal-rewritten URLs in email. Results are paginated.",
		Annotations: readOnly(),
	}, h.listURLRewriteClicks)
}

func (h *handlers) listURLRewriteClicks(ctx context.Context, _ *mcp.CallToolRequest, in urlRewriteClicksInput) (*mcp.CallToolResult, abnormal.Page[urlRewriteClickItem], error) {
	since, until, err := defaultSinceUntil(in.Since, in.Until)
	if err != nil {
		return nil, abnormal.Page[urlRewriteClickItem]{}, err
	}
	start, err := rfc3339ToUnix(since)
	if err != nil {
		return nil, abnormal.Page[urlRewriteClickItem]{}, err
	}
	end, err := rfc3339ToUnix(until)
	if err != nil {
		return nil, abnormal.Page[urlRewriteClickItem]{}, err
	}

	limit := abnormal.ClampLimit(in.Limit)
	resp, err := h.api.ListClickedEvents(ctx, abnormal.ListClickedEventsParams{
		Limit:     limit,
		Start:     start,
		End:       end,
		Recipient: strings.TrimSpace(in.Recipient),
		EventType: normalizeClickedEventType(in.EventType),
		Offset:    strings.TrimSpace(in.Cursor),
	})
	if err != nil {
		return nil, abnormal.Page[urlRewriteClickItem]{}, abnormal.APIError(err)
	}

	items := make([]urlRewriteClickItem, 0, len(resp.Data))
	for _, e := range resp.Data {
		items = append(items, mapURLRewriteClickItem(e))
	}
	return nil, offsetPage(items, resp.Metadata.Pagination.NextOffset), nil
}

func mapURLRewriteClickItem(e abnormal.SoarClickedEvent) urlRewriteClickItem {
	item := urlRewriteClickItem{
		EventType:   e.Type,
		Link:        e.Link,
		ClickedTime: unixToRFC3339(e.ClickedTime),
		UserEmail:   e.User.EmailAddress,
		Insights:    e.Insights,
	}
	if e.User.Name != nil {
		item.UserName = *e.User.Name
	}
	if e.MessageMetadata.Subject != nil {
		item.MessageSubject = *e.MessageMetadata.Subject
	}
	sender := e.MessageMetadata.Sender.EmailAddress
	if sender == "" {
		sender = e.MessageMetadata.From.EmailAddress
	}
	item.MessageSender = sender
	for _, addr := range e.MessageMetadata.To {
		if addr.EmailAddress != "" {
			item.MessageTo = append(item.MessageTo, addr.EmailAddress)
		}
	}
	for _, addr := range e.MessageMetadata.Cc {
		if addr.EmailAddress != "" {
			item.MessageCc = append(item.MessageCc, addr.EmailAddress)
		}
	}
	return item
}

func normalizeClickedEventType(eventType string) string {
	eventType = strings.TrimSpace(eventType)
	if eventType == "" {
		return ""
	}
	switch strings.ToLower(eventType) {
	case "click":
		return "Click"
	case "clickthrough":
		return "Clickthrough"
	default:
		return eventType
	}
}

func offsetPage[T any](items []T, nextOffset *string) abnormal.Page[T] {
	var next *string
	hasMore := false
	if nextOffset != nil && strings.TrimSpace(*nextOffset) != "" {
		next = nextOffset
		hasMore = true
	}
	return abnormal.Page[T]{
		Items:      items,
		NextCursor: next,
		HasMore:    hasMore,
		TotalCount: int64(len(items)),
	}
}

func rfc3339ToUnix(value string) (int64, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

func unixToRFC3339(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}
