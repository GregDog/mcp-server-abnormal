package abnormal

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// ListClickedEventsParams are query parameters for GET /url-rewrite/clicked-events.
type ListClickedEventsParams struct {
	Limit     int
	Start     int64
	End       int64
	Recipient string
	EventType string
	Offset    string
}

// ClickedEventsResponse is the paginated response for URL rewrite click events.
type ClickedEventsResponse struct {
	Metadata ClickedEventsResponseMetadata `json:"metadata"`
	Data     []SoarClickedEvent            `json:"data"`
}

// ClickedEventsResponseMetadata contains pagination metadata for clicked events.
type ClickedEventsResponseMetadata struct {
	Pagination ClickedEventsPaginationMetadata `json:"pagination"`
	RequestID  *string                         `json:"requestId"`
}

// ClickedEventsPaginationMetadata holds offset-based pagination for clicked events.
type ClickedEventsPaginationMetadata struct {
	NextOffset *string `json:"nextOffset"`
	Limit      *int    `json:"limit"`
}

// SoarClickedEvent is a URL rewrite click or clickthrough event.
type SoarClickedEvent struct {
	Type            string              `json:"type"`
	Link            string              `json:"link"`
	Insights        []string            `json:"insights"`
	MessageMetadata SoarMessageMetadata `json:"messageMetadata"`
	User            SoarUserAddress     `json:"user"`
	ClickedTime     int64               `json:"clickedTime"`
}

// SoarMessageMetadata is email metadata on a clicked event.
type SoarMessageMetadata struct {
	Subject *string           `json:"subject"`
	Sender  SoarUserAddress   `json:"sender"`
	From    SoarUserAddress   `json:"from"`
	To      []SoarUserAddress `json:"to"`
	Cc      []SoarUserAddress `json:"cc"`
}

// SoarUserAddress is a name and email address pair.
type SoarUserAddress struct {
	Name         *string `json:"name"`
	EmailAddress string  `json:"emailAddress"`
}

func (c *client) ListClickedEvents(ctx context.Context, params ListClickedEventsParams) (ClickedEventsResponse, error) {
	q := url.Values{}
	if params.Limit > 0 {
		q.Set("limit", strconv.Itoa(params.Limit))
	}
	if params.Start > 0 {
		q.Set("start", strconv.FormatInt(params.Start, 10))
	}
	if params.End > 0 {
		q.Set("end", strconv.FormatInt(params.End, 10))
	}
	if params.Recipient != "" {
		q.Set("recipient", params.Recipient)
	}
	if params.EventType != "" {
		q.Set("event_type", params.EventType)
	}
	if params.Offset != "" {
		q.Set("offset", params.Offset)
	}
	var out ClickedEventsResponse
	err := c.doJSON(ctx, http.MethodGet, "/url-rewrite/clicked-events", q, nil, &out)
	return out, err
}
