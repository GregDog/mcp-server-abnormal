package abnormal

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestListClickedEvents(t *testing.T) {
	var gotQuery string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(ClickedEventsResponse{
			Data: []SoarClickedEvent{{
				Type:        "Click",
				Link:        "https://example.com",
				ClickedTime: 1704067200,
				User:        SoarUserAddress{EmailAddress: "user@example.com"},
			}},
			Metadata: ClickedEventsResponseMetadata{
				Pagination: ClickedEventsPaginationMetadata{
					NextOffset: strPtr("next-token"),
				},
			},
		})
	})
	out, err := c.ListClickedEvents(context.Background(), ListClickedEventsParams{
		Limit:     20,
		Start:     1704067200,
		End:       1704153600,
		Recipient: "user@example.com",
		EventType: "Click",
		Offset:    "page-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"limit=20", "start=1704067200", "end=1704153600", "recipient=user%40example.com", "event_type=Click", "offset=page-1"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if len(out.Data) != 1 || out.Data[0].Link != "https://example.com" {
		t.Fatalf("unexpected: %+v", out)
	}
}
