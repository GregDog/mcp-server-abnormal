package tools

import (
	"context"
	"testing"
)

func TestSearchMessagesSenderConflict(t *testing.T) {
	h := testHandlers()
	_, _, err := h.searchMessages(context.Background(), nil, searchMessagesInput{
		Sender:       "a@b.com",
		SenderDomain: "evil.com",
	})
	if err != errSenderConflict {
		t.Fatalf("got %v", err)
	}
}

func TestSearchMessages(t *testing.T) {
	h := testHandlers()
	_, page, err := h.searchMessages(context.Background(), nil, searchMessagesInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestSearchMessagesSenderDomain(t *testing.T) {
	h := testHandlers()
	_, _, err := h.searchMessages(context.Background(), nil, searchMessagesInput{
		SenderDomain: "evil.com",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestListSearchActivities(t *testing.T) {
	h := testHandlers()
	_, page, err := h.listSearchActivities(context.Background(), nil, searchActivitiesInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ActivityID != 1 || page.Items[0].Action != "search" {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestGetSearchActivityRequiresID(t *testing.T) {
	h := testHandlers()
	_, _, err := h.getSearchActivity(context.Background(), nil, searchActivityGetInput{})
	if err != errActivityIDRequired {
		t.Fatalf("got %v", err)
	}
}

func TestGetSearchActivity(t *testing.T) {
	h := testHandlers()
	_, detail, err := h.getSearchActivity(context.Background(), nil, searchActivityGetInput{ActivityLogID: 42})
	if err != nil {
		t.Fatal(err)
	}
	if detail.ActivityID != 42 || detail.Action != "delete" || detail.Status != "completed" {
		t.Fatalf("unexpected detail: %+v", detail)
	}
}
