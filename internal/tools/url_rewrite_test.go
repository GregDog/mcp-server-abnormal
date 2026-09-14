package tools

import (
	"context"
	"testing"
)

func TestListURLRewriteClicks(t *testing.T) {
	h := testHandlers()
	_, page, err := h.listURLRewriteClicks(context.Background(), nil, urlRewriteClicksInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].UserEmail != "user@example.com" {
		t.Fatalf("unexpected: %+v", page)
	}
}

func TestNormalizeClickedEventType(t *testing.T) {
	if normalizeClickedEventType("click") != "Click" {
		t.Fatal("expected Click")
	}
	if normalizeClickedEventType("clickthrough") != "Clickthrough" {
		t.Fatal("expected Clickthrough")
	}
}
