package tools

import (
	"context"
	"testing"
)

func TestListThreats(t *testing.T) {
	h := testHandlers()
	_, page, err := h.listThreats(context.Background(), nil, threatListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ThreatID != "threat-1" {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestGetThreatRequiresID(t *testing.T) {
	h := testHandlers()
	_, _, err := h.getThreat(context.Background(), nil, getInput{})
	if err != errIDRequired {
		t.Fatalf("got %v", err)
	}
}

func TestGetThreat(t *testing.T) {
	h := testHandlers()
	_, detail, err := h.getThreat(context.Background(), nil, getInput{ID: "abc"})
	if err != nil {
		t.Fatal(err)
	}
	if detail.ThreatID != "abc" || len(detail.Messages) != 1 {
		t.Fatalf("unexpected detail: %+v", detail)
	}
}
