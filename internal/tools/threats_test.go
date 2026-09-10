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

func TestGetThreatActionRequiresIDs(t *testing.T) {
	h := testHandlers()
	_, _, err := h.getThreatAction(context.Background(), nil, threatActionGetInput{})
	if err != errIDRequired {
		t.Fatalf("got %v", err)
	}
	_, _, err = h.getThreatAction(context.Background(), nil, threatActionGetInput{ThreatID: "t1"})
	if err != errActionIDRequired {
		t.Fatalf("got %v", err)
	}
}

func TestGetThreatAction(t *testing.T) {
	h := testHandlers()
	_, out, err := h.getThreatAction(context.Background(), nil, threatActionGetInput{
		ThreatID: "t1", ActionID: "a1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "completed" || out.ThreatID != "t1" {
		t.Fatalf("unexpected: %+v", out)
	}
}
