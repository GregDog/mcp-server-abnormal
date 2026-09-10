package tools

import (
	"context"
	"testing"
)

func TestListMailboxCampaigns(t *testing.T) {
	h := testHandlers()
	_, page, err := h.listMailboxCampaigns(context.Background(), nil, mailboxCampaignsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].CampaignID != "camp-1" {
		t.Fatalf("unexpected page: %+v", page)
	}
}

func TestGetMailboxCampaignRequiresID(t *testing.T) {
	h := testHandlers()
	_, _, err := h.getMailboxCampaign(context.Background(), nil, getInput{})
	if err != errIDRequired {
		t.Fatalf("got %v", err)
	}
}

func TestGetMailboxCampaign(t *testing.T) {
	h := testHandlers()
	_, detail, err := h.getMailboxCampaign(context.Background(), nil, getInput{ID: "camp-1"})
	if err != nil {
		t.Fatal(err)
	}
	if detail.CampaignID != "camp-1" || detail.Subject != "spam" {
		t.Fatalf("unexpected detail: %+v", detail)
	}
}

func TestListMailboxUnanalyzed(t *testing.T) {
	h := testHandlers()
	_, out, err := h.listMailboxUnanalyzed(context.Background(), nil, mailboxUnanalyzedInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 1 || out.Items[0].AbxMessageID != 99 {
		t.Fatalf("unexpected result: %+v", out)
	}
}
