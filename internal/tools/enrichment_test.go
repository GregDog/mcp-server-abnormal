package tools

import (
	"context"
	"testing"
)

func TestListThreatLinks(t *testing.T) {
	h := testHandlers()
	_, out, err := h.listThreatLinks(context.Background(), nil, threatLinksInput{ThreatID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Links) != 1 || out.Links[0].LinkURL != "http://evil.example" {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestGetEmployeeRequiresEmail(t *testing.T) {
	h := testHandlers()
	_, _, err := h.getEmployee(context.Background(), nil, employeeInput{})
	if err != errEmailRequired {
		t.Fatalf("got %v", err)
	}
}

func TestListCases(t *testing.T) {
	h := testHandlers()
	_, page, err := h.listCases(context.Background(), nil, casesListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].CaseID != "case-1" {
		t.Fatalf("unexpected: %+v", page)
	}
}

func TestUpdateCasePreview(t *testing.T) {
	h := testResponseHandlers()
	_, out, err := h.updateCase(context.Background(), nil, caseUpdateInput{
		ID: "case-1", Action: "acknowledge_resolved",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Error != errConfirmationRequired || out.Confirmed {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestListVendors(t *testing.T) {
	h := testHandlers()
	_, page, err := h.listVendors(context.Background(), nil, listInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].VendorDomain != "vendor.com" {
		t.Fatalf("unexpected: %+v", page)
	}
}

func TestGetVendorRequiresDomain(t *testing.T) {
	h := testHandlers()
	_, _, err := h.getVendor(context.Background(), nil, vendorDomainInput{})
	if err != errVendorDomainRequired {
		t.Fatalf("got %v", err)
	}
}
