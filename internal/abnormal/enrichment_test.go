package abnormal

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestGetThreatLinks(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/threats/t1/links" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(ThreatLinksResponse{
			Links: []ThreatLink{{LinkURL: "http://evil.example"}},
		})
	})
	out, err := c.GetThreatLinks(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Links) != 1 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestGetEmployeeLoginsCSV(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("Timestamp,User Principal Name,User Display Name,Status,IP Address,City,State,Country or Region,Latitude,Longitude,App Display Name,App ID,Client App Used,Browser,Operating System,Device ID,Resource Display Name\n2024-01-01T00:00:00Z,user@example.com,User,Success,1.2.3.4,,,,,,,,,,,\n"))
	})
	rows, err := c.GetEmployeeLogins(context.Background(), "user@example.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].UserPrincipalName != "user@example.com" {
		t.Fatalf("unexpected: %+v", rows)
	}
}

func TestListCasesSendsFilter(t *testing.T) {
	var gotFilter string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotFilter = r.URL.Query().Get("filter")
		_ = json.NewEncoder(w).Encode(PaginatedCases{
			Cases: []AbnormalCaseRef{{CaseID: "1"}},
		})
	})
	_, err := c.ListCases(context.Background(), ListCasesParams{
		Filter: FormatTimeFilter("lastModifiedTime", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotFilter != "lastModifiedTime gte 2024-01-01T00:00:00Z lte 2024-01-02T00:00:00Z" {
		t.Fatalf("filter: %q", gotFilter)
	}
}

func TestListVendors(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vendors" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(PaginatedVendors{
			Vendors: []VendorRef{{VendorDomain: "vendor.com"}},
		})
	})
	out, err := c.ListVendors(context.Background(), ListVendorsParams{PageSize: 20, PageNumber: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Vendors) != 1 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestGetVendorDetails(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/vendors/vendor.com/details" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(VendorDetail{VendorDomain: "vendor.com", RiskLevel: "High"})
	})
	out, err := c.GetVendorDetails(context.Background(), "vendor.com")
	if err != nil {
		t.Fatal(err)
	}
	if out.RiskLevel != "High" {
		t.Fatalf("unexpected: %+v", out)
	}
}
