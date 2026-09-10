//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
	"github.com/GregDog/mcp-server-abnormal/internal/config"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	client, err := abnormal.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	now := time.Now().UTC()
	since := now.Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	until := now.Format(time.RFC3339)

	fmt.Println("=== Phase 3/4 live API smoke test ===")
	fmt.Printf("base_url: %s\n\n", cfg.BaseURL)

	var threatID string
	var recipientEmail string

	tryStep("ListThreats", func() error {
		filter := abnormal.FormatTimeFilter("receivedTime", since, until)
		resp, err := client.ListThreats(ctx, abnormal.ListThreatsParams{
			Filter: filter, PageSize: 1, PageNumber: 1,
		})
		if err != nil {
			return err
		}
		fmt.Printf("  threats returned: %d\n", len(resp.Threats))
		if len(resp.Threats) > 0 {
			threatID = resp.Threats[0].ThreatID
			fmt.Printf("  sample threat_id: %s\n", threatID)
		}
		return nil
	})

	if threatID != "" {
		tryStep("GetThreatLinks", func() error {
			resp, err := client.GetThreatLinks(ctx, threatID)
			if err != nil {
				return err
			}
			fmt.Printf("  links: %d\n", len(resp.Links))
			return nil
		})
		tryStep("GetThreatAttachments", func() error {
			resp, err := client.GetThreatAttachments(ctx, threatID)
			if err != nil {
				return err
			}
			fmt.Printf("  attachments: %d\n", len(resp.Attachments))
			return nil
		})
		tryStep("GetThreat", func() error {
			resp, err := client.GetThreat(ctx, threatID, 10, 1)
			if err != nil {
				return err
			}
			fmt.Printf("  messages: %d\n", len(resp.Messages))
			if len(resp.Messages) > 0 {
				recipientEmail = resp.Messages[0].RecipientAddress
			}
			return nil
		})
	} else {
		skip("GetThreatLinks", "no threat_id")
		skip("GetThreatAttachments", "no threat_id")
	}

	tryStep("ListCases", func() error {
		filter := abnormal.FormatTimeFilter("lastModifiedTime", since, until)
		resp, err := client.ListCases(ctx, abnormal.ListCasesParams{
			Filter: filter, PageSize: 5, PageNumber: 1,
		})
		if err != nil {
			return err
		}
		fmt.Printf("  cases: %d\n", len(resp.Cases))
		if len(resp.Cases) > 0 {
			caseID := resp.Cases[0].CaseID
			fmt.Printf("  sample case_id: %s\n", caseID)
			if err := probeCase(ctx, client, caseID); err != nil {
				fmt.Printf("  case detail probe: %v\n", abnormal.Redact(err.Error()))
			}
		}
		return nil
	})

	if recipientEmail != "" {
		tryStep("GetEmployee", func() error {
			resp, err := client.GetEmployee(ctx, recipientEmail)
			if err != nil {
				return err
			}
			fmt.Printf("  employee: %s (%s)\n", resp.Name, resp.Email)
			return nil
		})
		tryStep("GetEmployeeIdentity", func() error {
			resp, err := client.GetEmployeeIdentity(ctx, recipientEmail)
			if err != nil {
				return err
			}
			fmt.Printf("  genome entries: %d\n", len(resp.Data))
			return nil
		})
		tryStep("GetEmployeeLogins", func() error {
			rows, err := client.GetEmployeeLogins(ctx, recipientEmail, 5)
			if err != nil {
				return err
			}
			fmt.Printf("  login rows: %d\n", len(rows))
			return nil
		})
	} else {
		skip("GetEmployee", "no recipient email from threat")
		skip("GetEmployeeIdentity", "no recipient email from threat")
		skip("GetEmployeeLogins", "no recipient email from threat")
	}

	tryStep("ListVendors", func() error {
		resp, err := client.ListVendors(ctx, abnormal.ListVendorsParams{PageSize: 20, PageNumber: 1})
		if err != nil {
			return err
		}
		fmt.Printf("  vendors: %d\n", len(resp.Vendors))
		for _, v := range resp.Vendors {
			fmt.Printf("\n  --- %s ---\n", v.VendorDomain)
			if err := probeVendor(ctx, client, v.VendorDomain); err != nil {
				fmt.Printf("  detail error: %v\n", abnormal.Redact(err.Error()))
			}
		}
		return nil
	})

	tryStep("ListVendorCases", func() error {
		filter := abnormal.FormatTimeFilter("lastModifiedTime", since, until)
		resp, err := client.ListVendorCases(ctx, abnormal.ListVendorCasesParams{
			Filter: filter, PageSize: 5, PageNumber: 1,
		})
		if err != nil {
			return err
		}
		fmt.Printf("  vendor cases: %d\n", len(resp.VendorCases))
		if len(resp.VendorCases) > 0 {
			id := fmt.Sprintf("%d", resp.VendorCases[0].VendorCaseID)
			detail, err := client.GetVendorCase(ctx, id)
			if err != nil {
				fmt.Printf("  vendor case detail: %v\n", abnormal.Redact(err.Error()))
			} else {
				fmt.Printf("  vendor case domain: %s\n", detail.VendorDomain)
			}
		}
		return nil
	})
}

func probeCase(ctx context.Context, client abnormal.API, caseID string) error {
	detail, err := client.GetCase(ctx, caseID)
	if err != nil {
		return err
	}
	fmt.Printf("  case severity: %s\n", detail.Severity)
	analysis, err := client.GetCaseAnalysis(ctx, caseID)
	if err != nil {
		return err
	}
	fmt.Printf("  case insights: %d timeline: %d\n", len(analysis.Insights), len(analysis.EventTimeline))
	return nil
}

func probeVendor(ctx context.Context, client abnormal.API, domain string) error {
	detail, err := client.GetVendorDetails(ctx, domain)
	if err != nil {
		return err
	}
	fmt.Printf("  risk_level: %s\n", detail.RiskLevel)
	if len(detail.Analysis) > 0 {
		fmt.Println("  analysis:")
		for _, a := range detail.Analysis {
			fmt.Printf("    - %s\n", a)
		}
	}
	if len(detail.VendorContacts) > 0 {
		fmt.Printf("  vendor_contacts: %v\n", detail.VendorContacts)
	}
	if len(detail.CompanyContacts) > 0 {
		fmt.Printf("  company_contacts: %v\n", detail.CompanyContacts)
	}
	if len(detail.VendorCountries) > 0 {
		fmt.Printf("  vendor_countries: %v\n", detail.VendorCountries)
	}
	if len(detail.VendorIPAddresses) > 0 {
		fmt.Printf("  vendor_ip_addresses: %v\n", detail.VendorIPAddresses)
	}
	activity, err := client.GetVendorActivity(ctx, domain)
	if err != nil {
		return err
	}
	fmt.Printf("  activity_events: %d\n", len(activity.EventTimeline))
	for i, ev := range activity.EventTimeline {
		if i >= 3 {
			fmt.Printf("    ... and %d more events\n", len(activity.EventTimeline)-3)
			break
		}
		fmt.Printf("    event[%d]: %v\n", i, ev)
	}
	return nil
}

func tryStep(name string, fn func() error) {
	fmt.Printf("[%s] ", name)
	if err := fn(); err != nil {
		fmt.Printf("FAIL: %s\n", abnormal.Redact(err.Error()))
		return
	}
	fmt.Println("OK")
}

func skip(name, reason string) {
	fmt.Printf("[%s] SKIP (%s)\n", name, reason)
}
