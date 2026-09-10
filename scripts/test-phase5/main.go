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
	if !cfg.AllowEvidenceDownload {
		fmt.Fprintln(os.Stderr, "error: set ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD=true for Phase 5 smoke test")
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
	since := now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)
	until := now.Format(time.RFC3339)

	fmt.Println("=== Phase 5 live API smoke test ===")
	fmt.Printf("base_url: %s\n", cfg.BaseURL)
	fmt.Printf("max_evidence_bytes: %d\n\n", cfg.MaxEvidenceBytes)

	var messageID int64
	var cloudMessageID string

	tryStep("ListThreats", func() error {
		resp, err := client.ListThreats(ctx, abnormal.ListThreatsParams{
			Filter:     abnormal.FormatTimeFilter("receivedTime", since, until),
			PageSize:   1,
			PageNumber: 1,
			Source:     "attacks",
		})
		if err != nil {
			return err
		}
		fmt.Printf("  threats returned: %d\n", len(resp.Threats))
		if len(resp.Threats) == 0 {
			return nil
		}
		detail, err := client.GetThreat(ctx, resp.Threats[0].ThreatID, 10, 1)
		if err != nil {
			return err
		}
		if len(detail.Messages) == 0 {
			return nil
		}
		messageID = detail.Messages[0].AbxMessageID
		fmt.Printf("  sample message_id: %d\n", messageID)
		return nil
	})

	if messageID != 0 {
		tryStep("DownloadMessageEML", func() error {
			resp, err := client.DownloadMessageEML(ctx, messageID)
			if err != nil {
				return err
			}
			fmt.Printf("  content_type: %s size: %d preview: %q\n", resp.ContentType, len(resp.Data), abnormal.PreviewText(resp.Data, 80))
			return nil
		})
		tryStep("GetMessageAttachmentSignals", func() error {
			signals, err := client.GetMessageAttachmentSignals(ctx, messageID, "test.pdf")
			if err != nil {
				return err
			}
			fmt.Printf("  signal fields: %d\n", len(signals))
			return nil
		})
	} else {
		skip("DownloadMessageEML", "no message_id from threats")
		skip("GetMessageAttachmentSignals", "no message_id from threats")
	}

	tryStep("SearchMessages", func() error {
		resp, err := client.SearchMessages(ctx, abnormal.SearchRequest{
			Source: "abnormal",
			Filters: abnormal.SearchFilters{
				StartTime: since,
				EndTime:   until,
				Subject:   strPtr("invoice"),
			},
		}, 1, 1)
		if err != nil {
			return err
		}
		fmt.Printf("  search results: %d\n", len(resp.Results))
		if len(resp.Results) > 0 && resp.Results[0].CloudMessageID != nil {
			cloudMessageID = *resp.Results[0].CloudMessageID
			fmt.Printf("  sample cloud_message_id: %s\n", cloudMessageID)
		}
		return nil
	})

	if cloudMessageID != "" {
		tryStep("DownloadSearchMessageEML", func() error {
			resp, err := client.DownloadSearchMessageEML(ctx, cloudMessageID, "", "")
			if err != nil {
				return err
			}
			fmt.Printf("  content_type: %s size: %d\n", resp.ContentType, len(resp.Data))
			return nil
		})
	} else {
		skip("DownloadSearchMessageEML", "no cloud_message_id from search")
	}

	fmt.Println("\nDone.")
}

func strPtr(s string) *string { return &s }

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
