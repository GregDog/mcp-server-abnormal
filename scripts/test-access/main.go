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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour).Format(time.RFC3339)
	until := now.Format(time.RFC3339)
	filter := abnormal.FormatTimeFilter("receivedTime", since, until)

	resp, err := client.ListThreats(ctx, abnormal.ListThreatsParams{
		Filter:     filter,
		PageSize:   1,
		PageNumber: 1,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListThreats failed: %v\n", abnormal.Redact(err.Error()))
		os.Exit(1)
	}

	fmt.Printf("ok: returned=%d\n", len(resp.Threats))
	if len(resp.Threats) > 0 {
		fmt.Printf("sample threat_id=%s\n", resp.Threats[0].ThreatID)
	}
}
