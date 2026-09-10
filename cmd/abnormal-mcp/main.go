package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
	"github.com/GregDog/mcp-server-abnormal/internal/config"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		flags, err := parseServeArgs(os.Args[2:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			usage()
			os.Exit(2)
		}
		if err := runServe(flags); err != nil {
			fmt.Fprintln(os.Stderr, abnormal.Redact(err.Error()))
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Printf("abnormal-mcp %s (commit %s, built %s)\n", version, commit, date)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func setupLogger(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(abnormal.NewRedactingHandler(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))))
}

type serveFlags struct {
	allowResponse         bool
	allowEvidenceDownload bool
	transport             string
	httpAddr              string
	httpJSON              bool
}

func parseServeArgs(args []string) (serveFlags, error) {
	flags := serveFlags{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--allow-response":
			flags.allowResponse = true
		case "--allow-evidence-download":
			flags.allowEvidenceDownload = true
		case "--http-json":
			flags.httpJSON = true
		case "--transport", "--http-addr":
			if i+1 >= len(args) {
				return serveFlags{}, fmt.Errorf("flag %s requires a value", arg)
			}
			i++
			if arg == "--transport" {
				flags.transport = args[i]
			} else {
				flags.httpAddr = args[i]
			}
		default:
			return serveFlags{}, fmt.Errorf("unknown serve flag %q", arg)
		}
	}
	return flags, nil
}

func runServe(flags serveFlags) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if flags.allowResponse {
		cfg.AllowResponse = true
	}
	if flags.allowEvidenceDownload {
		cfg.AllowEvidenceDownload = true
	}
	if flags.transport != "" {
		cfg.Transport = flags.transport
	}
	if flags.httpAddr != "" {
		cfg.HTTPAddr = flags.httpAddr
	}
	if flags.httpJSON {
		cfg.HTTPJSON = true
	}

	setupLogger(cfg.LogLevel)

	client, err := abnormal.New(cfg)
	if err != nil {
		return err
	}

	server := newMCPServer(cfg, client)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	transport := strings.ToLower(cfg.Transport)
	slog.Info("starting abnormal mcp server",
		"transport", transport,
		"version", version,
		"allow_response", cfg.AllowResponse,
		"allow_evidence_download", cfg.AllowEvidenceDownload,
	)
	switch transport {
	case "stdio":
		return server.Run(ctx, &mcp.StdioTransport{})
	case "http":
		slog.Info("http transport configured",
			"addr", cfg.HTTPAddr,
			"json_response", cfg.HTTPJSON,
			"max_body_bytes", cfg.HTTPMaxBodyBytes,
		)
		return runHTTP(ctx, cfg, server)
	default:
		return fmt.Errorf("unsupported transport %q", cfg.Transport)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `abnormal-mcp is a Model Context Protocol server for Abnormal Security.

Usage:
  abnormal-mcp serve [--allow-response] [--allow-evidence-download] [--transport stdio|http] [--http-addr ADDR] [--http-json]
  abnormal-mcp version

Environment:
  ABNORMAL_API_TOKEN                  Required Abnormal REST API bearer token
  ABNORMAL_BASE_URL                   API base URL (default https://api.abnormalplatform.com/v1)
  ABNORMAL_MOCK_DATA                  Send Mock-Data: True header when true
  ABNORMAL_MCP_LOG_LEVEL              debug, info, warn, or error (default info)
  ABNORMAL_ALLOW_RESPONSE             Enable response MCP tools when true (default false)
  ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD    Enable evidence download tools when true (default false)
  ABNORMAL_MCP_TRANSPORT              stdio or http (default stdio)
  ABNORMAL_MCP_HTTP_ADDR              HTTP listen address when transport=http (default 127.0.0.1:8090, loopback only)
  ABNORMAL_MCP_HTTP_JSON              Use application/json responses for HTTP transport
  ABNORMAL_MCP_HTTP_MAX_BODY_BYTES    Max HTTP request body size (default 33554432)
  ABNORMAL_HTTP_MAX_RETRIES           Retries on 429/502/503/504 (default 2; 0 disables)
  ABNORMAL_MAX_EVIDENCE_BYTES         Max bytes per evidence download (default 10485760)
`)
}
