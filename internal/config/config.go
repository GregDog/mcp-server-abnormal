package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	DefaultBaseURL      = "https://api.abnormalplatform.com/v1"
	DefaultLogLevel     = "info"
	DefaultTransport    = "stdio"
	DefaultHTTPAddr     = "127.0.0.1:8090"
	DefaultHTTPMaxBody  = 32 * 1024 * 1024 // 32 MiB
	DefaultHTTPMaxRetry = 2
)

// Config is loaded from the process environment.
type Config struct {
	APIToken              string
	BaseURL               string
	MockData              bool
	LogLevel              string
	AllowResponse         bool
	AllowEvidenceDownload bool
	Transport             string
	HTTPAddr              string
	HTTPJSON              bool
	HTTPMaxBodyBytes      int64
	HTTPMaxRetries        int
}

// FromEnv loads configuration. ABNORMAL_API_TOKEN is required.
func FromEnv() (Config, error) {
	loadDotEnvFiles()

	cfg := Config{
		APIToken:              strings.TrimSpace(os.Getenv("ABNORMAL_API_TOKEN")),
		BaseURL:               strings.TrimSpace(os.Getenv("ABNORMAL_BASE_URL")),
		MockData:              parseBoolEnv(os.Getenv("ABNORMAL_MOCK_DATA")),
		LogLevel:              strings.TrimSpace(os.Getenv("ABNORMAL_MCP_LOG_LEVEL")),
		AllowResponse:         parseBoolEnv(os.Getenv("ABNORMAL_ALLOW_RESPONSE")),
		AllowEvidenceDownload: parseBoolEnv(os.Getenv("ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD")),
		Transport:             strings.TrimSpace(os.Getenv("ABNORMAL_MCP_TRANSPORT")),
		HTTPAddr:              strings.TrimSpace(os.Getenv("ABNORMAL_MCP_HTTP_ADDR")),
		HTTPJSON:              parseBoolEnv(os.Getenv("ABNORMAL_MCP_HTTP_JSON")),
		HTTPMaxBodyBytes:      parseInt64Env(os.Getenv("ABNORMAL_MCP_HTTP_MAX_BODY_BYTES"), DefaultHTTPMaxBody),
		HTTPMaxRetries:        parseIntEnv(os.Getenv("ABNORMAL_HTTP_MAX_RETRIES"), DefaultHTTPMaxRetry),
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = DefaultLogLevel
	}
	if cfg.Transport == "" {
		cfg.Transport = DefaultTransport
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = DefaultHTTPAddr
	}
	if cfg.APIToken == "" {
		return Config{}, fmt.Errorf("ABNORMAL_API_TOKEN is required")
	}
	switch strings.ToLower(cfg.Transport) {
	case "stdio", "http":
	default:
		return Config{}, fmt.Errorf("ABNORMAL_MCP_TRANSPORT must be stdio or http")
	}
	return cfg, nil
}

func parseIntEnv(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func parseInt64Env(value string, fallback int64) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func parseBoolEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
