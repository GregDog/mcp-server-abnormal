package config

import "testing"

func TestFromEnvRequiresToken(t *testing.T) {
	t.Setenv("ABNORMAL_API_TOKEN", "")
	t.Setenv("ABNORMAL_BASE_URL", "")
	t.Setenv("ABNORMAL_MCP_LOG_LEVEL", "")
	t.Setenv("ABNORMAL_ALLOW_RESPONSE", "")
	t.Setenv("ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD", "")

	if _, err := FromEnv(); err == nil {
		t.Fatal("expected error when token is missing")
	}
}

func TestFromEnvDefaults(t *testing.T) {
	t.Setenv("ABNORMAL_API_TOKEN", "example-token")
	t.Setenv("ABNORMAL_BASE_URL", "")
	t.Setenv("ABNORMAL_MCP_LOG_LEVEL", "")
	t.Setenv("ABNORMAL_ALLOW_RESPONSE", "")
	t.Setenv("ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD", "")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != DefaultBaseURL {
		t.Fatalf("base url: got %q", cfg.BaseURL)
	}
	if cfg.LogLevel != DefaultLogLevel {
		t.Fatalf("log level: got %q", cfg.LogLevel)
	}
	if cfg.AllowResponse || cfg.AllowEvidenceDownload {
		t.Fatal("expected response/evidence disabled by default")
	}
}

func TestFromEnvAllowFlags(t *testing.T) {
	t.Setenv("ABNORMAL_API_TOKEN", "example-token")
	t.Setenv("ABNORMAL_ALLOW_RESPONSE", "true")
	t.Setenv("ABNORMAL_ALLOW_EVIDENCE_DOWNLOAD", "true")

	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowResponse || !cfg.AllowEvidenceDownload {
		t.Fatal("expected allow flags true")
	}
}
