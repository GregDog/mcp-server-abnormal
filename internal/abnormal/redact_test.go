package abnormal

import (
	"strings"
	"testing"
)

func TestRedactBearer(t *testing.T) {
	in := "Authorization: Bearer secret-token-value"
	out := Redact(in)
	if strings.Contains(out, "secret-token-value") {
		t.Fatalf("token leaked: %q", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Fatalf("expected redaction markers: %q", out)
	}
}
