package abnormal

import (
	"errors"
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

func TestRedactAuthorizationHeader(t *testing.T) {
	in := "request failed: authorization=super-secret"
	out := Redact(in)
	if strings.Contains(out, "super-secret") {
		t.Fatalf("token leaked: %q", out)
	}
}

func TestRedactErrorPreservesUnwrap(t *testing.T) {
	inner := errors.New("Authorization: Bearer leaked-token")
	wrapped := RedactError(inner)
	if wrapped == inner {
		t.Fatal("expected wrapped error")
	}
	if strings.Contains(wrapped.Error(), "leaked-token") {
		t.Fatalf("token leaked: %q", wrapped.Error())
	}
}
