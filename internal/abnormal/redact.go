package abnormal

import (
	"regexp"
)

var authHeaderPattern = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(\S+)`)
var bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+\S+`)

// Redact removes bearer tokens and Authorization headers from a string.
func Redact(s string) string {
	if s == "" {
		return s
	}
	out := bearerPattern.ReplaceAllString(s, "Bearer [redacted]")
	out = authHeaderPattern.ReplaceAllString(out, `${1}[redacted]`)
	return out
}

// RedactLogMessage redacts sensitive values from log text.
func RedactLogMessage(s string) string {
	return Redact(s)
}

// RedactError returns err with token values removed from the message.
func RedactError(err error) error {
	if err == nil {
		return nil
	}
	msg := Redact(err.Error())
	if msg == err.Error() {
		return err
	}
	return redactedError{msg: msg, unwrap: err}
}

type redactedError struct {
	msg    string
	unwrap error
}

func (e redactedError) Error() string { return e.msg }
func (e redactedError) Unwrap() error { return e.unwrap }
