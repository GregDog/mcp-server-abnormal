package abnormal

import "fmt"

// HTTPStatusError is returned when the Abnormal API responds with a non-success status.
type HTTPStatusError struct {
	StatusCode int
	Message    string
}

func (e HTTPStatusError) Error() string {
	msg := Redact(e.Message)
	if msg == "" {
		return fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, msg)
}
