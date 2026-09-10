package tools

import "errors"

var (
	errIDRequired         = errors.New("id is required")
	errMessageIDRequired  = errors.New("message_id is required")
	errActivityIDRequired = errors.New("activity_log_id is required")
	errSenderConflict     = errors.New("sender and sender_domain cannot both be set")
	errSinceAfterUntil    = errors.New("since must be before until")
)
