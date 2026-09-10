package tools

import "log/slog"

func logResponseAction(tool, resourceType, resourceID, action string) {
	slog.Info("abnormal response action executed",
		"tool", tool,
		"resource_type", resourceType,
		"resource_id", resourceID,
		"action", action,
	)
}

func logEvidenceAccess(tool, resourceID string, sizeBytes int) {
	slog.Info("abnormal evidence accessed",
		"tool", tool,
		"resource_id", resourceID,
		"size_bytes", sizeBytes,
	)
}
