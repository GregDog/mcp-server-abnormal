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
