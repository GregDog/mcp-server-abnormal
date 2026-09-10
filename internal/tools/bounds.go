package tools

const (
	maxBoundedItems   = 50
	maxBoundedStrings = 25
	maxBoundedString  = 512
	maxTimelineEvents = 25
	maxGenomeEntries  = 100
)

func boundStrings(items []string, max int) []string {
	if max <= 0 || len(items) <= max {
		return items
	}
	out := make([]string, max)
	for i := 0; i < max; i++ {
		out[i] = trimString(items[i], maxBoundedString)
	}
	return out
}

func boundMaps(items []map[string]any, max int) []map[string]any {
	if max <= 0 || len(items) <= max {
		return items
	}
	return items[:max]
}

func trimString(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
