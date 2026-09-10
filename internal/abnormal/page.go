package abnormal

import (
	"strconv"
	"strings"
)

const (
	DefaultPageSize = 20
	MaxPageSize     = 50
)

// Page is the compact pagination envelope returned by list tools.
type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
	HasMore    bool    `json:"has_more"`
	TotalCount int64   `json:"total_count"`
}

// ClampLimit bounds a requested page size.
func ClampLimit(n int) int {
	if n <= 0 {
		return DefaultPageSize
	}
	if n > MaxPageSize {
		return MaxPageSize
	}
	return n
}

// PageNumberFromCursor parses a 1-indexed page number from an opaque cursor.
func PageNumberFromCursor(cursor string) int {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return 1
	}
	n, err := strconv.Atoi(cursor)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// NextCursorFromPageNumber returns the next cursor when more pages exist.
func NextCursorFromPageNumber(nextPage int) *string {
	if nextPage <= 0 {
		return nil
	}
	s := strconv.Itoa(nextPage)
	return &s
}
