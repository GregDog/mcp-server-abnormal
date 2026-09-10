package tools

import (
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/GregDog/mcp-server-abnormal/internal/abnormal"
)

type listInput struct {
	Limit  int    `json:"limit,omitempty" jsonschema:"Number of items to return. Default 20, maximum 50."`
	Cursor string `json:"cursor,omitempty" jsonschema:"Opaque cursor from a previous list response (page number)."`
}

type getInput struct {
	ID string `json:"id" jsonschema:"Abnormal object ID (UUID)."`
}

func readOnly() *mcp.ToolAnnotations {
	destructive := false
	openWorld := true
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &destructive,
		OpenWorldHint:   &openWorld,
		IdempotentHint:  true,
	}
}

func pageArgs(limit int, cursor string) (pageSize int, pageNumber int) {
	return abnormal.ClampLimit(limit), abnormal.PageNumberFromCursor(cursor)
}

func defaultSinceUntil(since, until string) (string, string, error) {
	now := time.Now().UTC()
	if until == "" {
		until = now.Format(time.RFC3339)
	}
	if since == "" {
		since = now.Add(-24 * time.Hour).Format(time.RFC3339)
	}
	sinceT, err := time.Parse(time.RFC3339, since)
	if err != nil {
		return "", "", err
	}
	untilT, err := time.Parse(time.RFC3339, until)
	if err != nil {
		return "", "", err
	}
	if !sinceT.Before(untilT) {
		return "", "", errSinceAfterUntil
	}
	return since, until, nil
}

func mapPage[T any](items []T, total int, pageNumber int, nextPageNumber int) abnormal.Page[T] {
	var next *string
	hasMore := false
	if nextPageNumber > 0 && nextPageNumber > pageNumber {
		next = abnormal.NextCursorFromPageNumber(nextPageNumber)
		hasMore = true
	}
	return abnormal.Page[T]{
		Items:      items,
		NextCursor: next,
		HasMore:    hasMore,
		TotalCount: int64(total),
	}
}

func searchPage[T any](items []T, total int, pageNumber int, nextPageNumber *int) abnormal.Page[T] {
	var next *string
	hasMore := false
	if nextPageNumber != nil && *nextPageNumber > pageNumber {
		next = abnormal.NextCursorFromPageNumber(*nextPageNumber)
		hasMore = true
	}
	return abnormal.Page[T]{
		Items:      items,
		NextCursor: next,
		HasMore:    hasMore,
		TotalCount: int64(total),
	}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func boolPtr(b bool) *bool { return &b }
