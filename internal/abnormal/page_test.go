package abnormal

import "testing"

func TestClampLimit(t *testing.T) {
	if ClampLimit(0) != DefaultPageSize {
		t.Fatal("zero should default")
	}
	if ClampLimit(100) != MaxPageSize {
		t.Fatal("should cap at max")
	}
}

func TestPageNumberFromCursor(t *testing.T) {
	if PageNumberFromCursor("") != 1 {
		t.Fatal("empty cursor")
	}
	if PageNumberFromCursor("3") != 3 {
		t.Fatal("page 3")
	}
	if PageNumberFromCursor("bad") != 1 {
		t.Fatal("invalid cursor")
	}
}
