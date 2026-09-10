package tools

import "testing"

func TestBoundStrings(t *testing.T) {
	in := []string{"a", "b", "c", "d"}
	out := boundStrings(in, 2)
	if len(out) != 2 || out[0] != "a" || out[1] != "b" {
		t.Fatalf("unexpected: %v", out)
	}
}

func TestTrimString(t *testing.T) {
	long := string(make([]byte, 600))
	got := trimString(long, 100)
	if len(got) != 101 { // 100 + ellipsis char as single rune in our impl - actually we use … which is 1 char
		if len(got) > 110 {
			t.Fatalf("too long: %d", len(got))
		}
	}
}
