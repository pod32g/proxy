package reqid

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewIsSixteenRandomBytesHex(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id := New()
		if len(id) != 32 {
			t.Fatalf("id = %q (%d chars), want 32 hex chars", id, len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Fatalf("id %q is not hex: %v", id, err)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

// The shape is deliberate: a W3C trace-id is exactly 16 bytes, so when tracing
// is enabled the request ID and the trace ID can be one value rather than two
// identifiers somebody has to join.
func TestNewIsTraceIDShaped(t *testing.T) {
	raw, err := hex.DecodeString(New())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 16 {
		t.Errorf("decoded to %d bytes, want the 16 of a W3C trace-id", len(raw))
	}
}

// "Honoured rather than replaced" is the criterion, and this is it.
func TestInboundIDIsHonoured(t *testing.T) {
	for _, in := range []string{
		"abc123",
		"0af7651916cd43dd8448eb211c80319c",     // a W3C trace-id
		"550e8400-e29b-41d4-a716-446655440000", // a UUID
		"01ARZ3NDEKTSV4RRFFQ69G5FAV",           // a ULID
		"req/2026-08-01#4711",                  // somebody's own scheme
		strings.Repeat("a", MaxLength),         // right at the bound
	} {
		if got := FromRequestOrNew(in); got != in {
			t.Errorf("FromRequestOrNew(%q) = %q, want the caller's id back", in, got)
		}
	}
}

// Honouring garbage is not the same as honouring the caller. The value is
// attacker-controlled and about to be written into every log line for the
// request, so anything that could forge a record or bloat an entry is replaced.
func TestUnusableInboundIDIsReplaced(t *testing.T) {
	for name, in := range map[string]string{
		"empty":             "",
		"whitespace only":   "   ",
		"newline injection": "abc\nfake-log-line",
		"carriage return":   "abc\rdef",
		"tab":               "abc\tdef",
		"space":             "abc def",
		"quote":             `abc"def`,
		"backslash":         `abc\def`,
		"null byte":         "abc\x00def",
		"too long":          strings.Repeat("a", MaxLength+1),
		"non-ascii":         "abcédef",
	} {
		t.Run(name, func(t *testing.T) {
			if got := Sanitize(in); got != "" {
				t.Errorf("Sanitize(%q) = %q, want it rejected", in, got)
			}
			got := FromRequestOrNew(in)
			if got == in {
				t.Errorf("FromRequestOrNew(%q) honoured an unusable id", in)
			}
			if len(got) != 32 {
				t.Errorf("replacement = %q, want a generated id", got)
			}
		})
	}
}

func TestSanitizeTrimsSurroundingSpace(t *testing.T) {
	if got := Sanitize("  abc123  "); got != "abc123" {
		t.Errorf("got %q, want %q", got, "abc123")
	}
}

func TestContextRoundTrip(t *testing.T) {
	ctx := WithID(context.Background(), "abc123")
	if got := FromContext(ctx); got != "abc123" {
		t.Errorf("got %q, want abc123", got)
	}
	// A context with no id must answer "" rather than panicking, since every
	// caller treats "" as "not identified".
	if got := FromContext(context.Background()); got != "" {
		t.Errorf("got %q from a bare context, want empty", got)
	}
	// An empty id must not create a value that later reads as set.
	if got := FromContext(WithID(context.Background(), "")); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
