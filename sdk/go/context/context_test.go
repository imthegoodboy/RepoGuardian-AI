package context

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func TestFromParams_Nil(t *testing.T) {
	c := FromParams(nil)
	if c.HasDeadline() {
		t.Fatal("expected no deadline for nil params")
	}
	if !math.IsInf(c.RemainingS(), +1) {
		t.Fatalf("RemainingS() = %v, want +Inf", c.RemainingS())
	}
	if c.Expired() {
		t.Fatal("Expired() must be false when no deadline is set")
	}
}

func TestFromParams_ContextFields(t *testing.T) {
	deadline := time.Now().Add(5 * time.Second).UnixMilli()
	params := map[string]any{
		"context": map[string]any{
			"invoke_id":   "abc",
			"plugin_name": "demo",
			"deadline_ms": float64(deadline), // json.Unmarshal default shape
			"credentials": map[string]any{"key": "v"},
		},
	}
	c := FromParams(params)

	if c.InvokeID != "abc" {
		t.Errorf("InvokeID = %q, want abc", c.InvokeID)
	}
	if c.PluginName != "demo" {
		t.Errorf("PluginName = %q, want demo", c.PluginName)
	}
	if !c.HasDeadline() {
		t.Fatal("HasDeadline() == false")
	}
	if c.Expired() {
		t.Fatal("Expired() reported true while deadline is still in the future")
	}
	rem := c.RemainingS()
	if rem <= 0 || rem > 5.1 {
		t.Errorf("RemainingS() = %v, want (0, 5.1]", rem)
	}
	if c.Credentials["key"] != "v" {
		t.Errorf("Credentials not parsed: %v", c.Credentials)
	}
}

func TestFromParams_DeadlineInThePast_IsExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Second).UnixMilli()
	c := FromParams(map[string]any{
		"context": map[string]any{"deadline_ms": float64(past)},
	})
	if !c.Expired() {
		t.Fatal("Expired() should be true for past deadlines")
	}
	if c.RemainingS() != 0 {
		t.Errorf("RemainingS() = %v, want 0", c.RemainingS())
	}
}

func TestFromParams_JSONNumberDeadline(t *testing.T) {
	// Simulate a stream that decoded with UseNumber().
	deadline := time.Now().Add(2 * time.Second).UnixMilli()
	params := map[string]any{
		"context": map[string]any{
			"deadline_ms": json.Number(toString(deadline)),
		},
	}
	c := FromParams(params)
	if !c.HasDeadline() || c.DeadlineMS != deadline {
		t.Fatalf("DeadlineMS = %d, want %d", c.DeadlineMS, deadline)
	}
}

func TestFromParams_InvalidDeadline_FallsBack(t *testing.T) {
	c := FromParams(map[string]any{"context": map[string]any{"deadline_ms": "not-a-number"}})
	if c.HasDeadline() {
		t.Fatal("HasDeadline() must be false for non-numeric deadline_ms")
	}
}

func TestRemaining_DurationCappedForNoDeadline(t *testing.T) {
	c := FromParams(nil)
	got := c.Remaining()
	if got != time.Duration(math.MaxInt64) {
		t.Errorf("Remaining() = %v, want MaxInt64 sentinel", got)
	}
}

func TestFromParams_InvokeIDFallsBackToParamsLevel(t *testing.T) {
	c := FromParams(map[string]any{"invoke_id": "outer", "context": map[string]any{}})
	if c.InvokeID != "outer" {
		t.Errorf("InvokeID = %q, want outer", c.InvokeID)
	}
}

func toString(i int64) string {
	// Tiny helper to avoid pulling strconv into the test header noise.
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = digits[i%10]
		i /= 10
	}
	return string(buf[pos:])
}
