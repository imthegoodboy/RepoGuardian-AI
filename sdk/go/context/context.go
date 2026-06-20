// Package context exposes a typed view of the per-invoke
// `params.context` payload that the Anna/Matrix Agent injects into every
// `invoke` request. Mirrors the Python (`executa_sdk.context.InvokeContext`)
// and Node (`@anna-executa/sdk/context`) helpers — keep the three in sync.
//
// The host derives `context.deadline_ms` from the iframe-supplied
// `tools.invoke(..., { timeoutMs })` and propagates it down so plugin code
// can size its own reverse-RPC subcalls (storage/image/upload/sampling)
// against the remaining budget.
//
// Older hosts may omit `context.deadline_ms`; in that case `RemainingS`
// returns `math.Inf(+1)` and `HasDeadline` is false — plugins should
// treat that as "no host-imposed deadline".
//
// Example:
//
//	ctx := invokectx.FromParams(req.Params)
//	if ctx.Expired() {
//	    return executa.Error(invokectx.ErrSubcallTimeout, "no time left in budget")
//	}
//	timeout := time.Duration(math.Min(5, ctx.RemainingS()) * float64(time.Second))
//	_ = storage.Set(ctx, key, value, timeout)
package context

import (
	"encoding/json"
	"math"
	"time"
)

// ErrSubcallTimeout is the wire error_name the host expects when a
// plugin pre-emptively bails because there is no time left in the
// invoke budget. Keep in sync with matrix/src/executa/protocol.py.
const ErrSubcallTimeout = "subcall_timeout"

// InvokeContext is a typed, read-only view of `params.context` for a
// single tool invocation. All fields may be zero when the host did not
// supply them.
type InvokeContext struct {
	InvokeID    string
	PluginName  string
	DeadlineMS  int64 // 0 ⇒ no deadline (HasDeadline == false)
	Credentials map[string]any
	Raw         map[string]any
}

// FromParams parses `params.context` from a raw `invoke` request body.
// `params` is the `params` field of the JSON-RPC envelope. Safe to call
// with `nil` — returns a zero-value InvokeContext.
func FromParams(params map[string]any) InvokeContext {
	if params == nil {
		return InvokeContext{}
	}
	ctxRaw, _ := params["context"].(map[string]any)
	if ctxRaw == nil {
		ctxRaw = map[string]any{}
	}

	out := InvokeContext{Raw: ctxRaw}

	if v, ok := ctxRaw["invoke_id"].(string); ok && v != "" {
		out.InvokeID = v
	} else if v, ok := params["invoke_id"].(string); ok {
		out.InvokeID = v
	}
	if v, ok := ctxRaw["plugin_name"].(string); ok {
		out.PluginName = v
	}
	out.DeadlineMS = parseDeadlineMS(ctxRaw["deadline_ms"])
	if creds, ok := ctxRaw["credentials"].(map[string]any); ok {
		out.Credentials = creds
	}
	return out
}

// HasDeadline reports whether the host gave us an absolute deadline.
func (c InvokeContext) HasDeadline() bool { return c.DeadlineMS > 0 }

// RemainingS returns the seconds left in the invoke budget. Returns
// +Inf when no deadline is set. Never returns a negative value — use
// Expired() to detect overshoot.
func (c InvokeContext) RemainingS() float64 {
	if !c.HasDeadline() {
		return math.Inf(+1)
	}
	rem := float64(c.DeadlineMS)/1000.0 - float64(time.Now().UnixNano())/1e9
	if rem < 0 {
		return 0
	}
	return rem
}

// Remaining returns RemainingS as a time.Duration. Returns
// `time.Duration(math.MaxInt64)` when no deadline is set so callers can
// pass it straight to `context.WithTimeout`.
func (c InvokeContext) Remaining() time.Duration {
	if !c.HasDeadline() {
		return time.Duration(math.MaxInt64)
	}
	rem := time.Until(time.Unix(0, c.DeadlineMS*int64(time.Millisecond)))
	if rem < 0 {
		return 0
	}
	return rem
}

// Expired reports whether the deadline (if any) has already passed.
func (c InvokeContext) Expired() bool {
	return c.HasDeadline() && c.RemainingS() <= 0
}

// parseDeadlineMS accepts the various JSON-decoded numeric shapes
// (float64 from encoding/json, json.Number, int64) and returns 0 on
// any parse failure — matching the Python/Node "soft fallback" policy.
func parseDeadlineMS(v any) int64 {
	switch n := v.(type) {
	case nil:
		return 0
	case float64:
		if n <= 0 {
			return 0
		}
		return int64(n)
	case int:
		if n <= 0 {
			return 0
		}
		return int64(n)
	case int64:
		if n <= 0 {
			return 0
		}
		return n
	case json.Number:
		i, err := n.Int64()
		if err != nil || i <= 0 {
			return 0
		}
		return i
	}
	return 0
}
