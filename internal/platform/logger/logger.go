// Package logger provides log/slog-based structured logging with a
// correlation id propagated through context.Context (TECHSPEC-001 §6.6
// decision 6: log/slog, no framework).
//
// Attaching correlation_id via a context-aware slog.Handler wrapper
// (rather than requiring every call site to fetch and pass the id as a
// log attribute) is the chosen approach: it means a call site that
// forgets to thread the id through still gets it in the log record, as
// long as the id was placed on the context. The alternative — a
// FromContext helper each call site must remember to use — fails silently
// exactly when it matters, at the one call site someone forgot.
//
// Nothing here reads configuration directly: the logger never sees a
// Vault token, a signing key, or any other secret, because nothing here
// is handed one.
package logger

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"slices"
)

// contextKey is unexported and distinct from string so a correlation id
// placed on a context can never collide with a key set by another
// package using a string or int key of the same value.
type contextKey struct{}

var correlationIDKey = contextKey{}

// correlationIDAttr is the log attribute key the correlation id is written
// under. It is also the key Handle refuses to let a caller shadow.
const correlationIDAttr = "correlation_id"

// WithCorrelationID returns a context carrying id as the correlation id.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey, id)
}

// CorrelationID returns the correlation id carried by ctx, or "" if none
// was set.
func CorrelationID(ctx context.Context) string {
	id, _ := ctx.Value(correlationIDKey).(string)
	return id
}

// EnsureCorrelationID returns ctx unchanged with its existing correlation
// id if one is already present; otherwise it generates a fresh one and
// returns a context carrying it.
//
// The id comes from crypto/rand.Text — at least 128 bits — not math/rand,
// not a counter, not a timestamp, none of which is a safe source for an
// identifier meant to stay unique across concurrent requests.
//
// There is no error to handle and no panic to write. crypto/rand.Text
// cannot fail: it reads from crypto/rand.Reader, which is documented to
// never return an error and to crash the program irrecoverably if the
// operating system's entropy source ever does. Guarding it here would be a
// second, unreachable crash in front of the standard library's own.
func EnsureCorrelationID(ctx context.Context) (context.Context, string) {
	if id := CorrelationID(ctx); id != "" {
		return ctx, id
	}
	id := rand.Text()
	return WithCorrelationID(ctx, id), id
}

// New returns a *slog.Logger writing JSON records to w at the given
// level, wrapped so that any record logged through a context carrying a
// correlation id (see WithCorrelationID / EnsureCorrelationID) has
// correlation_id attached automatically.
func New(w io.Writer, level slog.Level) *slog.Logger {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(&correlationHandler{base: h})
}

// correlationHandler adds correlation_id to every record whose context
// carries one, always at the top level of the record.
//
// It does not embed and delegate to the wrapped handler, and it must not.
// An attribute added to a record inside Handle lands inside whatever groups
// the underlying handler already has open, so a logger derived with
// WithGroup("req") would emit {"req":{"correlation_id":"..."}} — buried
// under an arbitrary name, invisible to the aggregator query the id exists
// to serve. The only place a top-level attribute can be added is against a
// handler with no groups open.
//
// So this handler keeps the base handler ungrouped and accumulates the
// groups and attrs a caller applies, replaying them onto the record itself
// at Handle time (the "groupOrAttrs" shape from the standard library's own
// slog.Handler writing guide). correlation_id is then added last, to the
// ungrouped base, where it belongs.
type correlationHandler struct {
	base slog.Handler
	goas []groupOrAttrs
}

// groupOrAttrs is one link in the chain a caller built with WithGroup and
// WithAttrs. Exactly one of group or attrs is set.
type groupOrAttrs struct {
	group string
	attrs []slog.Attr
}

func (h *correlationHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}

// withGoa returns a copy of h with one more link appended. The slice is
// copied rather than appended in place: two loggers derived from the same
// parent must not share, and grow into, the same backing array.
func (h *correlationHandler) withGoa(goa groupOrAttrs) *correlationHandler {
	next := *h
	next.goas = make([]groupOrAttrs, len(h.goas)+1)
	copy(next.goas, h.goas)
	next.goas[len(next.goas)-1] = goa
	return &next
}

func (h *correlationHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	return h.withGoa(groupOrAttrs{attrs: attrs})
}

func (h *correlationHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return h.withGoa(groupOrAttrs{group: name})
}

func (h *correlationHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	// Walk the chain from the innermost link outwards, nesting as we go: an
	// attrs link contributes at its own level, a group link wraps everything
	// accumulated so far. A group that would end up empty is dropped, which
	// is what slog.Handler implementations are required to do.
	for i := len(h.goas) - 1; i >= 0; i-- {
		goa := h.goas[i]
		switch {
		case goa.group != "":
			if len(attrs) == 0 {
				continue
			}
			attrs = []slog.Attr{{Key: goa.group, Value: slog.GroupValue(attrs...)}}
		default:
			attrs = append(slices.Clone(goa.attrs), attrs...)
		}
	}

	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	if id := CorrelationID(ctx); id != "" {
		// Drop any top-level attribute that would collide. Emitting both
		// produces a record with a repeated JSON key, and RFC 8259 leaves
		// the winner to the parser: some take the first, some the last.
		// Log attributes are routinely built from request data, so the
		// colliding value can be chosen by whoever sent the request — and
		// the correlation id exists precisely so an operator can trust the
		// field they filter on. The context wins; a caller cannot shadow it.
		//
		// Only the top level is filtered. The same key nested inside a
		// group is a different field and collides with nothing.
		attrs = slices.DeleteFunc(attrs, func(a slog.Attr) bool {
			return a.Key == correlationIDAttr
		})
		out.AddAttrs(attrs...)
		out.AddAttrs(slog.String(correlationIDAttr, id))
		return h.base.Handle(ctx, out)
	}
	out.AddAttrs(attrs...)
	return h.base.Handle(ctx, out)
}
