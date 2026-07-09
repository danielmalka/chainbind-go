package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"testing/slogtest"
)

func TestCorrelationID_AbsentIsEmptyString(t *testing.T) {
	if got := CorrelationID(context.Background()); got != "" {
		t.Fatalf("CorrelationID(background) = %q, want empty string", got)
	}
}

func TestWithCorrelationID_RoundTrips(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "abc123")
	if got := CorrelationID(ctx); got != "abc123" {
		t.Fatalf("CorrelationID = %q, want %q", got, "abc123")
	}
}

func TestEnsureCorrelationID_GeneratesDistinctIDsPerCall(t *testing.T) {
	_, id1 := EnsureCorrelationID(context.Background())
	_, id2 := EnsureCorrelationID(context.Background())
	if id1 == "" || id2 == "" {
		t.Fatalf("EnsureCorrelationID produced an empty id: %q, %q", id1, id2)
	}
	if id1 == id2 {
		t.Fatalf("EnsureCorrelationID produced the same id twice: %q", id1)
	}
}

func TestEnsureCorrelationID_PreservesExisting(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "already-set")
	got, id := EnsureCorrelationID(ctx)
	if id != "already-set" {
		t.Fatalf("EnsureCorrelationID id = %q, want existing %q", id, "already-set")
	}
	if CorrelationID(got) != "already-set" {
		t.Fatalf("EnsureCorrelationID returned context with id = %q, want %q", CorrelationID(got), "already-set")
	}
}

func TestNew_RecordCarriesCorrelationIDWhenPresent(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, 0)

	ctx := WithCorrelationID(context.Background(), "req-42")
	log.InfoContext(ctx, "hello")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode log record: %v", err)
	}
	if record["correlation_id"] != "req-42" {
		t.Fatalf("record[correlation_id] = %v, want %q", record["correlation_id"], "req-42")
	}
}

func TestNew_RecordOmitsCorrelationIDWhenAbsent(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, 0)

	log.InfoContext(context.Background(), "hello")

	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("decode log record: %v", err)
	}
	if _, present := record["correlation_id"]; present {
		t.Fatalf("record contains correlation_id = %v, want the field absent entirely", record["correlation_id"])
	}
}

// TestHandler_SlogConformance runs the standard library's own handler
// conformance suite. correlationHandler does not embed and delegate to
// slog.JSONHandler — it accumulates groups and attrs and replays them onto
// the record itself, so that correlation_id can be added to an ungrouped
// base handler. That is a real slog.Handler implementation, and a real
// implementation is exactly where the subtle bugs live: an empty group that
// should have been elided, a WithAttrs that mutates a shared slice, a
// pre-group attr that leaks into the group.
//
// slogtest.TestHandler checks all of it, and it is why this handler may be
// hand-written at all.
func TestHandler_SlogConformance(t *testing.T) {
	var buf bytes.Buffer
	h := &correlationHandler{base: slog.NewJSONHandler(&buf, nil)}

	results := func() []map[string]any {
		var out []map[string]any
		for _, line := range bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatalf("unmarshal record %q: %v", line, err)
			}
			out = append(out, m)
		}
		return out
	}

	if err := slogtest.TestHandler(h, results); err != nil {
		t.Fatalf("slogtest.TestHandler: %v", err)
	}
}

// TestCorrelationID_StaysTopLevelOnDerivedLoggers is the regression test for
// the bug this handler was rewritten to fix. A logger derived with
// WithGroup used to emit {"g":{"correlation_id":"..."}} — nested under an
// arbitrary group name, invisible to the aggregator query that is the entire
// reason a correlation id exists. It must sit at the top level no matter how
// the logger was derived.
func TestCorrelationID_StaysTopLevelOnDerivedLoggers(t *testing.T) {
	const id = "CID-77"

	cases := map[string]func(*slog.Logger) *slog.Logger{
		"root":           func(l *slog.Logger) *slog.Logger { return l },
		"With":           func(l *slog.Logger) *slog.Logger { return l.With("k", "v") },
		"WithGroup":      func(l *slog.Logger) *slog.Logger { return l.WithGroup("g") },
		"WithGroup+With": func(l *slog.Logger) *slog.Logger { return l.WithGroup("g").With("k", "v") },
		"With+WithGroup": func(l *slog.Logger) *slog.Logger { return l.With("k", "v").WithGroup("g") },
		"nested WithGroup": func(l *slog.Logger) *slog.Logger {
			return l.WithGroup("outer").WithGroup("inner").With("k", "v")
		},
	}

	for name, derive := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			derive(New(&buf, slog.LevelInfo)).InfoContext(WithCorrelationID(context.Background(), id), "hello")

			var rec map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
				t.Fatalf("unmarshal record: %v", err)
			}
			got, ok := rec["correlation_id"].(string)
			if !ok {
				t.Fatalf("correlation_id is not a top-level string in %s", buf.String())
			}
			if got != id {
				t.Fatalf("correlation_id = %q, want %q", got, id)
			}
		})
	}
}

// TestDerivedLoggers_DoNotShareBackingArray pins withGoa's slice copy.
//
// The chain must be deep enough for `append` to have over-allocated before
// it branches: appending to a full slice always reallocates, so a one-level
// derivation would pass even with a plain `append(h.goas, goa)`. Three links
// leave spare capacity; two loggers derived from that point then write into
// the same backing array, and the second silently overwrites the first's
// last link. Here that means logger x reports itself as "y".
func TestDerivedLoggers_DoNotShareBackingArray(t *testing.T) {
	var buf bytes.Buffer

	// Three links, so the goas slice has grown past its length.
	parent := New(&buf, slog.LevelInfo).With("a", 1).With("b", 2).With("c", 3)

	x := parent.With("who", "x")
	y := parent.With("who", "y")

	// y is derived before x logs: with a shared array, x now reads y's link.
	buf.Reset()
	x.InfoContext(context.Background(), "hello")
	if !bytes.Contains(buf.Bytes(), []byte(`"who":"x"`)) {
		t.Fatalf("x logged %s", buf.String())
	}

	buf.Reset()
	y.InfoContext(context.Background(), "hello")
	if !bytes.Contains(buf.Bytes(), []byte(`"who":"y"`)) {
		t.Fatalf("y logged %s", buf.String())
	}
}

// TestCorrelationID_CallerCannotShadowIt pins the collision rule. Emitting
// both the caller's attribute and the context's would produce a record with
// a repeated JSON key, and RFC 8259 leaves the winner to the parser. Log
// attributes are routinely built from request data, so the colliding value
// can be chosen by whoever sent the request; the field an operator filters
// on must come from the context.
func TestCorrelationID_CallerCannotShadowIt(t *testing.T) {
	ctx := WithCorrelationID(context.Background(), "REAL")

	cases := map[string]func(*slog.Logger) *slog.Logger{
		"via With": func(l *slog.Logger) *slog.Logger { return l.With(correlationIDAttr, "SPOOFED") },
		"root":     func(l *slog.Logger) *slog.Logger { return l },
	}

	for name, derive := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			l := derive(New(&buf, slog.LevelInfo))
			if name == "root" {
				l.InfoContext(ctx, "hello", correlationIDAttr, "SPOOFED")
			} else {
				l.InfoContext(ctx, "hello")
			}

			raw := buf.Bytes()
			if bytes.Contains(raw, []byte("SPOOFED")) {
				t.Fatalf("caller's correlation_id survived: %s", raw)
			}
			if n := bytes.Count(raw, []byte(`"correlation_id"`)); n != 1 {
				t.Fatalf("correlation_id appears %d times, want exactly 1: %s", n, raw)
			}

			var rec map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(raw), &rec); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if rec[correlationIDAttr] != "REAL" {
				t.Fatalf("correlation_id = %v, want REAL", rec[correlationIDAttr])
			}
		})
	}
}

// TestCorrelationID_NestedKeyIsNotFiltered proves the filter is surgical: a
// correlation_id inside a group is a different field and must survive.
func TestCorrelationID_NestedKeyIsNotFiltered(t *testing.T) {
	var buf bytes.Buffer
	ctx := WithCorrelationID(context.Background(), "REAL")
	New(&buf, slog.LevelInfo).WithGroup("g").InfoContext(ctx, "hello", correlationIDAttr, "INNER")

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rec[correlationIDAttr] != "REAL" {
		t.Fatalf("top-level correlation_id = %v, want REAL", rec[correlationIDAttr])
	}
	group, ok := rec["g"].(map[string]any)
	if !ok {
		t.Fatalf("group g missing: %s", buf.String())
	}
	if group[correlationIDAttr] != "INNER" {
		t.Fatalf("g.correlation_id = %v, want INNER — the filter reached into a group", group[correlationIDAttr])
	}
}
