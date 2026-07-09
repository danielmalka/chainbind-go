package http

import "net/http"

// healthHandler always answers 200 {"status":"ok"} — a liveness signal,
// never a dependency check (that is /ready's job, PRD Story 6 AC-2).
func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
