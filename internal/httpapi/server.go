// Package httpapi wires the gate: authentication, penalty box, rate
// limit, handler. The order is a decision, not an accident - see the
// comment in gate() and DESIGN.md section 4.
//
// The rate limiter runs after authentication because the budget is per
// key, and an unauthenticated caller has no key to spend against.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shishirreddyyk/authgate-go/internal/abuse"
	"github.com/shishirreddyyk/authgate-go/internal/keys"
	"github.com/shishirreddyyk/authgate-go/internal/limiter"
	"github.com/shishirreddyyk/authgate-go/internal/stats"
)

type Config struct {
	// FailClosedPrefixes are paths that must be denied when the counter
	// store is unreachable. Everything else fails open with a header, on
	// the argument that losing Redis should not take down reads, but it
	// must never silently unbottleneck an administrative path.
	FailClosedPrefixes []string
	Now                func() time.Time
}

type Server struct {
	cfg      Config
	keys     *keys.Store
	limiter  *limiter.Limiter
	tracker  *abuse.Tracker
	recorder *stats.Recorder
	mux      *http.ServeMux
}

func New(cfg Config, ks *keys.Store, lim *limiter.Limiter, tr *abuse.Tracker, rec *stats.Recorder) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.FailClosedPrefixes == nil {
		cfg.FailClosedPrefixes = []string{"/admin/"}
	}

	s := &Server{cfg: cfg, keys: ks, limiter: lim, tracker: tr, recorder: rec, mux: http.NewServeMux()}

	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.Handle("GET /v1/stats", s.gate("stats:read", http.HandlerFunc(s.handleStats)))
	s.mux.Handle("POST /v1/echo", s.gate("echo:write", http.HandlerFunc(s.handleEcho)))
	s.mux.Handle("GET /admin/keys", s.gate("admin", http.HandlerFunc(s.handleAdminKeys)))

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := s.cfg.Now()
	rw := &recordingWriter{ResponseWriter: w, status: http.StatusOK}

	s.mux.ServeHTTP(rw, r)

	outcome := stats.Allowed
	switch {
	case rw.status == http.StatusTooManyRequests:
		outcome = stats.RateLimited
	case rw.status >= 400:
		outcome = stats.Denied
	}
	s.recorder.Observe(s.cfg.Now().Sub(start), outcome)
}

// gate is the middleware chain applied to every authenticated route.
func (s *Server) gate(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := s.cfg.Now()
		src := clientIP(r)

		// 1. Authenticate first, even for a source already in the penalty
		// box. Checking the block first would be cheaper, but it would
		// also lock out every legitimate caller sharing an egress address
		// with one attacker - turning the control into a denial-of-service
		// primitive. The cost of that choice is one HMAC per request from
		// a blocked source. HMAC-SHA256 over 32 bytes is nanoseconds; if
		// this were bcrypt the trade would go the other way.
		token := bearer(r)
		key, err := s.keys.Verify(token)

		// 2. Penalty box, applied only to requests that failed to
		// authenticate.
		if err != nil {
			if blocked, retry := s.tracker.Blocked(src, now); blocked {
				w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
				writeErr(w, http.StatusTooManyRequests, "temporarily blocked")
				return
			}
			if _, ferr := s.tracker.RecordFailure(r.Context(), src, now); ferr != nil {
				// Counter store is down. The auth decision already stands;
				// say that abuse tracking is degraded rather than hide it.
				w.Header().Set("X-Authgate-Degraded", "true")
			}
			writeErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// 3. Authorize.
		if !key.HasScope(scope) {
			writeErr(w, http.StatusForbidden, "missing scope "+scope)
			return
		}

		// 4. Rate limit, per key.
		decision, lerr := s.limiter.Allow(r.Context(), "key:"+key.ID, now)
		if lerr != nil {
			if s.failClosed(r.URL.Path) {
				w.Header().Set("X-Authgate-Degraded", "true")
				writeErr(w, http.StatusServiceUnavailable, "rate limiter unavailable")
				return
			}
			w.Header().Set("X-Authgate-Degraded", "true")
			next.ServeHTTP(w, requestWithKey(r, key))
			return
		}

		w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(decision.Limit, 10))
		w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(decision.Remaining, 10))
		if !decision.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(decision.RetryAfter.Seconds())))
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		next.ServeHTTP(w, requestWithKey(r, key))
	})
}

func (s *Server) failClosed(path string) bool {
	for _, p := range s.cfg.FailClosedPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

type ctxKey struct{}

func requestWithKey(r *http.Request, k *keys.Key) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, k))
}

// KeyFrom returns the authenticated key for a request, if any.
func KeyFrom(ctx context.Context) (*keys.Key, bool) {
	k, ok := ctx.Value(ctxKey{}).(*keys.Key)
	return k, ok
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.recorder.Snapshot())
}

func (s *Server) handleEcho(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		if errors.Is(err, http.ErrBodyReadAfterClose) || err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json body")
			return
		}
	}
	key, _ := KeyFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"key_id": key.ID, "echo": body})
}

// handleAdminKeys lists credentials. It returns key IDs, scopes and a
// hash prefix. It never returns the stored hash in full and cannot
// return the secret, which does not exist on this side of the wire.
func (s *Server) handleAdminKeys(w http.ResponseWriter, _ *http.Request) {
	type row struct {
		ID       string   `json:"id"`
		Scopes   []string `json:"scopes"`
		Disabled bool     `json:"disabled"`
		Hash     string   `json:"hash_prefix"`
	}
	out := []row{}
	for _, k := range s.keys.List() {
		out = append(out, row{ID: k.ID, Scopes: k.Scopes, Disabled: k.Disabled, Hash: k.HashPrefix()})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return h[7:]
	}
	return ""
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type recordingWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *recordingWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}
