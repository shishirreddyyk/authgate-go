package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shishirreddyyk/authgate-go/internal/abuse"
	"github.com/shishirreddyyk/authgate-go/internal/keys"
	"github.com/shishirreddyyk/authgate-go/internal/limiter"
	"github.com/shishirreddyyk/authgate-go/internal/stats"
)

// brokenStore stands in for a Redis that has gone away.
type brokenStore struct{}

func (brokenStore) Incr(context.Context, string, time.Duration, time.Time) (int64, int64, error) {
	return 0, 0, errors.New("counter store unreachable")
}

type harness struct {
	srv   *Server
	now   time.Time
	token string
}

func newHarness(t *testing.T, limit int64, store limiter.Store) *harness {
	t.Helper()

	ks := keys.NewStore([]byte("test-pepper"))
	ks.Add("acct1", "good-secret", "echo:write", "stats:read")
	ks.Add("root", "root-secret", "*")

	h := &harness{now: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC), token: "ag_acct1_good-secret"}

	lim := limiter.New(store, limit, time.Minute)
	tracker := abuse.NewTracker(limiter.NewMemory(), abuse.DefaultConfig())
	h.srv = New(Config{Now: func() time.Time { return h.now }}, ks, lim, tracker, stats.NewRecorder())
	return h
}

func (h *harness) do(t *testing.T, method, path, token, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(`{"hello":"world"}`))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rr := httptest.NewRecorder()
	h.srv.ServeHTTP(rr, req)
	return rr
}

func TestHealthNeedsNoCredentials(t *testing.T) {
	h := newHarness(t, 100, limiter.NewMemory())
	rr := h.do(t, http.MethodGet, "/healthz", "", "1.2.3.4:1111")
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz returned %d", rr.Code)
	}
}

func TestUnauthenticatedRequestIsRejected(t *testing.T) {
	h := newHarness(t, 100, limiter.NewMemory())
	rr := h.do(t, http.MethodPost, "/v1/echo", "", "1.2.3.4:1111")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rr.Code)
	}
}

func TestMissingScopeIsForbiddenNotUnauthorized(t *testing.T) {
	h := newHarness(t, 100, limiter.NewMemory())
	// acct1 holds echo:write and stats:read, but not admin.
	rr := h.do(t, http.MethodGet, "/admin/keys", h.token, "1.2.3.4:1111")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 - a valid key without the scope is authenticated but not authorized", rr.Code)
	}
}

// TestBurstIsCutOffAtTheLimit: the plain rate-limit path.
func TestBurstIsCutOffAtTheLimit(t *testing.T) {
	h := newHarness(t, 5, limiter.NewMemory())

	for i := 1; i <= 5; i++ {
		rr := h.do(t, http.MethodPost, "/v1/echo", h.token, "1.2.3.4:1111")
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d returned %d, want 200", i, rr.Code)
		}
		if rr.Header().Get("X-RateLimit-Limit") != "5" {
			t.Fatalf("request %d missing X-RateLimit-Limit", i)
		}
	}

	rr := h.do(t, http.MethodPost, "/v1/echo", h.token, "1.2.3.4:1111")
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("request 6 returned %d, want 429", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After leaves a client guessing")
	}
}

// TestBudgetIsPerKeyNotGlobal: one caller exhausting its quota must not
// throttle a different caller.
func TestBudgetIsPerKeyNotGlobal(t *testing.T) {
	h := newHarness(t, 3, limiter.NewMemory())

	for i := 0; i < 4; i++ {
		h.do(t, http.MethodPost, "/v1/echo", h.token, "1.2.3.4:1111")
	}
	rr := h.do(t, http.MethodPost, "/v1/echo", "ag_root_root-secret", "1.2.3.4:1111")
	if rr.Code != http.StatusOK {
		t.Fatalf("second key got %d - budgets are leaking across callers", rr.Code)
	}
}

// TestCredentialStuffingGetsPenalised: repeated bad credentials from one
// source stop being answered on the auth path.
func TestCredentialStuffingGetsPenalised(t *testing.T) {
	h := newHarness(t, 1000, limiter.NewMemory())
	const attacker = "9.9.9.9:5555"

	for i := 0; i < 5; i++ {
		rr := h.do(t, http.MethodPost, "/v1/echo", "ag_acct1_guess", attacker)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d returned %d, want 401", i, rr.Code)
		}
	}

	rr := h.do(t, http.MethodPost, "/v1/echo", "ag_acct1_another-guess", attacker)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker still getting auth attempts answered: %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("block carried no Retry-After")
	}
}

// TestPenaltyDoesNotLockOutValidCredentials is the NAT case. A shared
// egress address must not become a denial-of-service primitive against
// everyone behind it.
func TestPenaltyDoesNotLockOutValidCredentials(t *testing.T) {
	h := newHarness(t, 1000, limiter.NewMemory())
	const shared = "9.9.9.9:5555"

	for i := 0; i < 8; i++ {
		h.do(t, http.MethodPost, "/v1/echo", "ag_acct1_guess", shared)
	}
	if blocked := h.do(t, http.MethodPost, "/v1/echo", "ag_acct1_guess", shared); blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the source to be in the penalty box, got %d", blocked.Code)
	}

	// Same address, correct credentials.
	rr := h.do(t, http.MethodPost, "/v1/echo", h.token, shared)
	if rr.Code == http.StatusTooManyRequests {
		t.Fatal("a legitimate user behind the same address was locked out by someone else's guessing")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("valid credentials returned %d, want 200", rr.Code)
	}
}

// TestPenaltyIsPerSource: the block must not be global.
func TestPenaltyIsPerSource(t *testing.T) {
	h := newHarness(t, 1000, limiter.NewMemory())

	for i := 0; i < 8; i++ {
		h.do(t, http.MethodPost, "/v1/echo", "ag_acct1_guess", "9.9.9.9:5555")
	}
	rr := h.do(t, http.MethodPost, "/v1/echo", h.token, "7.7.7.7:2222")
	if rr.Code != http.StatusOK {
		t.Fatalf("unrelated source got %d - one attacker is throttling the internet", rr.Code)
	}
}

// TestDegradedStoreFailsOpenOnReadsAndClosedOnAdmin encodes the
// availability trade-off: losing the counter store must not take down
// normal traffic, but it must never quietly unbottleneck /admin.
func TestDegradedStoreFailsOpenOnReadsAndClosedOnAdmin(t *testing.T) {
	h := newHarness(t, 5, brokenStore{})

	rr := h.do(t, http.MethodPost, "/v1/echo", h.token, "1.2.3.4:1111")
	if rr.Code != http.StatusOK {
		t.Fatalf("echo returned %d during a store outage, want 200 (fail open)", rr.Code)
	}
	if rr.Header().Get("X-Authgate-Degraded") != "true" {
		t.Fatal("served unlimited traffic without saying so - degradation must be loud")
	}

	admin := h.do(t, http.MethodGet, "/admin/keys", "ag_root_root-secret", "1.2.3.4:1111")
	if admin.Code != http.StatusServiceUnavailable {
		t.Fatalf("admin returned %d during a store outage, want 503 (fail closed)", admin.Code)
	}
}

// TestAdminListingNeverReturnsKeyMaterial.
func TestAdminListingNeverReturnsKeyMaterial(t *testing.T) {
	h := newHarness(t, 100, limiter.NewMemory())
	rr := h.do(t, http.MethodGet, "/admin/keys", "ag_root_root-secret", "1.2.3.4:1111")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin listing returned %d", rr.Code)
	}

	body := rr.Body.String()
	for _, secret := range []string{"good-secret", "root-secret", "ag_acct1_", "test-pepper"} {
		if strings.Contains(body, secret) {
			t.Fatalf("admin listing leaked %q", secret)
		}
	}

	var parsed struct {
		Keys []struct {
			ID   string `json:"id"`
			Hash string `json:"hash_prefix"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Keys) != 2 {
		t.Fatalf("listed %d keys, want 2", len(parsed.Keys))
	}
	for _, k := range parsed.Keys {
		if len(k.Hash) != 12 {
			t.Fatalf("key %s exposed a %d-char hash, want a 12-char prefix", k.ID, len(k.Hash))
		}
	}
}

// TestRejectionsAreShapedIdentically: unknown key and wrong secret must
// not differ in status or body, or the difference enumerates accounts.
func TestRejectionsAreShapedIdentically(t *testing.T) {
	h := newHarness(t, 1000, limiter.NewMemory())

	unknown := h.do(t, http.MethodPost, "/v1/echo", "ag_nosuchacct_x", "5.5.5.5:1")
	wrong := h.do(t, http.MethodPost, "/v1/echo", "ag_acct1_wrong", "6.6.6.6:1")

	if unknown.Code != wrong.Code {
		t.Fatalf("unknown key %d vs wrong secret %d", unknown.Code, wrong.Code)
	}
	if unknown.Body.String() != wrong.Body.String() {
		t.Fatalf("response bodies differ:\n%s\n%s", unknown.Body.String(), wrong.Body.String())
	}
}

func TestStatsReportPercentilesAndOutcomes(t *testing.T) {
	h := newHarness(t, 2, limiter.NewMemory())

	h.do(t, http.MethodPost, "/v1/echo", h.token, "1.2.3.4:1")
	h.do(t, http.MethodPost, "/v1/echo", h.token, "1.2.3.4:1")
	h.do(t, http.MethodPost, "/v1/echo", h.token, "1.2.3.4:1") // 429
	h.do(t, http.MethodPost, "/v1/echo", "ag_acct1_bad", "1.2.3.4:1")

	// Read stats with a different key: acct1's budget is deliberately
	// spent by the traffic above.
	rr := h.do(t, http.MethodGet, "/v1/stats", "ag_root_root-secret", "1.2.3.4:1")
	if rr.Code != http.StatusOK {
		t.Fatalf("stats returned %d", rr.Code)
	}
	var snap struct {
		Total       uint64 `json:"total_requests"`
		RateLimited uint64 `json:"rate_limited"`
		Denied      uint64 `json:"denied"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.RateLimited < 1 {
		t.Fatal("stats did not count the 429")
	}
	if snap.Denied < 1 {
		t.Fatal("stats did not count the 401")
	}
	if snap.Total < 4 {
		t.Fatalf("stats counted %d requests", snap.Total)
	}
}
