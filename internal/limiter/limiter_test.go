package limiter

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shishirreddyyk/authgate-go/internal/resp"
)

func TestMemoryAllowsUpToLimitThenRejects(t *testing.T) {
	l := New(NewMemory(), 10, time.Minute)
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

	for i := 1; i <= 10; i++ {
		d, err := l.Allow(context.Background(), "k", now)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if !d.Allowed {
			t.Fatalf("request %d rejected inside the budget (estimate %.2f)", i, d.Estimate)
		}
	}

	d, err := l.Allow(context.Background(), "k", now)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Fatal("request 11 allowed past a limit of 10")
	}
	if d.RetryAfter <= 0 {
		t.Fatal("rejection carried no Retry-After")
	}
	if d.Remaining != 0 {
		t.Fatalf("remaining = %d, want 0", d.Remaining)
	}
}

// TestSlidingWindowSurvivesBoundary is the reason this is not a fixed
// window. Spend the whole budget at the end of one window, then step
// one second into the next: a fixed window hands over a fresh full
// budget, which lets a caller do 2x the limit in two seconds.
func TestSlidingWindowSurvivesBoundary(t *testing.T) {
	l := New(NewMemory(), 10, time.Minute)
	ctx := context.Background()

	late := time.Date(2026, 7, 27, 12, 0, 59, 0, time.UTC)
	for i := 0; i < 10; i++ {
		if _, err := l.Allow(ctx, "k", late); err != nil {
			t.Fatal(err)
		}
	}

	justAfter := time.Date(2026, 7, 27, 12, 1, 1, 0, time.UTC)
	d, err := l.Allow(ctx, "k", justAfter)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed {
		t.Fatalf("fixed-window bug: full budget handed back across the boundary (estimate %.2f)", d.Estimate)
	}

	// Deep into the next window the previous count has aged out.
	wayAfter := time.Date(2026, 7, 27, 12, 1, 58, 0, time.UTC)
	d, err = l.Allow(ctx, "k", wayAfter)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed {
		t.Fatalf("still limited after the old window aged out (estimate %.2f)", d.Estimate)
	}
}

func TestMemoryStoreIsConcurrencySafe(t *testing.T) {
	store := NewMemory()
	l := New(store, 1000, time.Minute)
	now := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := l.Allow(context.Background(), "shared", now); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()

	cur, _, err := store.Incr(context.Background(), "shared", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if cur != 1001 {
		t.Fatalf("counted %d hits, want 1001 - a lost update means the mutex is not covering the read-modify-write", cur)
	}
}

func TestMemorySweepDropsStaleKeys(t *testing.T) {
	store := NewMemory()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	if _, _, err := store.Incr(context.Background(), "old", time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if n := store.Sweep(time.Minute, now.Add(10*time.Minute)); n != 1 {
		t.Fatalf("swept %d entries, want 1", n)
	}
}

// fakeRedis speaks just enough RESP to assert what the store puts on
// the wire and to hand back a canned reply.
type fakeRedis struct {
	ln       net.Listener
	mu       sync.Mutex
	received []string
	reply    string
	hangup   bool
}

func newFakeRedis(t *testing.T, reply string) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis{ln: ln, reply: reply}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeRedis) addr() string { return f.ln.Addr().String() }

func (f *fakeRedis) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				// Read one complete RESP command before answering. Reading the
				// whole command first is what makes wire() deterministic: the
				// client only unblocks once we reply, so by then every argument
				// -- including the multi-line Lua script and the key args that
				// follow it -- has already been recorded.
				if !f.readCommand(br) {
					return
				}
				f.mu.Lock()
				hangup := f.hangup
				reply := f.reply
				f.mu.Unlock()
				if hangup {
					return
				}
				c.Write([]byte(reply))
			}
		}(conn)
	}
}

// readCommand consumes one RESP array command, recording every byte it reads.
// Bulk strings are read by their declared length rather than by line, so a
// payload that contains newlines (the Lua script) is captured whole. It
// returns false when the connection is exhausted or malformed.
func (f *fakeRedis) readCommand(br *bufio.Reader) bool {
	header, err := br.ReadString('\n')
	if err != nil {
		return false
	}
	f.record(header)
	if !strings.HasPrefix(header, "*") {
		return true
	}
	n, err := strconv.Atoi(strings.TrimSpace(header[1:]))
	if err != nil {
		return false
	}
	for i := 0; i < n; i++ {
		lenLine, err := br.ReadString('\n')
		if err != nil {
			return false
		}
		f.record(lenLine)
		if !strings.HasPrefix(lenLine, "$") {
			continue
		}
		blen, err := strconv.Atoi(strings.TrimSpace(lenLine[1:]))
		if err != nil || blen < 0 {
			return false
		}
		buf := make([]byte, blen+2) // bulk payload plus its trailing CRLF
		if _, err := io.ReadFull(br, buf); err != nil {
			return false
		}
		f.record(string(buf))
	}
	return true
}

func (f *fakeRedis) record(s string) {
	f.mu.Lock()
	f.received = append(f.received, s)
	f.mu.Unlock()
}

func (f *fakeRedis) wire() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.received, "")
}

func TestRedisStoreSendsAtomicEvalAndParsesReply(t *testing.T) {
	f := newFakeRedis(t, "*2\r\n:3\r\n:7\r\n")
	client := resp.New(f.addr(), 2*time.Second)
	defer client.Close()

	store := NewRedis(client, "authgate")
	now := time.Date(2026, 7, 27, 12, 0, 30, 0, time.UTC)

	cur, prev, err := store.Incr(context.Background(), "key:abc", time.Minute, now)
	if err != nil {
		t.Fatalf("incr: %v", err)
	}
	if cur != 3 || prev != 7 {
		t.Fatalf("cur=%d prev=%d, want 3 and 7", cur, prev)
	}

	wire := f.wire()
	if !strings.Contains(wire, "EVAL") {
		t.Fatal("store did not use EVAL: the increment and the read are not atomic")
	}
	if !strings.Contains(wire, "INCR") || !strings.Contains(wire, "PEXPIRE") {
		t.Fatal("script did not carry INCR and PEXPIRE")
	}
	// Window start for 12:00:30 with a 1m window is 12:00:00.
	wantCur := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC).UnixMilli()
	if !strings.Contains(wire, "authgate:key:abc:"+itoa(wantCur)) {
		t.Fatalf("current-window key missing from the wire:\n%s", wire)
	}
	if !strings.Contains(wire, "authgate:key:abc:"+itoa(wantCur-60000)) {
		t.Fatalf("previous-window key missing from the wire:\n%s", wire)
	}
}

func TestRedisStoreSurfacesTransportFailure(t *testing.T) {
	f := newFakeRedis(t, "")
	f.mu.Lock()
	f.hangup = true
	f.mu.Unlock()

	client := resp.New(f.addr(), 300*time.Millisecond)
	defer client.Close()

	store := NewRedis(client, "authgate")
	_, _, err := store.Incr(context.Background(), "k", time.Minute, time.Now())
	if err == nil {
		t.Fatal("a dead counter store reported success; the gate would silently stop limiting")
	}
}

func itoa(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			break
		}
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
