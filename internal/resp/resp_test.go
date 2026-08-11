package resp

import (
	"bufio"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// stub is a server that records the bytes it receives and replies with a
// canned payload. It lets the client be tested against the actual wire
// format without running Redis in CI.
type stub struct {
	ln    net.Listener
	reply string

	mu       sync.Mutex
	received strings.Builder
	drop     bool
}

func newStub(t *testing.T, reply string) *stub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stub{ln: ln, reply: reply}
	go s.accept()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *stub) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				s.mu.Lock()
				s.received.WriteString(line)
				drop := s.drop
				s.mu.Unlock()
				if drop {
					return
				}
				if strings.HasPrefix(line, "*") || strings.HasPrefix(line, "$") {
					continue
				}
				io.WriteString(c, s.reply)
			}
		}(c)
	}
}

func (s *stub) wire() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.received.String()
}

func TestEncodesCommandsAsRespArrays(t *testing.T) {
	s := newStub(t, ":1\r\n")
	c := New(s.ln.Addr().String(), time.Second)
	defer c.Close()

	if _, err := c.Do("PING"); err != nil {
		t.Fatal(err)
	}
	want := "*1\r\n$4\r\nPING\r\n"
	if got := s.wire(); got != want {
		t.Fatalf("wire = %q, want %q", got, want)
	}
}

func TestDecodesReplyKinds(t *testing.T) {
	cases := []struct {
		name  string
		reply string
		check func(t *testing.T, v Value)
	}{
		{"integer", ":42\r\n", func(t *testing.T, v Value) {
			if v.Kind != KindInt || v.Int != 42 {
				t.Fatalf("got %+v", v)
			}
		}},
		{"simple string", "+PONG\r\n", func(t *testing.T, v Value) {
			if v.Kind != KindString || v.Str != "PONG" {
				t.Fatalf("got %+v", v)
			}
		}},
		{"bulk string", "$5\r\nhello\r\n", func(t *testing.T, v Value) {
			if v.Kind != KindString || v.Str != "hello" {
				t.Fatalf("got %+v", v)
			}
		}},
		{"nil bulk", "$-1\r\n", func(t *testing.T, v Value) {
			if v.Kind != KindNil {
				t.Fatalf("got %+v", v)
			}
		}},
		{"array", "*2\r\n:3\r\n:9\r\n", func(t *testing.T, v Value) {
			if v.Kind != KindArray || len(v.Array) != 2 || v.Array[0].Int != 3 || v.Array[1].Int != 9 {
				t.Fatalf("got %+v", v)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStub(t, tc.reply)
			c := New(s.ln.Addr().String(), time.Second)
			defer c.Close()

			v, err := c.Do("GET", "k")
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, v)
		})
	}
}

func TestServerErrorBecomesGoError(t *testing.T) {
	s := newStub(t, "-ERR unknown command\r\n")
	c := New(s.ln.Addr().String(), time.Second)
	defer c.Close()

	if _, err := c.Do("NOPE"); err == nil {
		t.Fatal("server error reply did not surface as an error")
	}
}

// TestConnectionIsDroppedAfterFailure: reusing a socket whose read
// position is unknown corrupts every later reply.
func TestConnectionIsDroppedAfterFailure(t *testing.T) {
	s := newStub(t, "")
	s.mu.Lock()
	s.drop = true
	s.mu.Unlock()

	c := New(s.ln.Addr().String(), 300*time.Millisecond)
	defer c.Close()

	if _, err := c.Do("PING"); err == nil {
		t.Fatal("expected an error when the server hung up")
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		t.Fatal("client kept a connection it could no longer trust")
	}
}

func TestDialFailureIsReported(t *testing.T) {
	c := New("127.0.0.1:1", 200*time.Millisecond)
	defer c.Close()
	if _, err := c.Do("PING"); err == nil {
		t.Fatal("dial to a closed port reported success")
	}
}

func TestClosedClientRefusesWork(t *testing.T) {
	s := newStub(t, ":1\r\n")
	c := New(s.ln.Addr().String(), time.Second)
	c.Close()
	if _, err := c.Do("PING"); err != ErrClosed {
		t.Fatalf("got %v, want ErrClosed", err)
	}
}
