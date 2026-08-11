// Package resp implements the small slice of the Redis wire protocol
// (RESP2) that authgate needs: enough to run an EVAL script and a PING.
//
// This is deliberately not a general Redis client. Four commands, one
// connection, no dependency tree. See DESIGN.md for why.
package resp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type Kind int

const (
	KindInt Kind = iota
	KindString
	KindNil
	KindArray
)

// Value is a decoded RESP reply.
type Value struct {
	Kind  Kind
	Int   int64
	Str   string
	Array []Value
}

// ErrClosed is returned once a client has been shut down.
var ErrClosed = errors.New("resp: client closed")

// Client is a single-connection RESP client. Calls are serialized by a
// mutex: authgate issues one round trip per request and the limiter is
// already the cheap path, so a pool would add moving parts without
// buying throughput at this scale. Documented, not accidental.
type Client struct {
	addr    string
	timeout time.Duration

	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
	closed bool
}

func New(addr string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	return &Client{addr: addr, timeout: timeout}
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return c.dropLocked()
}

func (c *Client) dropLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	c.reader = nil
	return err
}

func (c *Client) connectLocked() error {
	if c.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
	if err != nil {
		return fmt.Errorf("resp: dial %s: %w", c.addr, err)
	}
	c.conn = conn
	c.reader = bufio.NewReader(conn)
	return nil
}

// Do sends one command and returns its reply. Any transport error drops
// the connection so the next call redials rather than reusing a socket
// whose read position is now unknown.
func (c *Client) Do(args ...string) (Value, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return Value{}, ErrClosed
	}
	if err := c.connectLocked(); err != nil {
		return Value{}, err
	}

	deadline := time.Now().Add(c.timeout)
	if err := c.conn.SetDeadline(deadline); err != nil {
		c.dropLocked()
		return Value{}, err
	}

	if _, err := c.conn.Write(encode(args)); err != nil {
		c.dropLocked()
		return Value{}, fmt.Errorf("resp: write: %w", err)
	}

	v, err := decode(c.reader)
	if err != nil {
		c.dropLocked()
		return Value{}, err
	}
	return v, nil
}

// encode writes a command as a RESP array of bulk strings.
func encode(args []string) []byte {
	buf := make([]byte, 0, 32*len(args))
	buf = append(buf, '*')
	buf = strconv.AppendInt(buf, int64(len(args)), 10)
	buf = append(buf, '\r', '\n')
	for _, a := range args {
		buf = append(buf, '$')
		buf = strconv.AppendInt(buf, int64(len(a)), 10)
		buf = append(buf, '\r', '\n')
		buf = append(buf, a...)
		buf = append(buf, '\r', '\n')
	}
	return buf
}

func decode(r *bufio.Reader) (Value, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return Value{}, fmt.Errorf("resp: read type: %w", err)
	}

	line, err := readLine(r)
	if err != nil {
		return Value{}, err
	}

	switch prefix {
	case '+':
		return Value{Kind: KindString, Str: line}, nil
	case '-':
		return Value{}, fmt.Errorf("resp: server error: %s", line)
	case ':':
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return Value{}, fmt.Errorf("resp: bad integer %q", line)
		}
		return Value{Kind: KindInt, Int: n}, nil
	case '$':
		n, err := strconv.Atoi(line)
		if err != nil {
			return Value{}, fmt.Errorf("resp: bad bulk length %q", line)
		}
		if n < 0 {
			return Value{Kind: KindNil}, nil
		}
		body := make([]byte, n+2) // payload + CRLF
		if _, err := io.ReadFull(r, body); err != nil {
			return Value{}, fmt.Errorf("resp: read bulk: %w", err)
		}
		return Value{Kind: KindString, Str: string(body[:n])}, nil
	case '*':
		n, err := strconv.Atoi(line)
		if err != nil {
			return Value{}, fmt.Errorf("resp: bad array length %q", line)
		}
		if n < 0 {
			return Value{Kind: KindNil}, nil
		}
		out := Value{Kind: KindArray, Array: make([]Value, 0, n)}
		for i := 0; i < n; i++ {
			item, err := decode(r)
			if err != nil {
				return Value{}, err
			}
			out.Array = append(out.Array, item)
		}
		return out, nil
	default:
		return Value{}, fmt.Errorf("resp: unknown type byte %q", prefix)
	}
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("resp: read line: %w", err)
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", errors.New("resp: malformed line terminator")
	}
	return line[:len(line)-2], nil
}
