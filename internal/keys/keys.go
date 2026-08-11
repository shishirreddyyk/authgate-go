// Package keys stores and verifies API credentials.
//
// Two properties matter here and both have tests:
//
//  1. The plaintext secret is never stored. Only HMAC-SHA256(secret,
//     pepper) is. A dump of the key table does not yield usable keys
//     without the pepper, which lives in the process environment.
//  2. Verification takes the same work whether the key ID exists or not.
//     A short-circuit on unknown IDs turns response latency into an
//     oracle for "is this key ID real", which is free reconnaissance.
package keys

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
)

var (
	ErrMalformed = errors.New("keys: malformed token")
	ErrRejected  = errors.New("keys: rejected")
)

// Key is a credential record. Secret is absent by construction.
type Key struct {
	ID       string
	hash     []byte
	Scopes   []string
	Disabled bool
}

func (k *Key) HasScope(want string) bool {
	for _, s := range k.Scopes {
		if s == want || s == "*" {
			return true
		}
	}
	return false
}

// HashPrefix is the only part of the stored hash that is safe to show in
// an admin listing: enough to tell two keys apart, useless for forgery.
func (k *Key) HashPrefix() string {
	return hex.EncodeToString(k.hash)[:12]
}

type Store struct {
	pepper []byte

	mu   sync.RWMutex
	byID map[string]*Key

	// decoy is hashed against when the key ID is unknown, so the work
	// done on a miss matches the work done on a hit.
	decoy []byte
}

func NewStore(pepper []byte) *Store {
	return &Store{
		pepper: pepper,
		byID:   make(map[string]*Key),
		decoy:  hash(pepper, "decoy-value-never-issued"),
	}
}

func hash(pepper []byte, secret string) []byte {
	m := hmac.New(sha256.New, pepper)
	m.Write([]byte(secret))
	return m.Sum(nil)
}

// Add registers a credential. The caller holds the only copy of secret.
func (s *Store) Add(id, secret string, scopes ...string) *Key {
	k := &Key{ID: id, hash: hash(s.pepper, secret), Scopes: scopes}
	s.mu.Lock()
	s.byID[id] = k
	s.mu.Unlock()
	return k
}

func (s *Store) Disable(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byID[id]
	if !ok {
		return false
	}
	k.Disabled = true
	return true
}

func (s *Store) List() []*Key {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Key, 0, len(s.byID))
	for _, k := range s.byID {
		out = append(out, k)
	}
	return out
}

// Parse splits a token of the form ag_<id>_<secret>.
func Parse(token string) (id, secret string, err error) {
	if !strings.HasPrefix(token, "ag_") {
		return "", "", ErrMalformed
	}
	rest := token[len("ag_"):]
	i := strings.Index(rest, "_")
	if i <= 0 || i == len(rest)-1 {
		return "", "", ErrMalformed
	}
	return rest[:i], rest[i+1:], nil
}

// Verify resolves a token to a key. Every failure returns the same
// error: callers must not be able to distinguish "no such key" from
// "wrong secret" from "disabled".
func (s *Store) Verify(token string) (*Key, error) {
	id, secret, err := Parse(token)
	if err != nil {
		// Still burn a comparison so malformed input is not the fast path.
		hmac.Equal(s.decoy, hash(s.pepper, token))
		return nil, ErrRejected
	}

	s.mu.RLock()
	k, found := s.byID[id]
	s.mu.RUnlock()

	candidate := hash(s.pepper, secret)

	expected := s.decoy
	if found {
		expected = k.hash
	}
	match := hmac.Equal(expected, candidate)

	if !found || !match || k.Disabled {
		return nil, ErrRejected
	}
	return k, nil
}

// Generate mints a token and returns it exactly once.
func Generate(id string) (token string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "ag_" + id + "_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
