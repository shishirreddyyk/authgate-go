package keys

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func newTestStore() (*Store, string) {
	s := NewStore([]byte("test-pepper"))
	s.Add("acct1", "s3cret-value", "echo:write")
	return s, "ag_acct1_s3cret-value"
}

func TestVerifyAcceptsGoodTokenAndReturnsScopes(t *testing.T) {
	s, token := newTestStore()

	k, err := s.Verify(token)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if k.ID != "acct1" {
		t.Fatalf("id = %q, want acct1", k.ID)
	}
	if !k.HasScope("echo:write") {
		t.Fatal("granted scope missing")
	}
	if k.HasScope("admin") {
		t.Fatal("key holds a scope it was never granted")
	}
}

// TestFailuresAreIndistinguishable: unknown key, wrong secret, disabled
// key and malformed input must all produce the same error. Any
// difference is a free oracle for enumerating valid key IDs.
func TestFailuresAreIndistinguishable(t *testing.T) {
	s, _ := newTestStore()
	s.Add("disabled-acct", "whatever", "echo:write")
	s.Disable("disabled-acct")

	cases := map[string]string{
		"unknown id":     "ag_nosuch_anything",
		"wrong secret":   "ag_acct1_wrong-value",
		"disabled key":   "ag_disabled-acct_whatever",
		"malformed":      "not-a-token",
		"empty":          "",
		"missing secret": "ag_acct1_",
	}

	for name, token := range cases {
		_, err := s.Verify(token)
		if !errors.Is(err, ErrRejected) {
			t.Errorf("%s: got %v, want the single shared rejection error", name, err)
		}
	}
}

// TestSecretIsNotRecoverable: the store must hold a hash, never the
// plaintext. This is what makes a leaked key table useless on its own.
func TestSecretIsNotRecoverable(t *testing.T) {
	s, _ := newTestStore()

	for _, k := range s.List() {
		if bytes.Contains(k.hash, []byte("s3cret-value")) {
			t.Fatal("plaintext secret found inside the stored hash")
		}
		if strings.Contains(k.HashPrefix(), "s3cret") {
			t.Fatal("hash prefix leaked secret material")
		}
		if len(k.HashPrefix()) != 12 {
			t.Fatalf("hash prefix length %d, want a short non-forgeable prefix", len(k.HashPrefix()))
		}
	}
}

// TestPepperChangesTheHash: two stores with different peppers must not
// accept each other's credentials, or the pepper is decoration.
func TestPepperChangesTheHash(t *testing.T) {
	a := NewStore([]byte("pepper-a"))
	a.Add("acct", "same-secret", "*")
	b := NewStore([]byte("pepper-b"))
	b.Add("acct", "same-secret", "*")

	ka := a.List()[0]
	kb := b.List()[0]
	if bytes.Equal(ka.hash, kb.hash) {
		t.Fatal("same hash under different peppers")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	bad := []string{"", "ag_", "ag_only", "ag__nokey", "xx_a_b"}
	for _, in := range bad {
		if _, _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted malformed input", in)
		}
	}
}

func TestGenerateProducesParseableUniqueTokens(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := Generate("acct")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Parse(tok); err != nil {
			t.Fatalf("generated token does not parse: %q", tok)
		}
		if seen[tok] {
			t.Fatal("Generate repeated a token")
		}
		seen[tok] = true
	}
}

func TestWildcardScope(t *testing.T) {
	s := NewStore([]byte("p"))
	s.Add("root", "x", "*")
	k, err := s.Verify("ag_root_x")
	if err != nil {
		t.Fatal(err)
	}
	if !k.HasScope("anything") {
		t.Fatal("wildcard scope did not satisfy a named scope")
	}
}
