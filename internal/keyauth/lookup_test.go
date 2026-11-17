package keyauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// The lookup id names one key (128 bits of SHA-256 over the whole
// key), unlike the 20-bit display prefix two keys can share.
func TestLookupID(t *testing.T) {
	raw, short, _, err := Generate(KindHost)
	if err != nil {
		t.Fatal(err)
	}
	id := LookupID(raw)
	if len(id) != LookupIDLen || id != strings.ToLower(id) {
		t.Fatalf("lookup id %q: want %d lower-case hex characters", id, LookupIDLen)
	}
	if LookupID(raw) != id {
		t.Fatal("lookup id is not deterministic")
	}
	sibling := short + strings.Repeat("a", RawSuffixLen-(ShortPrefixLen-len(HostKeyPrefix)))
	if !ValidateFormat(sibling) || LookupID(sibling) == id {
		t.Fatal("two keys with the same display prefix share a lookup id")
	}
	if strings.Contains(id, raw[ShortPrefixLen:]) {
		t.Fatal("lookup id carries the key text")
	}
	if LookupID("wafh_short") != "" || LookupID("") != "" {
		t.Fatal("malformed key got a lookup id")
	}
}

// Verifications wait for a slot; a caller whose context ends while every
// slot is busy gives up instead of piling up argon2id allocations.
func TestVerifyContextGivesUpWhenSlotsBusy(t *testing.T) {
	raw, _, hash, err := Generate(KindHost)
	if err != nil {
		t.Fatal(err)
	}
	for range cap(verifySlots) {
		verifySlots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	ok, err := VerifyContext(ctx, raw, hash)
	for range cap(verifySlots) {
		<-verifySlots
	}
	if ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("VerifyContext with no free slot = %v, %v; want false, deadline exceeded", ok, err)
	}
	if ok, err := VerifyContext(context.Background(), raw, hash); !ok || err != nil {
		t.Fatalf("VerifyContext = %v, %v once slots are free", ok, err)
	}
}
