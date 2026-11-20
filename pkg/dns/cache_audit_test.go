package dns

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Audit B5 (docs/security-audit-todo.md): the resolver cache was a plain map
// with no size bound, keyed by names the sender chooses (DKIM selectors, SPF
// includes, HELO names) and holding whatever the sender's zone answers. A
// stream of unique names with large TXT answers pinned memory for the TTL.
func TestAudit_ResolverCacheIsBounded(t *testing.T) {
	r := &ResilientResolver{cache: make(map[string]*cacheEntry), cacheTTL: time.Hour}

	for i := 0; i < maxCacheEntries*2; i++ {
		r.putCache(fmt.Sprintf("txt:s%d._domainkey.evil.test", i), []string{"v=DKIM1"})
	}
	if size, _ := r.GetCacheStats(); size > maxCacheEntries {
		t.Fatalf("cache holds %d entries, want at most %d", size, maxCacheEntries)
	}

	// The cache must still work when full: a fresh entry is retrievable.
	r.putCache("txt:fresh.example", []string{"hello"})
	if got, ok := r.getCached("txt:fresh.example"); !ok || len(got) != 1 || got[0] != "hello" {
		t.Fatalf("a new entry must be cached even when the cache was full, got %v %v", got, ok)
	}
}

func TestAudit_ResolverCacheSkipsOversizedAnswers(t *testing.T) {
	r := &ResilientResolver{cache: make(map[string]*cacheEntry), cacheTTL: time.Hour}

	r.putCache("txt:big.evil.test", []string{strings.Repeat("A", maxCachedAnswerBytes+1)})
	if _, ok := r.getCached("txt:big.evil.test"); ok {
		t.Fatal("an answer larger than the per-entry bound must not be cached")
	}

	r.putCache("txt:normal.example", []string{strings.Repeat("A", 2048)})
	if _, ok := r.getCached("txt:normal.example"); !ok {
		t.Fatal("an ordinary 2 KB answer must be cached")
	}
}
