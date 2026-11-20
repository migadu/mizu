package recipient

import "testing"

// C11: the cache key was the fields joined with ":" and no escaping, while
// HELO names and quoted local parts may contain ":". Two different requests
// could share a key, so a verdict cached for one (accepted) answered the
// other without asking the backend - e.g. past a recipient's sender block.
func TestAudit_CacheKeyIsUnambiguous(t *testing.T) {
	v := &Validator{}
	a := v.buildCacheKey("192.0.2.1", "ptr.test", "mail.x.test", "a:evil@x.test", "victim@y.test")
	b := v.buildCacheKey("192.0.2.1", "ptr.test", "mail.x.test:a", "evil@x.test", "victim@y.test")
	if a == b {
		t.Fatalf("two different requests share the cache key %q", a)
	}
	c := v.buildCacheKey("192.0.2.1", "ptr.test", "h", `a" "b`, "c")
	d := v.buildCacheKey("192.0.2.1", "ptr.test", "h", "a", `b" "c`)
	if c == d {
		t.Fatalf("two different requests share the cache key %q", c)
	}
}
