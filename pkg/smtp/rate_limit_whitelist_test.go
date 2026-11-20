package smtp

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"migadu/mizu/pkg/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// oneDimConfig returns a rate limit config with a single per-IP dimension of the
// given limit, so tests can assert whitelist bypass against a real dimension.
func oneDimConfig(limit int) config.RateLimitConfig {
	return config.RateLimitConfig{
		Enabled: true,
		Dimensions: []config.RateLimitDimension{
			{Name: "per_ip", Keys: []string{"IP"}, Limit: limit, WindowSeconds: 60},
		},
	}
}

// TestRateLimiter_WhitelistedIP verifies inline IP and CIDR entries bypass all
// rate limit dimensions.
func TestRateLimiter_WhitelistedIP(t *testing.T) {
	cfg := oneDimConfig(2)
	cfg.WhitelistedIPs = []string{"10.1.2.3", "192.168.0.0/16"}

	rl := NewRateLimiter(cfg, nil, discardLogger())
	defer rl.Shutdown()

	// Non-whitelisted IP is limited after 2.
	other := SessionContext{RemoteAddr: "8.8.8.8:25", From: "a@x.com"}
	for i := 0; i < 2; i++ {
		if err := rl.CheckRateLimit(other); err != nil {
			t.Fatalf("email %d should be allowed: %v", i+1, err)
		}
	}
	if err := rl.CheckRateLimit(other); err == nil {
		t.Fatal("3rd email from non-whitelisted IP should be limited")
	}

	// Exact whitelisted IP bypasses.
	exact := SessionContext{RemoteAddr: "10.1.2.3:25", From: "a@x.com"}
	for i := 0; i < 50; i++ {
		if err := rl.CheckRateLimit(exact); err != nil {
			t.Fatalf("whitelisted IP should bypass at %d: %v", i+1, err)
		}
	}

	// Address inside whitelisted CIDR bypasses.
	cidr := SessionContext{RemoteAddr: "192.168.5.9:25", From: "a@x.com"}
	for i := 0; i < 50; i++ {
		if err := rl.CheckRateLimit(cidr); err != nil {
			t.Fatalf("IP in whitelisted CIDR should bypass at %d: %v", i+1, err)
		}
	}
}

// TestReadWhitelistFile checks comment and blank-line handling.
func TestReadWhitelistFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	content := "" +
		"# a full-line comment\n" +
		"\n" +
		"   \n" +
		"1.2.3.4\n" +
		"  10.0.0.0/8   # trailing comment\n" +
		"#another\n" +
		"example.com\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got := readWhitelistFile(path, discardLogger())
	want := []string{"1.2.3.4", "10.0.0.0/8", "example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d: got %q want %q", i, got[i], want[i])
		}
	}

	// Missing file yields no entries (and does not panic).
	if entries := readWhitelistFile(filepath.Join(dir, "missing.txt"), discardLogger()); entries != nil {
		t.Fatalf("missing file should yield nil, got %v", entries)
	}
}

// TestRateLimiter_WhitelistFromFile verifies file-sourced entries (IPs, domains,
// senders) are honored and merged with inline entries.
func TestRateLimiter_WhitelistFromFile(t *testing.T) {
	dir := t.TempDir()
	ipsFile := filepath.Join(dir, "ips.txt")
	domainsFile := filepath.Join(dir, "domains.txt")
	sendersFile := filepath.Join(dir, "senders.txt")
	if err := os.WriteFile(ipsFile, []byte("# ops probes\n203.0.113.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(domainsFile, []byte("Trusted.ORG\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sendersFile, []byte("Admin@Example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := oneDimConfig(1)
	// A sender-keyed dimension too, so the Mail-stage checks below exercise a
	// limit (per_ip alone is only charged at connect).
	cfg.Dimensions = append(cfg.Dimensions,
		config.RateLimitDimension{Name: "per_ip_from", Keys: []string{"IP", "FROM"}, Limit: 1, WindowSeconds: 60})
	cfg.WhitelistedIPsFile = ipsFile
	cfg.WhitelistedDomainsFile = domainsFile
	cfg.WhitelistedSendersFile = sendersFile

	rl := NewRateLimiter(cfg, nil, discardLogger())
	defer rl.Shutdown()

	cases := []SessionContext{
		{RemoteAddr: "203.0.113.7:25", From: "who@nowhere.test"}, // file IP
		// Sender entries exempt every dimension only for a verified
		// (authenticated) sender, hence AuthenticatedUser on these two.
		{RemoteAddr: "8.8.8.8:25", From: "bob@trusted.org", AuthenticatedUser: "bob@trusted.org"},     // file domain (case-insensitive)
		{RemoteAddr: "8.8.8.8:25", From: "admin@example.com", AuthenticatedUser: "admin@example.com"}, // file sender (case-insensitive)
	}
	for _, ctx := range cases {
		ctx.Stage = StageMail
		for i := 0; i < 10; i++ {
			if err := rl.CheckRateLimit(ctx); err != nil {
				t.Fatalf("whitelisted (from file) %+v should bypass at %d: %v", ctx, i+1, err)
			}
		}
	}
}

// TestRateLimiter_WhitelistFileAppearsLater verifies the "warn and continue"
// behavior: a configured file that is missing at startup is treated as empty,
// and the reload loop picks it up once it appears.
func TestRateLimiter_WhitelistFileAppearsLater(t *testing.T) {
	dir := t.TempDir()
	ipsFile := filepath.Join(dir, "not-yet-there.txt")

	cfg := oneDimConfig(2)
	cfg.WhitelistedIPsFile = ipsFile // path set, file does not exist yet
	cfg.WhitelistReloadIntervalSeconds = 1

	rl := NewRateLimiter(cfg, nil, discardLogger())
	defer rl.Shutdown()

	// Missing file at startup: limiter comes up empty (no crash), IP is limited.
	ctx := SessionContext{RemoteAddr: "203.0.113.99:25", From: "a@x.com"}
	for i := 0; i < 2; i++ {
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("email %d should be allowed pre-file: %v", i+1, err)
		}
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("expected limit before the file exists")
	}

	// Create the file; reload loop should detect it appearing.
	if err := os.WriteFile(ipsFile, []byte("203.0.113.99\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !rl.whitelist.Load().matchesIP("203.0.113.99") {
		if time.Now().After(deadline) {
			t.Fatal("whitelist file appearing was not picked up within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := rl.CheckRateLimit(ctx); err != nil {
		t.Fatalf("IP should bypass once the file appears: %v", err)
	}
}

// TestRateLimiter_WhitelistHotReload verifies that editing a whitelist file is
// picked up by the running limiter without reconstruction.
func TestRateLimiter_WhitelistHotReload(t *testing.T) {
	dir := t.TempDir()
	ipsFile := filepath.Join(dir, "ips.txt")
	if err := os.WriteFile(ipsFile, []byte("# empty to start\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := oneDimConfig(2)
	cfg.WhitelistedIPsFile = ipsFile
	cfg.WhitelistReloadIntervalSeconds = 1 // fast reload for the test

	rl := NewRateLimiter(cfg, nil, discardLogger())
	defer rl.Shutdown()

	ctx := SessionContext{RemoteAddr: "198.51.100.42:25", From: "a@x.com"}

	// Initially not whitelisted: limited after 2.
	for i := 0; i < 2; i++ {
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("email %d should be allowed pre-reload: %v", i+1, err)
		}
	}
	if err := rl.CheckRateLimit(ctx); err == nil {
		t.Fatal("expected limit before whitelisting")
	}

	// Add the IP to the file; the reload loop should pick it up.
	if err := os.WriteFile(ipsFile, []byte("198.51.100.42\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if rl.whitelist.Load().matchesIP("198.51.100.42") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("whitelist file change was not hot-reloaded within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Now the previously-limited IP bypasses the limit.
	for i := 0; i < 50; i++ {
		if err := rl.CheckRateLimit(ctx); err != nil {
			t.Fatalf("IP should bypass after hot reload at %d: %v", i+1, err)
		}
	}
}
