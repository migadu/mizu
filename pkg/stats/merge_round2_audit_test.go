package stats

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func gzipped(t *testing.T, s string) io.Reader {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := io.Copy(gw, strings.NewReader(s)); err != nil {
		t.Fatal(err)
	}
	gw.Close()
	return &buf
}

// D13: a peer's stats file is data from another process. A null entry
// ({"ips":{"203.0.113.9":null}}) was dereferenced in mergeIPEntry and
// panicked the sync loop.
func TestAudit_StatsMergeSkipsNullEntries(t *testing.T) {
	m := NewManager(true, 24*time.Hour, "test-host", false, 0, nil, 0, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))

	export, err := decodeStatsExport(gzipped(t, `{"ips":{"203.0.113.9":null,"203.0.113.10":{"connections":3}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if merged := m.mergeStats(export); merged != 1 {
		t.Fatalf("merged %d entries, want 1 (the null entry skipped)", merged)
	}
	if _, ok := m.ips["203.0.113.9"]; ok {
		t.Fatal("the null entry was stored")
	}
}

// The decompressed size was unbounded: a few kilobytes of gzip can expand to
// gigabytes.
func TestAudit_StatsImportBoundsDecompressedSize(t *testing.T) {
	bomb := `{"version":"` + strings.Repeat("a", maxStatsExportBytes+1024) + `"}`
	if _, err := decodeStatsExport(gzipped(t, bomb)); err == nil {
		t.Fatal("an export larger than the limit was accepted")
	}
}
