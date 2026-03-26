package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/storage"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Version information, injected at build time
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	serverURL   string
	timeout     time.Duration
	username    string
	password    string
	configFile  string
	showVersion bool
)

func defaultMizuConfigPath() string {
	for _, p := range []string{
		"/etc/mizu/config.toml",
		"/usr/local/etc/mizu/config.toml",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "config.toml"
}

func init() {
	flag.StringVar(&serverURL, "server", "http://localhost:8080", "Mizu server URL")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "Request timeout")
	flag.StringVar(&configFile, "config", defaultMizuConfigPath(), "Path to config file for auth credentials")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
}

func main() {
	flag.Usage = usage
	flag.Parse()

	// Check for -version flag
	if showVersion {
		cmdVersion()
		os.Exit(0)
	}

	// Load credentials from config file
	if configFile != "" {
		if cfg, err := config.LoadFromFile(configFile); err == nil {
			username = cfg.Health.Username
			password = cfg.Health.Password
		}
		// Silently ignore config file errors - server might not require auth
	}

	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}

	command := flag.Arg(0)

	switch command {
	case "health":
		cmdHealth()
	case "blocked-ips":
		cmdBlockedIPs()
	case "stats":
		cmdStats()
	case "connections":
		cmdConnections()
	case "certs":
		cmdCerts()
	case "tls":
		cmdTLS()
	case "renew-cert":
		cmdRenewCert()
	case "flush-cache":
		cmdFlushCache()
	case "version", "-version", "--version":
		cmdVersion()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `mizu-admin - Administration tool for Mizu SMTP relay

Usage:
  mizu-admin [flags] <command>

Commands:
  health             Show overall health status and component details
  blocked-ips        Show blocked IP addresses and their reputation
  stats              Show message statistics (accepted/rejected/junk)
  connections        Show connection tracker state used for limiting decisions
  certs              Show TLS certificate status and expiry (from health endpoint)
  tls                Manage TLS certificates (list, delete, clean, sync)
  renew-cert         Force certificate renewal (requires server support)
  flush-cache        Flush recipient and IP block caches
  version            Show version information

Flags:
  -server string     Mizu server URL (default "http://localhost:8080")
  -timeout duration  Request timeout (default 10s)
  -config string     Path to config file for auth credentials (default "config.toml")
  -version           Show version information

Authentication:
  mizu-admin reads HTTP Basic Auth credentials from config.toml [health] section.
  If no credentials are configured, requests are sent without authentication.

Examples:
  mizu-admin version                          # Show version information
  mizu-admin health                           # Uses credentials from config.toml
  mizu-admin -config /etc/mizu/config.toml health
  mizu-admin -server http://smtp.example.com:8080 stats
  mizu-admin certs
  mizu-admin tls list
  mizu-admin tls delete example.com
  mizu-admin tls clean
  mizu-admin tls sync
  mizu-admin flush-cache

`)
}

func cmdVersion() {
	fmt.Printf("mizu-admin %s\n", version)
	fmt.Printf("  commit: %s\n", commit)
	fmt.Printf("  built:  %s\n", date)
}

// Health response structures
type HealthResponse struct {
	Status     string                     `json:"status"`
	Components map[string]ComponentStatus `json:"components"`
}

type ComponentStatus struct {
	Status  string `json:"status"`
	Details any    `json:"details,omitempty"`
}

func cmdHealth() {
	resp, err := httpGetHealth("/health")
	if err != nil {
		fatal("Failed to get health status: %v", err)
	}

	var health HealthResponse
	if err := json.Unmarshal(resp, &health); err != nil {
		fatal("Failed to parse health response: %v", err)
	}

	// Print overall status
	statusIcon := "✓"
	if health.Status != "healthy" {
		statusIcon = "✗"
	}
	fmt.Printf("%s Overall Status: %s\n\n", statusIcon, strings.ToUpper(health.Status))

	// Sort component names for consistent output
	names := make([]string, 0, len(health.Components))
	for name := range health.Components {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		comp := health.Components[name]
		icon := "✓"
		switch comp.Status {
		case "unhealthy":
			icon = "✗"
		case "degraded":
			icon = "⚠"
		}

		fmt.Printf("%s %s: %s\n", icon, name, comp.Status)

		if comp.Details != nil {
			if details, ok := comp.Details.(map[string]any); ok {
				// Sort detail keys for consistent output
				keys := make([]string, 0, len(details))
				for k := range details {
					keys = append(keys, k)
				}
				sort.Strings(keys)

				for _, k := range keys {
					v := details[k]
					fmt.Printf("    %-28s %v\n", k+":", v)
				}
			} else {
				// Fallback for non-map details
				fmt.Printf("    %v\n", comp.Details)
			}
		}
		fmt.Println()
	}
}

// Stats response structures
type StatsResponse struct {
	IPs     map[string]IPStats        `json:"ips"`
	Summary StatsSummary              `json:"summary"`
	Servers map[string]*ServerSummary `json:"servers,omitempty"`
}

type IPStats struct {
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Connections int64     `json:"connections"`
	Positive    int64     `json:"positive"`
	Negative    int64     `json:"negative"`
	IsDenied    bool      `json:"is_denied"`
	Reputation  float64   `json:"reputation"`
	Servers     []string  `json:"servers,omitempty"`
}

type StatsSummary struct {
	TotalIPs          int   `json:"total_ips"`
	BlockedIPs        int   `json:"blocked_ips"`
	ActiveConnections int64 `json:"active_connections"`
	EventsProcessed   int64 `json:"events_processed"`
	EventsDropped     int64 `json:"events_dropped"`
}

type ServerDomainStats struct {
	Messages int64 `json:"messages"`
	Accepted int64 `json:"accepted"`
	Rejected int64 `json:"rejected"`
	Junk     int64 `json:"junk"`
}

type ServerSummary struct {
	Hostname          string                        `json:"hostname"`
	TotalMessages     int64                         `json:"total_messages"`
	AcceptedMessages  int64                         `json:"accepted_messages"`
	RejectedMessages  int64                         `json:"rejected_messages"`
	JunkMessages      int64                         `json:"junk_messages"`
	ActiveConnections int64                         `json:"active_connections"`
	LastUpdated       time.Time                     `json:"last_updated"`
	SenderDomains     map[string]*ServerDomainStats `json:"sender_domains,omitempty"`    // Sender (FROM) domains
	RecipientDomains  map[string]*ServerDomainStats `json:"recipient_domains,omitempty"` // Recipient (TO) domains
}

func cmdBlockedIPs() {
	resp, err := httpGet("/api/stats")
	if err != nil {
		fatal("Failed to get stats: %v", err)
	}

	var stats StatsResponse
	if err := json.Unmarshal(resp, &stats); err != nil {
		fatal("Failed to parse stats response: %v", err)
	}

	// Filter blocked IPs
	blockedIPs := make(map[string]IPStats)
	for ip, ipStats := range stats.IPs {
		if ipStats.IsDenied || ipStats.Reputation < -0.2 {
			blockedIPs[ip] = ipStats
		}
	}

	if len(blockedIPs) == 0 {
		fmt.Println("No blocked IP addresses")
		return
	}

	fmt.Printf("Blocked IP Addresses (%d total)\n\n", len(blockedIPs))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "IP ADDRESS\tREPUTATION\tCONNECTIONS\tPOSITIVE\tNEGATIVE\tLAST SEEN\tSERVER\tREASON")
	fmt.Fprintln(w, "──────────\t──────────\t───────────\t────────\t────────\t─────────\t──────\t──────")

	// Sort by reputation (worst first)
	type ipEntry struct {
		ip    string
		stats IPStats
	}
	entries := make([]ipEntry, 0, len(blockedIPs))
	for ip, stats := range blockedIPs {
		entries = append(entries, ipEntry{ip, stats})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].stats.Reputation < entries[j].stats.Reputation
	})

	for _, entry := range entries {
		reason := "Low reputation"
		if entry.stats.IsDenied {
			reason = "No rDNS"
		}

		serverStr := strings.Join(entry.stats.Servers, ", ")
		if serverStr == "" {
			serverStr = "-"
		}

		fmt.Fprintf(w, "%s\t%.2f\t%d\t%d\t%d\t%s\t%s\t%s\n",
			entry.ip,
			entry.stats.Reputation,
			entry.stats.Connections,
			entry.stats.Positive,
			entry.stats.Negative,
			entry.stats.LastSeen.Format("2006-01-02 15:04"),
			serverStr,
			reason,
		)
	}
	w.Flush()
}

func cmdStats() {
	resp, err := httpGet("/api/stats")
	if err != nil {
		fatal("Failed to get stats: %v", err)
	}

	var stats StatsResponse
	if err := json.Unmarshal(resp, &stats); err != nil {
		fatal("Failed to parse stats response: %v", err)
	}

	// Per-server breakdown with domain tables
	if len(stats.Servers) > 0 {
		// Sort server names for consistent output
		serverNames := make([]string, 0, len(stats.Servers))
		for name := range stats.Servers {
			serverNames = append(serverNames, name)
		}
		sort.Strings(serverNames)

		for _, name := range serverNames {
			srv := stats.Servers[name]
			fmt.Printf("Server: %s\n", name)
			fmt.Println(strings.Repeat("─", len("Server: ")+len(name)))

			fmt.Printf("  Total messages:           %d\n", srv.TotalMessages)

			if srv.TotalMessages > 0 {
				resolved := srv.AcceptedMessages + srv.RejectedMessages + srv.JunkMessages
				incomplete := srv.TotalMessages - resolved
				acceptRate := float64(srv.AcceptedMessages) / float64(srv.TotalMessages) * 100
				rejectRate := float64(srv.RejectedMessages) / float64(srv.TotalMessages) * 100
				junkRate := float64(srv.JunkMessages) / float64(srv.TotalMessages) * 100
				incompleteRate := float64(incomplete) / float64(srv.TotalMessages) * 100

				fmt.Printf("    Accepted:               %d  %6.1f%%\n", srv.AcceptedMessages, acceptRate)
				fmt.Printf("    Rejected:               %d  %6.1f%%\n", srv.RejectedMessages, rejectRate)
				fmt.Printf("    Junk:                   %d  %6.1f%%\n", srv.JunkMessages, junkRate)
				fmt.Printf("    Incomplete:             %d  %6.1f%%\n", incomplete, incompleteRate)
			}

			fmt.Printf("  Active connections:       %d\n", srv.ActiveConnections)

			if !srv.LastUpdated.IsZero() {
				fmt.Printf("  Last updated:             %s\n", srv.LastUpdated.Format("2006-01-02 15:04:05"))
			}

			// Per-server top sender domains (FROM)
			if len(srv.SenderDomains) > 0 {
				fmt.Println()
				fmt.Printf("  Top Sender Domains (FROM)\n")
				fmt.Printf("  ─────────────────────────\n")

				type srvDomainEntry struct {
					domain string
					stats  *ServerDomainStats
				}
				domainEntries := make([]srvDomainEntry, 0, len(srv.SenderDomains))
				for domain, dStats := range srv.SenderDomains {
					domainEntries = append(domainEntries, srvDomainEntry{domain, dStats})
				}
				sort.Slice(domainEntries, func(i, j int) bool {
					return domainEntries[i].stats.Messages > domainEntries[j].stats.Messages
				})

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "  DOMAIN\tMESSAGES\tACCEPTED\tREJECTED\tJUNK")

				for i, entry := range domainEntries {
					if i >= 10 {
						break
					}
					fmt.Fprintf(w, "  %s\t%d\t%d\t%d\t%d\n",
						entry.domain,
						entry.stats.Messages,
						entry.stats.Accepted,
						entry.stats.Rejected,
						entry.stats.Junk,
					)
				}
				w.Flush()
			}

			// Per-server top recipient domains (TO)
			if len(srv.RecipientDomains) > 0 {
				fmt.Println()
				fmt.Printf("  Top Recipient Domains (TO)\n")
				fmt.Printf("  ──────────────────────────\n")

				type srvDomainEntry struct {
					domain string
					stats  *ServerDomainStats
				}
				rcptEntries := make([]srvDomainEntry, 0, len(srv.RecipientDomains))
				for domain, dStats := range srv.RecipientDomains {
					rcptEntries = append(rcptEntries, srvDomainEntry{domain, dStats})
				}
				sort.Slice(rcptEntries, func(i, j int) bool {
					return rcptEntries[i].stats.Messages > rcptEntries[j].stats.Messages
				})

				w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "  DOMAIN\tRECIPIENTS\tACCEPTED\tJUNK")

				for i, entry := range rcptEntries {
					if i >= 10 {
						break
					}
					fmt.Fprintf(w, "  %s\t%d\t%d\t%d\n",
						entry.domain,
						entry.stats.Messages,
						entry.stats.Accepted,
						entry.stats.Junk,
					)
				}
				w.Flush()
			}
			fmt.Println()
		}
	}

	// Infrastructure stats (shared across all servers)
	fmt.Println("Infrastructure")
	fmt.Println("==============")
	fmt.Println()
	fmt.Printf("Total IPs tracked:        %d\n", stats.Summary.TotalIPs)
	fmt.Printf("Blocked IPs:              %d\n", stats.Summary.BlockedIPs)
	fmt.Printf("Events processed:         %d\n", stats.Summary.EventsProcessed)
	fmt.Printf("Events dropped:           %d\n", stats.Summary.EventsDropped)
}

func cmdConnections() {
	resp, err := httpGetHealth("/health")
	if err != nil {
		fatal("Failed to get health status: %v", err)
	}

	var health HealthResponse
	if err := json.Unmarshal(resp, &health); err != nil {
		fatal("Failed to parse health response: %v", err)
	}

	// Find connection tracker components (connection_tracker:* or distributed_connections:*)
	found := false
	for name, comp := range health.Components {
		isDistributed := strings.HasPrefix(name, "distributed_connections")
		isLocal := strings.HasPrefix(name, "connection_tracker")
		if !isDistributed && !isLocal {
			continue
		}
		found = true

		details, ok := comp.Details.(map[string]any)
		if !ok {
			continue
		}

		fmt.Printf("Connection Tracker: %s\n", name)
		fmt.Println(strings.Repeat("=", len("Connection Tracker: ")+len(name)))
		fmt.Println()

		statusIcon := "✓"
		switch comp.Status {
		case "unhealthy":
			statusIcon = "✗"
		case "degraded":
			statusIcon = "⚠"
		}
		fmt.Printf("Status:                   %s %s\n", statusIcon, strings.ToUpper(comp.Status))

		if isDistributed {
			fmt.Printf("Mode:                     distributed\n")
			printDetailInt(details, "local_connections", "Local connections")
			printDetailInt(details, "global_connections", "Global connections (limiter)")
			printDetailInt(details, "unique_ips", "Unique IPs")
			printDetailInt(details, "active_peers", "Active peers")
			printDetailInt(details, "stale_peers", "Stale peers")
			printDetailInt(details, "cluster_members", "Cluster members")
		} else {
			fmt.Printf("Mode:                     local\n")
			printDetailInt(details, "total_connections", "Total connections (limiter)")
			printDetailInt(details, "unique_ips", "Unique IPs")
			printDetailInt(details, "max_total_connections", "Max total connections")
			printDetailInt(details, "max_connections_per_ip", "Max connections per IP")
			printDetailFloat(details, "total_utilization_percent", "Total utilization")
			printDetailFloat(details, "per_ip_utilization_percent", "Busiest IP utilization")
			if ip, ok := details["busiest_ip"].(string); ok && ip != "" {
				conns := int(getFloat(details, "busiest_ip_connections"))
				fmt.Printf("  Busiest IP:               %s (%d connections)\n", ip, conns)
			}
		}

		// Show per-IP breakdown if available
		if perIP, ok := details["per_ip"].(map[string]any); ok && len(perIP) > 0 {
			fmt.Println()
			fmt.Println("Per-IP Connections")
			fmt.Println("──────────────────")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "IP ADDRESS\tCONNECTIONS")

			type ipEntry struct {
				ip    string
				count int
			}
			entries := make([]ipEntry, 0, len(perIP))
			for ip, count := range perIP {
				entries = append(entries, ipEntry{ip, int(getFloat(map[string]any{ip: count}, ip))})
			}
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].count > entries[j].count
			})
			for _, e := range entries {
				fmt.Fprintf(w, "%s\t%d\n", e.ip, e.count)
			}
			w.Flush()
		}
		fmt.Println()
	}

	if !found {
		fmt.Println("No connection tracker data available")
		fmt.Println("(Connection trackers may not be registered as health checkers)")
		fmt.Println()
		fmt.Println("Falling back to stats-based connection count:")

		// Fall back to stats
		statsResp, err := httpGet("/api/stats")
		if err != nil {
			fatal("Failed to get stats: %v", err)
		}
		var stats StatsResponse
		if err := json.Unmarshal(statsResp, &stats); err != nil {
			fatal("Failed to parse stats response: %v", err)
		}
		fmt.Printf("  Active connections (stats): %d\n", stats.Summary.ActiveConnections)
		fmt.Println()
		fmt.Println("Note: This count comes from the local ConnectionTracker but does NOT")
		fmt.Println("include distributed peer counts used for cluster-wide limiting.")
	}
}

func printDetailInt(details map[string]any, key, label string) {
	if val, ok := details[key]; ok {
		fmt.Printf("  %-25s %v\n", label+":", int(getFloat(map[string]any{key: val}, key)))
	}
}

func printDetailFloat(details map[string]any, key, label string) {
	if val := getFloat(details, key); val > 0 {
		fmt.Printf("  %-25s %.1f%%\n", label+":", val)
	}
}

func getFloat(m map[string]any, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

func cmdCerts() {
	resp, err := httpGetHealth("/health")
	if err != nil {
		fatal("Failed to get health status: %v", err)
	}

	var health HealthResponse
	if err := json.Unmarshal(resp, &health); err != nil {
		fatal("Failed to parse health response: %v", err)
	}

	// Look for TLS certificate component
	certComp, ok := health.Components["tls_certificate"]
	if !ok {
		fmt.Println("No TLS certificate information available")
		fmt.Println("(Server may be running in local mode)")
		return
	}

	fmt.Println("TLS Certificate Status")
	fmt.Println("======================")
	fmt.Println()

	statusIcon := "✓"
	switch certComp.Status {
	case "unhealthy":
		statusIcon = "✗"
	case "degraded":
		statusIcon = "⚠"
	}

	fmt.Printf("Status: %s %s\n\n", statusIcon, strings.ToUpper(certComp.Status))

	if certComp.Details != nil {
		details, ok := certComp.Details.(map[string]any)
		if ok {
			if subject, ok := details["subject"].(string); ok {
				fmt.Printf("Subject:          %s\n", subject)
			}
			if issuer, ok := details["issuer"].(string); ok {
				fmt.Printf("Issuer:           %s\n", issuer)
			}
			if validFrom, ok := details["valid_from"].(string); ok {
				fmt.Printf("Valid From:       %s\n", validFrom)
			}
			if validUntil, ok := details["valid_until"].(string); ok {
				fmt.Printf("Valid Until:      %s\n", validUntil)
			}
			if days, ok := details["days_until_expiry"].(float64); ok {
				daysInt := int(days)
				fmt.Printf("Days Until Expiry: %d", daysInt)
				if daysInt < 7 {
					fmt.Printf(" ⚠️  CRITICAL - Renew soon!")
				} else if daysInt < 30 {
					fmt.Printf(" ⚠️  Warning")
				}
				fmt.Println()
			}
			if errorMsg, ok := details["error"].(string); ok {
				fmt.Printf("\nError: %s\n", errorMsg)
			}
		}
	}
}

func cmdRenewCert() {
	fmt.Println("Forcing certificate renewal...")
	fmt.Println("Note: This requires server-side support for /api/renew-cert endpoint")
	fmt.Println()

	resp, err := httpPost("/api/renew-cert", nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fmt.Println("✗ Certificate renewal endpoint not implemented on server")
			fmt.Println("  This feature requires server-side support")
			os.Exit(1)
		}
		fatal("Failed to renew certificate: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp, &result); err != nil {
		fatal("Failed to parse response: %v", err)
	}

	if status, ok := result["status"].(string); ok && status == "success" {
		fmt.Println("✓ Certificate renewal initiated successfully")
		if msg, ok := result["message"].(string); ok {
			fmt.Printf("  %s\n", msg)
		}
	} else {
		fmt.Println("✗ Certificate renewal failed")
		if msg, ok := result["error"].(string); ok {
			fmt.Printf("  Error: %s\n", msg)
		}
	}
}

func cmdFlushCache() {
	fmt.Println("Flushing caches...")
	fmt.Println("Note: This requires server-side support for /api/flush-cache endpoint")
	fmt.Println()

	resp, err := httpPost("/api/flush-cache", nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fmt.Println("✗ Flush cache endpoint not implemented on server")
			fmt.Println("  This feature requires server-side support")
			os.Exit(1)
		}
		fatal("Failed to flush cache: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp, &result); err != nil {
		fatal("Failed to parse response: %v", err)
	}

	if status, ok := result["status"].(string); ok && status == "success" {
		fmt.Println("✓ Caches flushed successfully")
		if flushed, ok := result["flushed"].(map[string]any); ok {
			for key, val := range flushed {
				fmt.Printf("  %s: %v\n", key, val)
			}
		}
	} else {
		fmt.Println("✗ Cache flush failed")
		if msg, ok := result["error"].(string); ok {
			fmt.Printf("  Error: %s\n", msg)
		}
	}
}

func cmdTLS() {
	if flag.NArg() < 2 {
		printTLSUsage()
		os.Exit(1)
	}

	subcommand := flag.Arg(1)
	ctx := context.Background()

	switch subcommand {
	case "list", "ls":
		handleTLSList(ctx)
	case "delete", "del", "rm":
		handleTLSDelete(ctx)
	case "clean":
		handleTLSClean(ctx)
	case "cache", "sync":
		handleTLSCache(ctx)
	case "help", "--help", "-h":
		printTLSUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown tls subcommand: %s\n\n", subcommand)
		printTLSUsage()
		os.Exit(1)
	}
}

func printTLSUsage() {
	fmt.Fprintf(os.Stderr, `TLS Certificate Management

Usage:
  mizu-admin tls <subcommand> [arguments]

Subcommands:
  list, ls           List all certificates in storage
  delete, del, rm    Delete certificate for a domain
  clean              Clean up expired and invalid certificates
  cache, sync        Sync certificates from storage to local cache
  help               Show this help message

Examples:
  mizu-admin tls list
  mizu-admin tls delete example.com
  mizu-admin tls clean
  mizu-admin tls sync

Notes:
  - Commands require a valid config.toml with storage backend configuration
  - Use -config flag to specify a different config file
  - Deleted certificates will be automatically re-requested by the server

`)
}

func handleTLSList(ctx context.Context) {
	// Load config to get storage backend settings
	cfg, err := config.LoadFromFile(configFile)
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	// Initialize storage backend
	backend, err := initStorageBackend(ctx, cfg)
	if err != nil {
		fatal("Failed to initialize storage backend: %v", err)
	}

	fmt.Println("Listing certificates in storage...")
	fmt.Println()

	// List objects with autocert prefix (certs/ + autocert/)
	// The server stores certs at: S3Prefix + "certs/" + "autocert/"
	prefix := cfg.Storage.S3Prefix + "certs/autocert/"
	objects, err := backend.ListObjects(ctx, prefix, true)
	if err != nil {
		fatal("Failed to list certificates: %v", err)
	}

	// Collect all certificate objects
	var certs []CertificateInfo
	for _, obj := range objects {
		// Skip acme account keys and token files
		filename := filepath.Base(obj.Key)
		if strings.HasPrefix(filename, "acme_account") {
			continue
		}

		certInfo := CertificateInfo{
			S3Key:        obj.Key,
			Size:         obj.Size,
			LastModified: obj.LastModified,
		}

		// Domain is the filename (e.g., "example.com", "example.com+rsa")
		certInfo.Domain = filename
		if strings.HasSuffix(filename, "+rsa") {
			certInfo.Domain = strings.TrimSuffix(filename, "+rsa") + " (RSA)"
		}

		// Download and parse certificate for more details
		reader, err := backend.GetObject(ctx, obj.Key)
		if err == nil {
			certData, _ := io.ReadAll(reader)
			reader.Close()
			parseCertificateData(certData, &certInfo)
		}

		certs = append(certs, certInfo)
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found in storage")
		return
	}

	fmt.Printf("Found %d certificate(s)\n\n", len(certs))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tTYPE\tSTATUS\tEXPIRY\tSIZE\tLAST MODIFIED")
	fmt.Fprintln(w, "──────\t────\t──────\t──────\t────\t─────────────")

	for _, cert := range certs {
		status := "Valid"
		expiryStr := "-"
		if !cert.Expiry.IsZero() {
			daysUntilExpiry := int(time.Until(cert.Expiry).Hours() / 24)
			if daysUntilExpiry < 0 {
				expiryStr = "EXPIRED"
				status = "Expired"
			} else if daysUntilExpiry < 7 {
				expiryStr = fmt.Sprintf("%dd ⚠", daysUntilExpiry)
				status = "Expiring"
			} else if daysUntilExpiry < 30 {
				expiryStr = fmt.Sprintf("%dd", daysUntilExpiry)
				status = "Expiring"
			} else {
				expiryStr = fmt.Sprintf("%dd", daysUntilExpiry)
			}
		}

		if cert.CertType == "Invalid" || cert.CertType == "Parse Error" {
			status = "Invalid"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d bytes\t%s\n",
			cert.Domain,
			cert.CertType,
			status,
			expiryStr,
			cert.Size,
			cert.LastModified.Format("2006-01-02 15:04"),
		)
	}
	w.Flush()
}

func handleTLSDelete(ctx context.Context) {
	if flag.NArg() < 3 {
		fmt.Fprintln(os.Stderr, "Error: delete requires a domain argument")
		fmt.Fprintln(os.Stderr, "Usage: mizu-admin tls delete <domain>")
		fmt.Fprintln(os.Stderr, "Example: mizu-admin tls delete example.com")
		os.Exit(1)
	}

	domain := flag.Arg(2)

	// Load config to get storage backend settings
	cfg, err := config.LoadFromFile(configFile)
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	// Initialize storage backend
	backend, err := initStorageBackend(ctx, cfg)
	if err != nil {
		fatal("Failed to initialize storage backend: %v", err)
	}

	fmt.Printf("Deleting certificate for domain: %s\n", domain)
	fmt.Println("Warning: This will remove the certificate from storage.")
	fmt.Println("The server will automatically request a new certificate on next use.")
	fmt.Println()

	// Compute S3 keys for both ECDSA and RSA variants
	// Certificates are stored with plain domain names: prefix + domain, prefix + domain+rsa
	prefix := cfg.Storage.S3Prefix + "certs/autocert/"
	ecdsaKey := prefix + domain
	rsaKey := prefix + domain + "+rsa"

	deleted := 0
	notFound := 0
	var errors []string

	// Delete both variants
	for _, key := range []string{ecdsaKey, rsaKey} {
		keyType := "ECDSA"
		if strings.Contains(key, "+rsa") {
			keyType = "RSA"
		}

		err := backend.RemoveObject(ctx, key)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Printf("  %s certificate not found (may not exist)\n", keyType)
				notFound++
			} else {
				errMsg := fmt.Sprintf("%s certificate: %v", keyType, err)
				errors = append(errors, errMsg)
				fmt.Printf("✗ Failed to delete %s\n", errMsg)
			}
		} else {
			fmt.Printf("✓ Deleted %s certificate\n", keyType)
			deleted++
		}
	}

	fmt.Println()

	if deleted > 0 {
		fmt.Printf("Successfully deleted %d certificate(s) for '%s'\n", deleted, domain)
	}
	if notFound == 2 {
		fmt.Printf("No certificates found for '%s' (may have been already deleted)\n", domain)
	}
	if len(errors) > 0 {
		fmt.Println("Errors occurred during deletion:")
		for _, e := range errors {
			fmt.Printf("  - %s\n", e)
		}
		os.Exit(1)
	}
	if deleted == 0 && notFound == 0 {
		fmt.Println("✗ No certificates deleted")
		os.Exit(1)
	}
}

func handleTLSClean(ctx context.Context) {
	// Load config to get storage backend settings
	cfg, err := config.LoadFromFile(configFile)
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	// Initialize storage backend
	backend, err := initStorageBackend(ctx, cfg)
	if err != nil {
		fatal("Failed to initialize storage backend: %v", err)
	}

	fmt.Println("Cleaning up expired and invalid certificates...")
	fmt.Println()

	// List objects with autocert prefix
	prefix := cfg.Storage.S3Prefix + "certs/autocert/"
	objects, err := backend.ListObjects(ctx, prefix, true)
	if err != nil {
		fatal("Failed to list certificates: %v", err)
	}

	// Find certificates to clean
	var toDelete []struct {
		key    string
		domain string
		reason string
	}

	for _, obj := range objects {
		// Skip acme account keys and token files
		filename := filepath.Base(obj.Key)
		if strings.HasPrefix(filename, "acme_account") {
			continue
		}

		// Download and parse certificate
		reader, err := backend.GetObject(ctx, obj.Key)
		if err != nil {
			fmt.Printf("Warning: Failed to read %s: %v\n", obj.Key, err)
			continue
		}

		certData, _ := io.ReadAll(reader)
		reader.Close()

		// Domain is the filename (e.g., "example.com", "example.com+rsa")
		domain := filename
		if strings.HasSuffix(filename, "+rsa") {
			domain = strings.TrimSuffix(filename, "+rsa") + " (RSA)"
		}

		certInfo := CertificateInfo{
			S3Key:  obj.Key,
			Domain: domain,
		}
		parseCertificateData(certData, &certInfo)

		// Check if expired
		if !certInfo.Expiry.IsZero() && time.Now().After(certInfo.Expiry) {
			toDelete = append(toDelete, struct {
				key    string
				domain string
				reason string
			}{obj.Key, certInfo.Domain, "expired"})
		}

		// Check if invalid
		if certInfo.CertType == "Invalid" || certInfo.CertType == "Parse Error" {
			toDelete = append(toDelete, struct {
				key    string
				domain string
				reason string
			}{obj.Key, certInfo.Domain, "invalid"})
		}
	}

	if len(toDelete) == 0 {
		fmt.Println("No expired or invalid certificates found")
		return
	}

	fmt.Printf("Found %d certificate(s) to clean:\n\n", len(toDelete))
	for _, item := range toDelete {
		fmt.Printf("  - %s (%s)\n", item.domain, item.reason)
	}
	fmt.Println()

	deleted := 0
	failed := 0

	for _, item := range toDelete {
		err := backend.RemoveObject(ctx, item.key)
		if err != nil {
			fmt.Printf("✗ Failed to delete %s: %v\n", item.domain, err)
			failed++
		} else {
			fmt.Printf("✓ Deleted %s (%s)\n", item.domain, item.reason)
			deleted++
		}
	}

	fmt.Println()
	fmt.Printf("Cleaned up %d certificate(s)", deleted)
	if failed > 0 {
		fmt.Printf(" (%d failed)", failed)
	}
	fmt.Println()
}

func handleTLSCache(ctx context.Context) {
	// Load config to get storage backend settings
	cfg, err := config.LoadFromFile(configFile)
	if err != nil {
		fatal("Failed to load config: %v", err)
	}

	// Check if fallback cache is configured
	if cfg.TLS.LetsEncrypt.FallbackCacheDir == "" {
		fmt.Println("Fallback cache directory not configured in config.toml")
		fmt.Println("Set tls.letsencrypt.fallback_cache_dir to enable local certificate caching")
		os.Exit(1)
	}

	// Initialize storage backend
	backend, err := initStorageBackend(ctx, cfg)
	if err != nil {
		fatal("Failed to initialize storage backend: %v", err)
	}

	fmt.Printf("Syncing certificates from storage to local cache: %s\n", cfg.TLS.LetsEncrypt.FallbackCacheDir)
	fmt.Println()

	// Ensure cache directory exists
	if err := os.MkdirAll(cfg.TLS.LetsEncrypt.FallbackCacheDir, 0700); err != nil {
		fatal("Failed to create cache directory: %v", err)
	}

	// List objects with autocert prefix
	prefix := cfg.Storage.S3Prefix + "certs/autocert/"
	objects, err := backend.ListObjects(ctx, prefix, true)
	if err != nil {
		fatal("Failed to list certificates: %v", err)
	}

	synced := 0
	skipped := 0
	failed := 0

	for _, obj := range objects {
		// Extract filename from key
		parts := strings.Split(obj.Key, "/")
		filename := parts[len(parts)-1]
		localPath := filepath.Join(cfg.TLS.LetsEncrypt.FallbackCacheDir, filename)

		// Check if local file exists and is newer
		if stat, err := os.Stat(localPath); err == nil {
			if stat.ModTime().After(obj.LastModified) || stat.ModTime().Equal(obj.LastModified) {
				skipped++
				continue
			}
		}

		// Download from storage
		reader, err := backend.GetObject(ctx, obj.Key)
		if err != nil {
			fmt.Printf("✗ Failed to download %s: %v\n", filename, err)
			failed++
			continue
		}

		// Write to local cache
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			fmt.Printf("✗ Failed to read %s: %v\n", filename, err)
			failed++
			continue
		}

		if err := os.WriteFile(localPath, data, 0600); err != nil {
			fmt.Printf("✗ Failed to write %s: %v\n", filename, err)
			failed++
			continue
		}

		// Set modification time to match storage
		os.Chtimes(localPath, obj.LastModified, obj.LastModified)

		fmt.Printf("✓ Synced %s\n", filename)
		synced++
	}

	fmt.Println()
	fmt.Printf("Sync complete: %d synced, %d skipped, %d failed\n", synced, skipped, failed)
}

// HTTP helper functions

// httpGet performs a GET request and requires HTTP 200.
func httpGet(path string) ([]byte, error) {
	return httpGetAccepting(path, http.StatusOK)
}

// httpGetHealth performs a GET request to the health endpoint,
// accepting both HTTP 200 (healthy) and HTTP 503 (unhealthy) as valid responses.
func httpGetHealth(path string) ([]byte, error) {
	return httpGetAccepting(path, http.StatusOK, http.StatusServiceUnavailable)
}

// httpGetAccepting performs a GET request and accepts the specified status codes.
func httpGetAccepting(path string, acceptedStatuses ...int) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	url := serverURL + path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add Basic Auth if configured
	if username != "" {
		req.SetBasicAuth(username, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	for _, accepted := range acceptedStatuses {
		if resp.StatusCode == accepted {
			return body, nil
		}
	}

	return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
}

func httpPost(path string, data io.Reader) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	url := serverURL + path

	req, err := http.NewRequest("POST", url, data)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	// Add Basic Auth if configured
	if username != "" {
		req.SetBasicAuth(username, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}

// Certificate management helper functions and types

type CertificateInfo struct {
	S3Key        string
	Domain       string
	CertType     string // "ECDSA", "RSA", or "Unknown"
	Size         int64
	LastModified time.Time
	Expiry       time.Time
	NotBefore    time.Time
	Subject      string
	Issuer       string
}

func initStorageBackend(ctx context.Context, cfg *config.Config) (storage.Backend, error) {
	switch cfg.Storage.Backend {
	case "s3":
		// Initialize S3 backend using AWS SDK v2
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(cfg.Storage.S3Region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.Storage.S3AccessKey,
				cfg.Storage.S3SecretKey,
				"",
			)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}

		s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
			// Custom endpoint resolver for non-AWS S3 services
			if cfg.Storage.S3Endpoint != "" {
				o.BaseEndpoint = aws.String(cfg.Storage.S3Endpoint)
				o.UsePathStyle = true
			}
		})

		return storage.NewS3Backend(s3Client, cfg.Storage.S3Bucket, nil), nil

	case "filesystem":
		backend, err := storage.NewFilesystemBackend(cfg.Storage.FilesystemPath, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to init filesystem backend: %w", err)
		}
		return backend, nil

	default:
		return nil, fmt.Errorf("unsupported storage backend: %s", cfg.Storage.Backend)
	}
}

func parseCertificateData(data []byte, info *CertificateInfo) {
	// autocert stores: private key PEM + certificate PEM
	// Skip the private key and parse the certificate
	var certPEM []byte
	remaining := data

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			certPEM = pem.EncodeToMemory(block)
			break
		}

		remaining = rest
	}

	if certPEM == nil {
		info.CertType = "Invalid"
		return
	}

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		info.CertType = "Invalid"
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		info.CertType = "Parse Error"
		return
	}

	// Extract information
	info.Expiry = cert.NotAfter
	info.NotBefore = cert.NotBefore
	info.Subject = cert.Subject.String()
	info.Issuer = cert.Issuer.String()

	// Extract domain from certificate if not already set
	if strings.Contains(info.Domain, "...") || info.Domain == "unknown" {
		if len(cert.DNSNames) > 0 {
			info.Domain = cert.DNSNames[0]
			if cert.PublicKeyAlgorithm == x509.RSA {
				info.Domain += " (RSA)"
			}
		} else if cert.Subject.CommonName != "" {
			info.Domain = cert.Subject.CommonName
			if cert.PublicKeyAlgorithm == x509.RSA {
				info.Domain += " (RSA)"
			}
		}
	}

	// Determine cert type from public key algorithm
	switch cert.PublicKeyAlgorithm {
	case x509.ECDSA:
		info.CertType = "ECDSA"
	case x509.RSA:
		info.CertType = "RSA"
	default:
		info.CertType = cert.PublicKeyAlgorithm.String()
	}
}
