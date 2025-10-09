package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"migadu/mizu/pkg/config"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
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

func init() {
	flag.StringVar(&serverURL, "server", "http://localhost:8080", "Mizu server URL")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "Request timeout")
	flag.StringVar(&configFile, "config", "config.toml", "Path to config file for auth credentials")
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
		if cfg, err := config.LoadConfigFromFile(configFile); err == nil {
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
	case "certs":
		cmdCerts()
	case "renew-cert":
		cmdRenewCert()
	case "flush-cache":
		cmdFlushCache()
	case "dlq":
		cmdDLQ()
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
  certs              Show TLS certificate status and expiry
  renew-cert         Force certificate renewal (requires server support)
  flush-cache        Flush recipient and IP block caches
  dlq <subcommand>   Manage dead letter queue (list, inspect, reprocess, delete)
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
	resp, err := httpGet("/health")
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

	// Print component details
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "COMPONENT\tSTATUS\tDETAILS")
	fmt.Fprintln(w, "─────────\t──────\t───────")

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

		details := ""
		if comp.Details != nil {
			detailsJSON, _ := json.MarshalIndent(comp.Details, "", "  ")
			details = string(detailsJSON)
			// Compact single-line details
			if !strings.Contains(details, "\n") {
				details = strings.TrimSpace(details)
			}
		}

		fmt.Fprintf(w, "%s %s\t%s\t%s\n", icon, name, comp.Status, details)
	}
	w.Flush()
}

// Stats response structures
type StatsResponse struct {
	IPs     map[string]IPStats     `json:"ips"`
	Domains map[string]DomainStats `json:"domains"`
	Summary StatsSummary           `json:"summary"`
}

type IPStats struct {
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Connections int64     `json:"connections"`
	Positive    int64     `json:"positive"`
	Negative    int64     `json:"negative"`
	IsDenied    bool      `json:"is_denied"`
	Reputation  float64   `json:"reputation"`
}

type DomainStats struct {
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Messages   int64     `json:"messages"`
	Positive   int64     `json:"positive"`
	Negative   int64     `json:"negative"`
	Reputation float64   `json:"reputation"`
}

type StatsSummary struct {
	TotalIPs         int   `json:"total_ips"`
	TotalDomains     int   `json:"total_domains"`
	BlockedIPs       int   `json:"blocked_ips"`
	TotalConnections int64 `json:"total_connections"`
	TotalMessages    int64 `json:"total_messages"`
	AcceptedMessages int64 `json:"accepted_messages"`
	RejectedMessages int64 `json:"rejected_messages"`
	JunkMessages     int64 `json:"junk_messages"`
	EventsProcessed  int64 `json:"events_processed"`
	EventsDropped    int64 `json:"events_dropped"`
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
	fmt.Fprintln(w, "IP ADDRESS\tREPUTATION\tCONNECTIONS\tPOSITIVE\tNEGATIVE\tLAST SEEN\tREASON")
	fmt.Fprintln(w, "──────────\t──────────\t───────────\t────────\t────────\t─────────\t──────")

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

		fmt.Fprintf(w, "%s\t%.2f\t%d\t%d\t%d\t%s\t%s\n",
			entry.ip,
			entry.stats.Reputation,
			entry.stats.Connections,
			entry.stats.Positive,
			entry.stats.Negative,
			entry.stats.LastSeen.Format("2006-01-02 15:04"),
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

	fmt.Println("Message Statistics")
	fmt.Println("==================")
	fmt.Println()

	// Summary
	fmt.Printf("Total IPs tracked:        %d\n", stats.Summary.TotalIPs)
	fmt.Printf("Total domains tracked:    %d\n", stats.Summary.TotalDomains)
	fmt.Printf("Blocked IPs:              %d\n", stats.Summary.BlockedIPs)
	fmt.Printf("Total connections:        %d\n", stats.Summary.TotalConnections)
	fmt.Println()

	fmt.Printf("Total messages:           %d\n", stats.Summary.TotalMessages)
	fmt.Printf("  Accepted (ham):         %d\n", stats.Summary.AcceptedMessages)
	fmt.Printf("  Rejected/Junk:          %d\n", stats.Summary.RejectedMessages)
	fmt.Printf("  Marked as junk:         %d\n", stats.Summary.JunkMessages)
	fmt.Println()

	if stats.Summary.TotalMessages > 0 {
		acceptRate := float64(stats.Summary.AcceptedMessages) / float64(stats.Summary.TotalMessages) * 100
		rejectRate := float64(stats.Summary.RejectedMessages) / float64(stats.Summary.TotalMessages) * 100
		fmt.Printf("Accept rate:              %.1f%%\n", acceptRate)
		fmt.Printf("Reject rate:              %.1f%%\n", rejectRate)
		fmt.Println()
	}

	fmt.Printf("Events processed:         %d\n", stats.Summary.EventsProcessed)
	fmt.Printf("Events dropped:           %d\n", stats.Summary.EventsDropped)
	fmt.Println()

	// Top domains
	fmt.Println("Top 10 Domains by Message Volume")
	fmt.Println("─────────────────────────────────")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tMESSAGES\tACCEPTED\tREJECTED\tREPUTATION")

	type domainEntry struct {
		domain string
		stats  DomainStats
	}
	domainEntries := make([]domainEntry, 0, len(stats.Domains))
	for domain, dStats := range stats.Domains {
		domainEntries = append(domainEntries, domainEntry{domain, dStats})
	}
	sort.Slice(domainEntries, func(i, j int) bool {
		return domainEntries[i].stats.Messages > domainEntries[j].stats.Messages
	})

	for i, entry := range domainEntries {
		if i >= 10 {
			break
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%.2f\n",
			entry.domain,
			entry.stats.Messages,
			entry.stats.Positive,
			entry.stats.Negative,
			entry.stats.Reputation,
		)
	}
	w.Flush()
}

func cmdCerts() {
	resp, err := httpGet("/health")
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

// HTTP helper functions

func httpGet(path string) ([]byte, error) {
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
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

func cmdDLQ() {
	if flag.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "DLQ subcommand required")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  mizu-admin dlq list [--limit N]     List DLQ entries (default limit: 100)")
		fmt.Fprintln(os.Stderr, "  mizu-admin dlq inspect <job-id>     Show details of a specific DLQ entry")
		fmt.Fprintln(os.Stderr, "  mizu-admin dlq reprocess <job-id>   Move job back to active queue for retry")
		fmt.Fprintln(os.Stderr, "  mizu-admin dlq delete <job-id>      Permanently delete a DLQ entry")
		os.Exit(1)
	}

	subcommand := flag.Arg(1)

	switch subcommand {
	case "list":
		cmdDLQList()
	case "inspect":
		if flag.NArg() < 3 {
			fatal("Job ID required for 'inspect' command")
		}
		cmdDLQInspect(flag.Arg(2))
	case "reprocess":
		if flag.NArg() < 3 {
			fatal("Job ID required for 'reprocess' command")
		}
		cmdDLQReprocess(flag.Arg(2))
	case "delete":
		if flag.NArg() < 3 {
			fatal("Job ID required for 'delete' command")
		}
		cmdDLQDelete(flag.Arg(2))
	default:
		fmt.Fprintf(os.Stderr, "Unknown DLQ subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func cmdDLQList() {
	resp, err := httpGet("/api/dlq")
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not configured") {
			fmt.Println("✗ DLQ not available")
			fmt.Println("  Server does not have persistent queue enabled")
			os.Exit(1)
		}
		fatal("Failed to get DLQ entries: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp, &result); err != nil {
		fatal("Failed to parse response: %v", err)
	}

	entries, ok := result["entries"].([]any)
	if !ok {
		fatal("Invalid response format")
	}

	if len(entries) == 0 {
		fmt.Println("Dead Letter Queue is empty")
		return
	}

	fmt.Printf("Dead Letter Queue (%d entries)\n\n", len(entries))

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "JOB ID\tFROM\tRECIPIENTS\tATTEMPTS\tREASON\tMOVED AT\tEXPIRES")
	fmt.Fprintln(w, "──────\t────\t──────────\t────────\t──────\t────────\t───────")

	for _, entry := range entries {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		jobMap, ok := entryMap["job"].(map[string]any)
		if !ok {
			continue
		}

		jobID := getString(jobMap, "id")
		from := getString(jobMap, "from")
		reason := getString(entryMap, "reason")
		attempts := getInt(jobMap, "attempts")

		recipients := getStringSlice(jobMap, "recipients")
		recipientsStr := strings.Join(recipients, ", ")
		if len(recipientsStr) > 30 {
			recipientsStr = recipientsStr[:27] + "..."
		}

		movedAt := getTime(entryMap, "moved_at")
		expiresAt := getTime(entryMap, "expires_at")

		if len(reason) > 40 {
			reason = reason[:37] + "..."
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			jobID[:8]+"...", // Shorten job ID for display
			from,
			recipientsStr,
			attempts,
			reason,
			movedAt,
			expiresAt,
		)
	}
	w.Flush()
}

func cmdDLQInspect(jobID string) {
	resp, err := httpGet("/api/dlq/" + jobID)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fatal("DLQ entry not found: %s", jobID)
		}
		fatal("Failed to get DLQ entry: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp, &result); err != nil {
		fatal("Failed to parse response: %v", err)
	}

	entryMap, ok := result["entry"].(map[string]any)
	if !ok {
		fatal("Invalid response format")
	}

	jobMap, ok := entryMap["job"].(map[string]any)
	if !ok {
		fatal("Invalid entry format")
	}

	fmt.Println("DLQ Entry Details")
	fmt.Println("=================")
	fmt.Println()

	fmt.Printf("Job ID:           %s\n", getString(jobMap, "id"))
	fmt.Printf("From:             %s\n", getString(jobMap, "from"))
	fmt.Printf("Original To:      %s\n", getString(jobMap, "original_to"))

	recipients := getStringSlice(jobMap, "recipients")
	fmt.Printf("Recipients:       %s\n", strings.Join(recipients, ", "))

	fmt.Printf("Endpoint:         %s\n", getString(jobMap, "endpoint"))
	fmt.Printf("Is Forwarding:    %t\n", getBool(jobMap, "is_forwarding"))
	fmt.Printf("Is Custom Endpoint: %t\n", getBool(jobMap, "is_custom_endpoint"))
	fmt.Printf("Is Junk:          %t\n", getBool(jobMap, "is_junk"))
	fmt.Println()

	fmt.Printf("Attempts:         %d\n", getInt(jobMap, "attempts"))
	fmt.Printf("Max Attempts:     %d\n", getInt(jobMap, "max_attempts"))
	fmt.Printf("Created At:       %s\n", getTime(jobMap, "created_at"))
	fmt.Printf("Last Attempt:     %s\n", getTime(jobMap, "last_attempt"))
	fmt.Println()

	fmt.Printf("Moved to DLQ:     %s\n", getTime(entryMap, "moved_at"))
	fmt.Printf("Expires At:       %s\n", getTime(entryMap, "expires_at"))
	fmt.Printf("Reason:           %s\n", getString(entryMap, "reason"))
	fmt.Println()

	// Show email content if not too large
	emailContent := getString(jobMap, "email_content")
	if emailContent != "" && len(emailContent) < 2000 {
		fmt.Println("Email Content Preview:")
		fmt.Println("----------------------")
		fmt.Println(emailContent)
	} else if getString(jobMap, "email_storage_key") != "" {
		fmt.Printf("Email stored separately (key: %s)\n", getString(jobMap, "email_storage_key"))
	}
}

func cmdDLQReprocess(jobID string) {
	fmt.Printf("Reprocessing job %s...\n", jobID)

	resp, err := httpPost("/api/dlq/"+jobID, nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fatal("DLQ entry not found: %s", jobID)
		}
		fatal("Failed to reprocess job: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp, &result); err != nil {
		fatal("Failed to parse response: %v", err)
	}

	if status, ok := result["status"].(string); ok && status == "success" {
		fmt.Println("✓ Job moved back to active queue for reprocessing")
		if msg, ok := result["message"].(string); ok {
			fmt.Printf("  %s\n", msg)
		}
	} else {
		fmt.Println("✗ Reprocessing failed")
		if msg, ok := result["error"].(string); ok {
			fmt.Printf("  Error: %s\n", msg)
		}
	}
}

func cmdDLQDelete(jobID string) {
	fmt.Printf("Deleting DLQ entry %s...\n", jobID)
	fmt.Println("Warning: This permanently deletes the job and cannot be undone.")
	fmt.Print("Continue? (y/N): ")

	var response string
	fmt.Scanln(&response)
	if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
		fmt.Println("Cancelled")
		return
	}

	req, err := http.NewRequest("DELETE", serverURL+"/api/dlq/"+jobID, nil)
	if err != nil {
		fatal("Failed to create request: %v", err)
	}

	if username != "" {
		req.SetBasicAuth(username, password)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		fatal("Failed to delete entry: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if strings.Contains(string(body), "not found") {
			fatal("DLQ entry not found: %s", jobID)
		}
		fatal("Failed to delete entry: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		fatal("Failed to parse response: %v", err)
	}

	if status, ok := result["status"].(string); ok && status == "success" {
		fmt.Println("✓ DLQ entry deleted successfully")
	} else {
		fmt.Println("✗ Deletion failed")
		if msg, ok := result["error"].(string); ok {
			fmt.Printf("  Error: %s\n", msg)
		}
	}
}

// Helper functions for extracting values from JSON maps
func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]any, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}

func getBool(m map[string]any, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func getStringSlice(m map[string]any, key string) []string {
	if v, ok := m[key].([]any); ok {
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return []string{}
}

func getTime(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.Format("2006-01-02 15:04:05")
		}
		return v
	}
	return ""
}
