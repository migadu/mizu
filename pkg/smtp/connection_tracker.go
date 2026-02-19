package smtp

import (
	"fmt"
	"migadu/mizu/pkg/health"
	"net"
	"sync"
)

// ConnectionTracker tracks active connections globally and per-IP to enforce limits.
// It provides thread-safe operations for tracking and releasing connections.
type ConnectionTracker struct {
	mu                  sync.RWMutex
	name                string         // Health checker name (empty = default "connection_tracker")
	maxConnections      int            // Maximum total concurrent connections (0 = unlimited)
	maxConnectionsPerIP int            // Maximum concurrent connections per IP (0 = unlimited)
	totalConnections    int            // Current total number of connections
	ipConnections       map[string]int // Map of IP -> connection count
}

// NewConnectionTracker creates a new connection tracker with the specified limits.
// Set maxConnections to 0 for unlimited total connections.
// Set maxConnectionsPerIP to 0 for unlimited connections per IP.
func NewConnectionTracker(maxConnections, maxConnectionsPerIP int) *ConnectionTracker {
	return &ConnectionTracker{
		maxConnections:      maxConnections,
		maxConnectionsPerIP: maxConnectionsPerIP,
		totalConnections:    0,
		ipConnections:       make(map[string]int),
	}
}

// TryAcquire attempts to acquire a connection slot for the given remote address.
// Returns nil on success, or an error if limits are exceeded.
func (ct *ConnectionTracker) TryAcquire(remoteAddr string) error {
	// Extract IP from address (format: "IP:port" or "[IPv6]:port")
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// If no port, assume it's just an IP
		host = remoteAddr
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Check global connection limit
	if ct.maxConnections > 0 && ct.totalConnections >= ct.maxConnections {
		return fmt.Errorf("maximum total connections reached (%d)", ct.maxConnections)
	}

	// Check per-IP connection limit
	if ct.maxConnectionsPerIP > 0 {
		currentIPConns := ct.ipConnections[host]
		if currentIPConns >= ct.maxConnectionsPerIP {
			return fmt.Errorf("maximum connections per IP reached (%d)", ct.maxConnectionsPerIP)
		}
	}

	// Acquire connection slot
	ct.totalConnections++
	ct.ipConnections[host]++

	return nil
}

// Release releases a connection slot for the given remote address.
// This should be called when a connection is closed, typically in a defer statement.
func (ct *ConnectionTracker) Release(remoteAddr string) {
	// Extract IP from address
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Release connection slot
	if ct.totalConnections > 0 {
		ct.totalConnections--
	}

	if count, exists := ct.ipConnections[host]; exists && count > 0 {
		ct.ipConnections[host]--
		// Clean up map entry if count reaches zero to prevent memory leak
		if ct.ipConnections[host] == 0 {
			delete(ct.ipConnections, host)
		}
	}
}

// GetStats returns current connection statistics.
// Returns total connections, number of unique IPs, and per-IP breakdown.
func (ct *ConnectionTracker) GetStats() (total int, uniqueIPs int, perIP map[string]int) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	// Create a copy of the IP connections map to avoid exposing internal state
	perIPCopy := make(map[string]int, len(ct.ipConnections))
	for ip, count := range ct.ipConnections {
		if count > 0 {
			perIPCopy[ip] = count
		}
	}

	return ct.totalConnections, len(perIPCopy), perIPCopy
}

// GetLimits returns the configured connection limits.
func (ct *ConnectionTracker) GetLimits() (maxTotal, maxPerIP int) {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.maxConnections, ct.maxConnectionsPerIP
}

// SetName sets a custom health checker name (e.g. "connection_tracker:mx-primary").
func (ct *ConnectionTracker) SetName(name string) {
	ct.name = name
}

// Name returns the component name for health checks.
func (ct *ConnectionTracker) Name() string {
	if ct.name != "" {
		return ct.name
	}
	return "connection_tracker"
}

// CheckHealth returns the health status of the connection tracker.
func (ct *ConnectionTracker) CheckHealth() health.ComponentStatus {
	total, uniqueIPs, perIP := ct.GetStats()
	maxTotal, maxPerIP := ct.GetLimits()

	// Calculate utilization percentages
	var totalUtilization float64
	if maxTotal > 0 {
		totalUtilization = float64(total) / float64(maxTotal) * 100
	}

	// Find the IP with the highest connection count
	var maxIPConns int
	var maxIPAddr string
	for ip, count := range perIP {
		if count > maxIPConns {
			maxIPConns = count
			maxIPAddr = ip
		}
	}

	var perIPUtilization float64
	if maxPerIP > 0 && maxIPConns > 0 {
		perIPUtilization = float64(maxIPConns) / float64(maxPerIP) * 100
	}

	status := "healthy"
	if maxTotal > 0 && totalUtilization >= 90 {
		status = "degraded"
	}
	if maxTotal > 0 && totalUtilization >= 100 {
		status = "unhealthy"
	}

	details := map[string]interface{}{
		"total_connections":          total,
		"unique_ips":                 uniqueIPs,
		"max_total_connections":      maxTotal,
		"max_connections_per_ip":     maxPerIP,
		"total_utilization_pct":      fmt.Sprintf("%.1f", totalUtilization),
		"highest_ip_connections":     maxIPConns,
		"highest_ip_address":         maxIPAddr,
		"highest_ip_utilization_pct": fmt.Sprintf("%.1f", perIPUtilization),
	}

	return health.ComponentStatus{
		Status:  status,
		Details: details,
	}
}
