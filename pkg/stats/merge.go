package stats

// mergeStats merges remote stats into local stats using max-wins semantics.
// Each peer exports its own observed counters to S3. When merging, we take the
// maximum of local vs remote for each counter. This prevents counter inflation
// that would occur with additive merging across repeated sync cycles.
func (m *Manager) mergeStats(remote *StatsExport) int {
	merged := 0

	// Merge IP stats
	for ip, remoteEntry := range remote.IPs {
		merged += m.mergeIPEntry(ip, remoteEntry)
	}

	// Merge domain stats
	for domain, remoteEntry := range remote.Domains {
		merged += m.mergeDomainEntry(domain, remoteEntry)
	}

	return merged
}

// maxInt64 returns the larger of two int64 values
func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// mergeIPEntry merges a remote IP entry into local stats using max-wins semantics.
// For counters (Connections, Positive, Negative), we take the maximum of local vs
// remote to get the best available estimate without inflation.
func (m *Manager) mergeIPEntry(ip string, remote *IPExport) int {
	m.ipMu.Lock()
	defer m.ipMu.Unlock()

	local, exists := m.ips[ip]
	if !exists {
		// New entry - create it
		local = &IPEntry{}
		local.FromExport(remote)
		m.ips[ip] = local
		return 1
	}

	// Existing entry - merge using max-wins
	local.mu.Lock()
	defer local.mu.Unlock()

	// Take earliest first seen
	if remote.FirstSeen.Before(local.FirstSeen) {
		local.FirstSeen = remote.FirstSeen
	}

	// Take latest last seen
	if remote.LastSeen.After(local.LastSeen) {
		local.LastSeen = remote.LastSeen
	}

	// Max-wins for counters: prevents inflation from repeated sync cycles.
	// Each node exports its own observed totals; taking max gives the best
	// cluster-wide estimate without unbounded growth.
	local.Connections = maxInt64(local.Connections, remote.Connections)
	local.Positive = maxInt64(local.Positive, remote.Positive)
	local.Negative = maxInt64(local.Negative, remote.Negative)

	// IsDenied is a hard flag (e.g., for no rDNS). If any server has denied it,
	// the denial should propagate.
	if remote.IsDenied {
		local.IsDenied = true
	}

	// Union server sets
	if len(remote.Servers) > 0 {
		if local.Servers == nil {
			local.Servers = make(map[string]struct{})
		}
		for _, s := range remote.Servers {
			local.Servers[s] = struct{}{}
		}
	}

	return 1
}

// mergeDomainEntry merges a remote domain entry into local stats using max-wins semantics.
// For counters (Messages, Positive, Negative, Junk, Rejected), we take the maximum of
// local vs remote to get the best available estimate without inflation.
func (m *Manager) mergeDomainEntry(domain string, remote *DomainExport) int {
	m.domainMu.Lock()
	defer m.domainMu.Unlock()

	local, exists := m.domains[domain]
	if !exists {
		// New entry - create it
		local = &DomainEntry{}
		local.FromExport(remote)
		m.domains[domain] = local
		return 1
	}

	// Existing entry - merge using max-wins
	local.mu.Lock()
	defer local.mu.Unlock()

	// Take earliest first seen
	if remote.FirstSeen.Before(local.FirstSeen) {
		local.FirstSeen = remote.FirstSeen
	}

	// Take latest last seen
	if remote.LastSeen.After(local.LastSeen) {
		local.LastSeen = remote.LastSeen
	}

	// Max-wins for counters: prevents inflation from repeated sync cycles.
	local.Messages = maxInt64(local.Messages, remote.Messages)
	local.Positive = maxInt64(local.Positive, remote.Positive)
	local.Negative = maxInt64(local.Negative, remote.Negative)
	local.Junk = maxInt64(local.Junk, remote.Junk)
	local.Rejected = maxInt64(local.Rejected, remote.Rejected)

	return 1
}
