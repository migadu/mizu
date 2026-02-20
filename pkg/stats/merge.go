package stats

// mergeStats merges remote stats into local stats
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

// mergeIPEntry merges a remote IP entry into local stats
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

	// Existing entry - merge it
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

	// Sum the counters to get a true aggregate across the fleet.
	local.Connections += remote.Connections
	local.Positive += remote.Positive
	local.Negative += remote.Negative

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

// mergeDomainEntry merges a remote domain entry into local stats
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

	// Existing entry - merge it
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

	// Sum the counters for a true aggregate.
	local.Messages += remote.Messages
	local.Positive += remote.Positive
	local.Negative += remote.Negative
	local.Junk += remote.Junk
	local.Rejected += remote.Rejected

	return 1
}
