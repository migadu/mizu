package smtp

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// AcceptLimiter is a net.Listener wrapper that bounds the number of open
// sockets, in total and per peer IP, at the moment a connection is accepted.
//
// It exists because every other limit in this package is applied in
// Backend.NewSession, which go-smtp calls when the client sends EHLO/HELO. A
// client that connects and never greets - or keeps the connection alive with
// NOOP, which go-smtp answers without a session - is invisible to
// ConnectionTracker, DistributedTracker and RateLimiter, and could hold sockets
// up to the process's file-descriptor limit. This counts the socket itself.
//
// A slot is tied to the returned net.Conn and released exactly once, when that
// connection is closed, so the count cannot drift from the number of sockets
// actually open. There is deliberately no reaper.
//
// It must wrap the raw TCP listener, underneath any PROXY-protocol or TLS
// listener: it keys on the TCP peer address. With PROXY protocol that peer is
// the load balancer, so pass the trusted proxy networks as perIPExempt - they
// are still counted against the total.
type AcceptLimiter struct {
	net.Listener

	maxTotal    int // 0 = unlimited
	maxPerIP    int // 0 = unlimited
	perIPExempt []*net.IPNet
	logger      *slog.Logger

	mu    sync.Mutex
	total int
	perIP map[string]int

	refused        atomic.Uint64
	lastRefusalLog atomic.Int64 // unix seconds of the last refusal log line
}

// NewAcceptLimiter wraps l. maxTotal and maxPerIP of 0 disable the respective
// limit. Peers inside perIPExempt are not subject to maxPerIP.
func NewAcceptLimiter(l net.Listener, maxTotal, maxPerIP int, perIPExempt []*net.IPNet, logger *slog.Logger) *AcceptLimiter {
	return &AcceptLimiter{
		Listener:    l,
		maxTotal:    maxTotal,
		maxPerIP:    maxPerIP,
		perIPExempt: perIPExempt,
		logger:      logger,
		perIP:       make(map[string]int),
	}
}

// Accept returns the next connection that fits within the limits. Connections
// over a limit are closed immediately and never reach the SMTP server: nothing
// is written to them, because on an implicit-TLS port a plaintext reply would
// be garbage, and a sending MTA treats a dropped connection as a temporary
// failure either way.
func (l *AcceptLimiter) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		ip := peerIP(c.RemoteAddr())
		countPerIP := l.maxPerIP > 0 && !l.exempt(ip)

		// The per-IP count keys IPv6 on the /64 (acceptKey); the exemption
		// above and the log line use the real address.
		key := acceptKey(ip)
		reason := l.acquire(key, countPerIP)
		if reason != "" {
			refused := l.refused.Add(1)
			// At most one line a second: this path runs once per refused
			// socket, which under the flood it exists for is as fast as the
			// peer can connect.
			if l.logger != nil {
				now := time.Now().Unix()
				if last := l.lastRefusalLog.Load(); now != last && l.lastRefusalLog.CompareAndSwap(last, now) {
					l.logger.Info("Refusing connection at accept - connection limit reached",
						"remote_addr", ip, "reason", reason, "refused_total", refused)
				}
			}
			_ = c.Close()
			continue
		}

		return &limitedConn{Conn: c, limiter: l, ip: key, countedPerIP: countPerIP}, nil
	}
}

// acquire takes a slot, returning "" on success or the limit that refused it.
func (l *AcceptLimiter) acquire(ip string, countPerIP bool) string {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.maxTotal > 0 && l.total >= l.maxTotal {
		return "max_connections"
	}
	if countPerIP && l.perIP[ip] >= l.maxPerIP {
		return "max_connections_per_ip"
	}
	l.total++
	if countPerIP {
		l.perIP[ip]++
	}
	return ""
}

func (l *AcceptLimiter) release(ip string, countedPerIP bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.total--
	if countedPerIP {
		if l.perIP[ip] <= 1 {
			delete(l.perIP, ip)
		} else {
			l.perIP[ip]--
		}
	}
}

func (l *AcceptLimiter) exempt(ip string) bool {
	if len(l.perIPExempt) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range l.perIPExempt {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Counts returns the number of open sockets and the number of distinct peer
// IPs currently counted against the per-IP limit.
func (l *AcceptLimiter) Counts() (total int, uniqueIPs int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total, len(l.perIP)
}

// Refused returns how many connections have been closed at accept.
func (l *AcceptLimiter) Refused() uint64 {
	return l.refused.Load()
}

// acceptKey is the per-IP counting key for a peer address: the address itself
// for IPv4, its /64 for IPv6. One IPv6 allocation is 2^64 addresses; keyed on
// the full address each would get its own budget and only the total cap would
// bound a single host.
func acceptKey(ip string) string { return bucketIP(ip) }

// peerIP extracts the bare IP from a peer address.
func peerIP(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// limitedConn releases its AcceptLimiter slot when closed - once, however many
// times Close is called (go-smtp and the TLS / PROXY wrappers above may each
// close the connection).
type limitedConn struct {
	net.Conn
	limiter      *AcceptLimiter
	ip           string
	countedPerIP bool
	once         sync.Once
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.limiter.release(c.ip, c.countedPerIP) })
	return err
}
