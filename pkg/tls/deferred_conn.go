package tls

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// DeferredTLSConn wraps a TCP connection and performs TLS handshake on demand.
// This prevents head-of-line blocking in the Accept() loop by deferring the
// expensive TLS handshake until the first Read/Write operation.
type DeferredTLSConn struct {
	tcpConn          net.Conn
	tlsConfig        *tls.Config
	logger           *slog.Logger
	handshakeOnce    sync.Once
	handshakeMutex   sync.Mutex // Protects tlsConn for SetDeadline/Close before handshake
	tlsConn          *tls.Conn
	handshakeErr     error
	handshakeTimeout time.Duration
}

// NewDeferredTLSConn creates a new deferred TLS connection wrapper.
// The TLS handshake will be performed on the first Read/Write operation.
func NewDeferredTLSConn(tcpConn net.Conn, tlsConfig *tls.Config, handshakeTimeout time.Duration, logger *slog.Logger) *DeferredTLSConn {
	return &DeferredTLSConn{
		tcpConn:          tcpConn,
		tlsConfig:        tlsConfig,
		logger:           logger,
		handshakeTimeout: handshakeTimeout,
	}
}

// HandshakeComplete returns whether the TLS handshake has been performed.
// This is safe to call concurrently from any goroutine.
func (c *DeferredTLSConn) HandshakeComplete() bool {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	return c.tlsConn != nil || c.handshakeErr != nil
}

// PerformHandshake performs the TLS handshake with timeout.
// This method is idempotent - it will only perform the handshake once via sync.Once.
func (c *DeferredTLSConn) PerformHandshake() error {
	c.handshakeOnce.Do(func() {
		c.doHandshake()
	})
	return c.handshakeErr
}

// doHandshake performs the actual TLS handshake. Called exactly once via sync.Once.
func (c *DeferredTLSConn) doHandshake() {
	remoteAddr := c.tcpConn.RemoteAddr().String()
	if c.logger != nil {
		c.logger.Debug("Starting deferred TLS handshake", "remote_addr", remoteAddr)
	}

	// Clone TLS config to avoid race conditions
	tlsConfig := c.tlsConfig.Clone()

	// Create TLS connection over TCP connection
	tlsConn := tls.Server(c.tcpConn, tlsConfig)

	// Set handshake timeout
	if c.handshakeTimeout > 0 {
		deadline := time.Now().Add(c.handshakeTimeout)
		if err := tlsConn.SetDeadline(deadline); err != nil {
			c.handshakeErr = fmt.Errorf("failed to set handshake deadline: %w", err)
			if c.logger != nil {
				c.logger.Error("Failed to set TLS handshake deadline", "error", c.handshakeErr)
			}
			return
		}
	}

	// Perform the handshake
	startTime := time.Now()
	if err := tlsConn.Handshake(); err != nil {
		c.handshakeErr = fmt.Errorf("TLS handshake failed: %w", err)
		if c.logger != nil {
			c.logger.Warn("TLS handshake failed", "remote_addr", remoteAddr, "error", err, "duration", time.Since(startTime))
		}
		return
	}

	// Clear deadline after successful handshake
	if c.handshakeTimeout > 0 {
		tlsConn.SetDeadline(time.Time{})
	}

	duration := time.Since(startTime)
	if c.logger != nil {
		c.logger.Debug("TLS handshake completed successfully",
			"remote_addr", remoteAddr,
			"duration", duration,
			"tls_version", tlsVersionString(tlsConn.ConnectionState().Version),
			"cipher_suite", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
	}

	// Store tlsConn only on success — readers of c.tlsConn can use it as
	// an implicit "handshake succeeded" signal.
	c.handshakeMutex.Lock()
	c.tlsConn = tlsConn
	c.handshakeMutex.Unlock()
}

// Read implements net.Conn.Read
// Performs handshake on first read if not already done
func (c *DeferredTLSConn) Read(b []byte) (n int, err error) {
	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}
	return c.tlsConn.Read(b)
}

// Write implements net.Conn.Write
// Performs handshake on first write if not already done
func (c *DeferredTLSConn) Write(b []byte) (n int, err error) {
	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}
	return c.tlsConn.Write(b)
}

// Close implements net.Conn.Close
func (c *DeferredTLSConn) Close() error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.tlsConn != nil {
		return c.tlsConn.Close()
	}
	return c.tcpConn.Close()
}

// LocalAddr implements net.Conn.LocalAddr
func (c *DeferredTLSConn) LocalAddr() net.Addr {
	return c.tcpConn.LocalAddr()
}

// RemoteAddr implements net.Conn.RemoteAddr
func (c *DeferredTLSConn) RemoteAddr() net.Addr {
	return c.tcpConn.RemoteAddr()
}

// SetDeadline implements net.Conn.SetDeadline
func (c *DeferredTLSConn) SetDeadline(t time.Time) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.tlsConn != nil {
		return c.tlsConn.SetDeadline(t)
	}
	return c.tcpConn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.SetReadDeadline
func (c *DeferredTLSConn) SetReadDeadline(t time.Time) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.tlsConn != nil {
		return c.tlsConn.SetReadDeadline(t)
	}
	return c.tcpConn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline
func (c *DeferredTLSConn) SetWriteDeadline(t time.Time) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.tlsConn != nil {
		return c.tlsConn.SetWriteDeadline(t)
	}
	return c.tcpConn.SetWriteDeadline(t)
}

// ConnectionState returns the TLS connection state.
// Returns zero value if handshake hasn't been performed yet.
func (c *DeferredTLSConn) ConnectionState() tls.ConnectionState {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.tlsConn != nil {
		return c.tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}

// ensureHandshake ensures the TLS handshake has been performed.
// sync.Once provides both the fast path (already done) and slow path (first call).
func (c *DeferredTLSConn) ensureHandshake() error {
	return c.PerformHandshake()
}

// tlsVersionString returns a human-readable TLS version string
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", version)
	}
}
