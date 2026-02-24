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
	tcpConn           net.Conn
	tlsConfig         *tls.Config
	logger            *slog.Logger
	handshakeComplete bool
	handshakeMutex    sync.Mutex
	tlsConn           *tls.Conn
	handshakeErr      error
	handshakeTimeout  time.Duration
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

// PerformHandshake performs the TLS handshake with timeout.
// This method is idempotent - it will only perform the handshake once.
func (c *DeferredTLSConn) PerformHandshake() error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	// Idempotent - only perform once
	if c.handshakeComplete {
		return c.handshakeErr
	}
	c.handshakeComplete = true

	remoteAddr := c.tcpConn.RemoteAddr().String()
	if c.logger != nil {
		c.logger.Debug("Starting deferred TLS handshake", "remote_addr", remoteAddr)
	}

	// Clone TLS config to avoid race conditions
	tlsConfig := c.tlsConfig.Clone()

	// Create TLS connection over TCP connection
	c.tlsConn = tls.Server(c.tcpConn, tlsConfig)

	// Set handshake timeout
	if c.handshakeTimeout > 0 {
		deadline := time.Now().Add(c.handshakeTimeout)
		if err := c.tlsConn.SetDeadline(deadline); err != nil {
			c.handshakeErr = fmt.Errorf("failed to set handshake deadline: %w", err)
			if c.logger != nil {
				c.logger.Error("Failed to set TLS handshake deadline", "error", c.handshakeErr)
			}
			return c.handshakeErr
		}
	}

	// Perform the handshake
	startTime := time.Now()
	if err := c.tlsConn.Handshake(); err != nil {
		c.handshakeErr = fmt.Errorf("TLS handshake failed: %w", err)
		if c.logger != nil {
			c.logger.Warn("TLS handshake failed", "remote_addr", remoteAddr, "error", err, "duration", time.Since(startTime))
		}
		return c.handshakeErr
	}

	// Clear deadline after successful handshake
	if c.handshakeTimeout > 0 {
		c.tlsConn.SetDeadline(time.Time{})
	}

	duration := time.Since(startTime)
	if c.logger != nil {
		c.logger.Debug("TLS handshake completed successfully",
			"remote_addr", remoteAddr,
			"duration", duration,
			"tls_version", tlsVersionString(c.tlsConn.ConnectionState().Version),
			"cipher_suite", tls.CipherSuiteName(c.tlsConn.ConnectionState().CipherSuite))
	}

	return nil
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

// ensureHandshake ensures the TLS handshake has been performed
func (c *DeferredTLSConn) ensureHandshake() error {
	// Fast path: handshake already done
	if c.handshakeComplete {
		return c.handshakeErr
	}

	// Slow path: need to perform handshake
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
