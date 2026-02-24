package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing
func generateTestCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Mizu Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// TestDeferredTLSConn tests basic deferred TLS connection functionality
func TestDeferredTLSConn(t *testing.T) {
	// Create test certificate
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	// Create a pipe to simulate a network connection
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Wrap server side with deferred TLS
	deferredConn := NewDeferredTLSConn(serverConn, tlsConfig, 5*time.Second, logger)
	defer deferredConn.Close()

	// Start client TLS handshake in background
	var clientErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
		clientErr = clientTLS.Handshake()
		if clientErr != nil {
			return
		}

		// Write test data
		_, writeErr := clientTLS.Write([]byte("Hello, Server!"))
		if writeErr != nil {
			clientErr = writeErr
		}
	}()

	// Server side: handshake should NOT be performed yet
	if deferredConn.HandshakeComplete() {
		t.Error("Handshake should not be complete before first Read/Write")
	}

	// Read from deferred connection (this triggers handshake)
	buf := make([]byte, 1024)
	n, err := deferredConn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from deferred TLS conn: %v", err)
	}

	// Verify handshake was performed
	if !deferredConn.HandshakeComplete() {
		t.Error("Handshake should be complete after Read")
	}

	// Verify data
	if string(buf[:n]) != "Hello, Server!" {
		t.Errorf("Unexpected data: %s", buf[:n])
	}

	wg.Wait()
	if clientErr != nil {
		t.Fatalf("Client error: %v", clientErr)
	}
}

// TestDeferredTLSListener tests the deferred TLS listener
func TestDeferredTLSListener(t *testing.T) {
	// Create test certificate
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	// Create TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Wrap with deferred TLS listener
	deferredListener := NewDeferredTLSListener(listener, tlsConfig, 5*time.Second, logger)

	// Accept connections in background
	var acceptErr error
	var serverConn net.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn, acceptErr = deferredListener.Accept()
		if acceptErr != nil {
			return
		}
		defer serverConn.Close()

		// Read data (this triggers TLS handshake)
		buf := make([]byte, 1024)
		n, readErr := serverConn.Read(buf)
		if readErr != nil {
			acceptErr = readErr
			return
		}

		// Echo back
		_, writeErr := serverConn.Write(buf[:n])
		if writeErr != nil {
			acceptErr = writeErr
		}
	}()

	// Give server time to start accepting
	time.Sleep(100 * time.Millisecond)

	// Connect as client
	clientConn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("Failed to connect as client: %v", err)
	}
	defer clientConn.Close()

	// Send test data
	testMsg := "Hello from client!"
	_, err = clientConn.Write([]byte(testMsg))
	if err != nil {
		t.Fatalf("Failed to write to client conn: %v", err)
	}

	// Read echo
	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read from client conn: %v", err)
	}

	if string(buf[:n]) != testMsg {
		t.Errorf("Expected %q, got %q", testMsg, buf[:n])
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("Server error: %v", acceptErr)
	}
}

// BenchmarkDeferredTLSHandshake benchmarks the deferred TLS handshake
func BenchmarkDeferredTLSHandshake(b *testing.B) {
	cert, err := generateTestCert()
	if err != nil {
		b.Fatalf("Failed to generate test cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serverConn, clientConn := net.Pipe()

		deferredConn := NewDeferredTLSConn(serverConn, tlsConfig, 5*time.Second, logger)

		// Client handshake in background
		go func() {
			clientTLS := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
			clientTLS.Handshake()
			clientTLS.Write([]byte("test"))
			clientConn.Close()
		}()

		// Trigger handshake
		buf := make([]byte, 4)
		deferredConn.Read(buf)
		deferredConn.Close()
		serverConn.Close()
	}
}
