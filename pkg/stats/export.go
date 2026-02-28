package stats

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ExportToS3 exports the current stats to S3 as a compressed JSON file.
// Uses hash-based change detection to avoid writing unchanged data,
// which prevents accumulating S3 object versions when stats haven't changed.
func (m *Manager) ExportToS3(ctx context.Context, s3Client *s3.Client, bucket, prefix, hostname string) error {
	if !m.enabled || !m.syncEnabled {
		return nil
	}

	// Create export data
	export := m.createExport(hostname)

	// Marshal to JSON
	jsonData, err := json.Marshal(export)
	if err != nil {
		return fmt.Errorf("failed to marshal stats: %w", err)
	}

	// Hash the JSON data (pre-compression) to detect changes.
	// We hash the uncompressed JSON because gzip output can vary
	// even for identical input (timestamps in gzip header).
	h := sha256.Sum256(jsonData)
	currentHash := hex.EncodeToString(h[:])

	// Skip upload if data hasn't changed since last export
	if currentHash == m.lastExportHash {
		m.logger.Debug("Skipping S3 stats export - data unchanged")
		return nil
	}

	// Compress the JSON
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(jsonData); err != nil {
		return fmt.Errorf("failed to compress stats: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Upload to S3 (prefix already includes the "stats/" subdirectory)
	objectName := path.Join(prefix, fmt.Sprintf("%s.json.gz", hostname))
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(objectName),
		Body:            bytes.NewReader(buf.Bytes()),
		ContentType:     aws.String("application/gzip"),
		ContentEncoding: aws.String("gzip"),
	})
	if err != nil {
		return fmt.Errorf("failed to upload stats to S3: %w", err)
	}

	// Update last export hash on successful upload
	m.lastExportHash = currentHash

	m.logger.Debug("Exported stats to S3",
		"hostname", hostname,
		"object", objectName,
		"size", buf.Len(),
		"ips", len(export.IPs))

	return nil
}

// createExport creates an export snapshot of current stats
func (m *Manager) createExport(hostname string) *StatsExport {
	// If hostname is empty, try to auto-detect
	if hostname == "" {
		hostname, _ = os.Hostname()
		if hostname == "" {
			hostname = "unknown"
		}
	}

	export := &StatsExport{
		Version:   "1.0",
		Hostname:  hostname,
		Timestamp: time.Now(),
		IPs:       make(map[string]*IPExport),
	}

	// Export IPs
	m.ipMu.RLock()
	for ip, entry := range m.ips {
		export.IPs[ip] = entry.ToExport()
	}
	m.ipMu.RUnlock()

	// Include aggregated local server message counts in export
	m.srvCountersMu.RLock()
	var acceptedMsg, rejectedMsg, junkMsg int64
	for _, c := range m.srvCounters {
		acceptedMsg += int64(c.accepted)
		rejectedMsg += int64(c.rejected)
		junkMsg += int64(c.junk)
	}
	// Total is computed from outcomes to handle multi-recipient messages correctly
	totalMsg := acceptedMsg + rejectedMsg + junkMsg
	export.Summary = &ExportSummary{
		TotalMessages:    totalMsg,
		AcceptedMessages: acceptedMsg,
		RejectedMessages: rejectedMsg,
		JunkMessages:     junkMsg,
	}
	m.srvCountersMu.RUnlock()

	return export
}

// StartExportLoop starts the periodic export to S3
func (m *Manager) StartExportLoop(ctx context.Context, s3Client *s3.Client, bucket, prefix, hostname string, interval time.Duration) {
	if !m.enabled || !m.syncEnabled {
		m.logger.Info("Stats export disabled")
		return
	}

	m.logger.Info("Starting stats export loop",
		"hostname", hostname,
		"interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Export immediately on start
	if err := m.ExportToS3(ctx, s3Client, bucket, prefix, hostname); err != nil {
		m.logger.Error("Failed to export stats", "error", err)
	}

	for {
		select {
		case <-ticker.C:
			if err := m.ExportToS3(ctx, s3Client, bucket, prefix, hostname); err != nil {
				m.logger.Error("Failed to export stats", "error", err)
				// Continue running even if export fails
			}
		case <-ctx.Done():
			m.logger.Info("Stats export loop stopped")
			return
		}
	}
}
