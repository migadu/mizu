package stats

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ExportToS3 exports the current stats to S3 as a compressed JSON file
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

	// Compress the JSON
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(jsonData); err != nil {
		return fmt.Errorf("failed to compress stats: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Upload to S3
	objectName := path.Join(prefix, "stats", fmt.Sprintf("%s.json.gz", hostname))
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

	m.logger.Debug("Exported stats to S3",
		"hostname", hostname,
		"object", objectName,
		"size", buf.Len(),
		"ips", len(export.IPs),
		"domains", len(export.Domains))

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
		Domains:   make(map[string]*DomainExport),
	}

	// Export IPs
	m.ipMu.RLock()
	for ip, entry := range m.ips {
		export.IPs[ip] = entry.ToExport()
	}
	m.ipMu.RUnlock()

	// Export domains
	m.domainMu.RLock()
	for domain, entry := range m.domains {
		export.Domains[domain] = entry.ToExport()
	}
	m.domainMu.RUnlock()

	// Include local server message counts in export
	m.localCountersMu.RLock()
	export.Summary = &ExportSummary{
		TotalMessages:    int64(m.localTotalMessages),
		AcceptedMessages: int64(m.localAcceptedMessages),
		RejectedMessages: int64(m.localRejectedMessages),
		JunkMessages:     int64(m.localJunkMessages),
	}
	m.localCountersMu.RUnlock()

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
