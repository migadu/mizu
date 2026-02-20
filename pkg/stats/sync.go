package stats

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// SyncFromS3 downloads and merges stats from other servers
func (m *Manager) SyncFromS3(ctx context.Context, s3Client *s3.Client, bucket, prefix string) error {
	if !m.enabled || !m.syncEnabled || len(m.syncServers) == 0 {
		return nil
	}

	var totalMerged int
	for _, serverHostname := range m.syncServers {
		merged, err := m.syncFromServer(ctx, s3Client, bucket, prefix, serverHostname)
		if err != nil {
			m.logger.Error("Failed to sync from server",
				"server", serverHostname,
				"error", err)
			// Continue with other servers even if one fails
			continue
		}
		totalMerged += merged
	}

	if totalMerged > 0 {
		m.logger.Debug("Completed stats sync",
			"servers", len(m.syncServers),
			"total_entries_merged", totalMerged)
	}

	return nil
}

// syncFromServer syncs stats from a single server
func (m *Manager) syncFromServer(ctx context.Context, s3Client *s3.Client, bucket, prefix, serverHostname string) (int, error) {
	objectName := path.Join(prefix, "stats", fmt.Sprintf("%s.json.gz", serverHostname))

	// Check if we've already synced this version
	m.lastSyncMu.RLock()
	lastSync, exists := m.lastSync[serverHostname]
	lastAttempt, attemptExists := m.lastSyncAttempt[serverHostname]
	m.lastSyncMu.RUnlock()

	// Mark that we are attempting to sync now
	m.lastSyncMu.Lock()
	m.lastSyncAttempt[serverHostname] = time.Now()
	m.lastSyncMu.Unlock()

	// Check last modified time
	objInfo, err := s3Client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectName),
	})
	if err != nil {
		// Check if the error is because the object doesn't exist
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			// If we have synced before and it's been a while, the peer might be gone.
			if attemptExists && time.Since(lastAttempt) > stalePeerTimeout {
				m.logger.Warn("Peer stats file not found for stale peer, skipping for now", "peer", serverHostname, "object", objectName)
				return 0, nil // Not an error, just a stale peer
			}
		}
		return 0, fmt.Errorf("failed to stat object: %w", err)
	}

	if exists && !objInfo.LastModified.After(lastSync) {
		// No changes since last sync
		return 0, nil
	}

	// Download the stats file
	result, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectName),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get object: %w", err)
	}
	defer result.Body.Close()

	// Read and decompress
	gzReader, err := gzip.NewReader(result.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, gzReader); err != nil {
		return 0, fmt.Errorf("failed to decompress: %w", err)
	}

	// Parse JSON
	var remoteStats StatsExport
	if err := json.Unmarshal(buf.Bytes(), &remoteStats); err != nil {
		return 0, fmt.Errorf("failed to unmarshal stats: %w", err)
	}

	// Merge the stats
	merged := m.mergeStats(&remoteStats)

	// Capture peer's per-server summary if available
	if remoteStats.Summary != nil {
		m.peerSummariesMu.Lock()
		m.peerSummaries[serverHostname] = &ServerSummary{
			Hostname:         serverHostname,
			TotalMessages:    remoteStats.Summary.TotalMessages,
			AcceptedMessages: remoteStats.Summary.AcceptedMessages,
			RejectedMessages: remoteStats.Summary.RejectedMessages,
			JunkMessages:     remoteStats.Summary.JunkMessages,
			LastUpdated:      remoteStats.Timestamp,
		}
		m.peerSummariesMu.Unlock()
	}

	// Update last sync time
	m.lastSyncMu.Lock()
	m.lastSync[serverHostname] = *objInfo.LastModified
	m.lastSyncMu.Unlock()

	m.logger.Debug("Synced stats from server",
		"server", serverHostname,
		"last_modified", *objInfo.LastModified,
		"ips", len(remoteStats.IPs),
		"domains", len(remoteStats.Domains),
		"merged", merged)

	return merged, nil
}

// StartSyncLoop starts the periodic sync from other servers
func (m *Manager) StartSyncLoop(ctx context.Context, s3Client *s3.Client, bucket, prefix string, interval time.Duration) {
	if !m.enabled || !m.syncEnabled || len(m.syncServers) == 0 {
		m.logger.Info("Stats sync disabled or no servers to sync from")
		return
	}

	m.logger.Info("Starting stats sync loop",
		"interval", interval,
		"servers", len(m.syncServers))

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Sync immediately on start
	if err := m.SyncFromS3(ctx, s3Client, bucket, prefix); err != nil {
		m.logger.Error("Failed to sync stats", "error", err)
	}

	for {
		select {
		case <-ticker.C:
			if err := m.SyncFromS3(ctx, s3Client, bucket, prefix); err != nil {
				m.logger.Error("Failed to sync stats", "error", err)
				// Continue running even if sync fails
			}
		case <-ctx.Done():
			m.logger.Info("Stats sync loop stopped")
			return
		}
	}
}
