package tls

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/acme/autocert"
)

// ClusterAwareCache wraps an autocert.Cache and only allows the cluster leader
// to write new certificates. All nodes can read certificates from the cache.
type ClusterAwareCache struct {
	underlying autocert.Cache
	isLeaderF  func() bool
	logger     *slog.Logger
}

// NewClusterAwareCache creates a new cluster-aware certificate cache
func NewClusterAwareCache(cache autocert.Cache, isLeaderF func() bool, logger *slog.Logger) *ClusterAwareCache {
	return &ClusterAwareCache{
		underlying: cache,
		isLeaderF:  isLeaderF,
		logger:     logger,
	}
}

// Get retrieves a certificate from the cache (all nodes can read)
func (c *ClusterAwareCache) Get(ctx context.Context, name string) ([]byte, error) {
	isLeader := c.isLeaderF()
	c.logger.Info("ClusterCache: Get certificate request", "name", name, "is_leader", isLeader)

	data, err := c.underlying.Get(ctx, name)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			c.logger.Info("ClusterCache: Certificate not found (cache miss)", "name", name, "is_leader", isLeader)
		} else {
			c.logger.Error("ClusterCache: Error getting certificate",
				"name", name,
				"is_leader", isLeader,
				"error", err,
				"error_type", fmt.Sprintf("%T", err))
		}
		return nil, err
	}

	c.logger.Info("ClusterCache: Certificate retrieved successfully", "name", name, "is_leader", isLeader, "bytes", len(data))
	return data, nil
}

// Put stores a certificate in the cache (only leader can write)
func (c *ClusterAwareCache) Put(ctx context.Context, name string, data []byte) error {
	isLeader := c.isLeaderF()

	c.logger.Info("ClusterCache: Put certificate request", "name", name, "is_leader", isLeader)

	// Check if this node is the cluster leader
	if !isLeader {
		// Non-leader nodes should not write certificates
		// This prevents race conditions with Let's Encrypt
		c.logger.Warn("ClusterCache: Certificate request BLOCKED - not cluster leader (leader will handle it)", "name", name)
		return fmt.Errorf("only cluster leader can request new certificates")
	}

	c.logger.Info("ClusterCache: Cluster leader storing certificate", "name", name)
	err := c.underlying.Put(ctx, name, data)
	if err != nil {
		c.logger.Error("ClusterCache: Failed to store certificate", "name", name, "error", err)
		return err
	}

	c.logger.Info("ClusterCache: Certificate stored by leader", "name", name)
	return nil
}

// Delete removes a certificate from the cache (only leader can delete)
func (c *ClusterAwareCache) Delete(ctx context.Context, name string) error {
	isLeader := c.isLeaderF()

	c.logger.Debug("ClusterCache: Delete certificate request", "name", name, "is_leader", isLeader)

	// Check if this node is the cluster leader
	if !isLeader {
		c.logger.Debug("ClusterCache: Skipping certificate delete (not cluster leader)", "name", name)
		return fmt.Errorf("only cluster leader can delete certificates")
	}

	c.logger.Info("ClusterCache: Cluster leader deleting certificate", "name", name)
	err := c.underlying.Delete(ctx, name)
	if err != nil {
		c.logger.Error("ClusterCache: Failed to delete certificate", "name", name, "error", err)
		return err
	}

	c.logger.Info("ClusterCache: Certificate deleted by leader", "name", name)
	return nil
}
