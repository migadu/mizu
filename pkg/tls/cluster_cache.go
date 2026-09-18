package tls

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

// ClusterAwareCache wraps an autocert.Cache and keeps deletions to the cluster
// leader. All nodes can read, and all nodes can store.
//
// It is not the leader gate — acmeTransport is. autocert writes to the cache
// only once it holds a certificate, so refusing the write cannot prevent an
// order; it can only throw away the result. With ordering gated upstream, a node
// that holds a certificate was entitled to order it, and refusing to store it
// after a leadership change mid-order discards something the CA has already
// issued and counted. Deletion stays gated: it destroys shared state that no
// other node can recover.
type ClusterAwareCache struct {
	underlying autocert.Cache
	isLeaderF  func() bool
	logger     *slog.Logger
}

// NewClusterAwareCache creates a new cluster-aware certificate cache.
// isLeaderF should return true if this node is the current cluster leader.
func NewClusterAwareCache(cache autocert.Cache, isLeaderF func() bool, logger *slog.Logger) *ClusterAwareCache {
	return &ClusterAwareCache{
		underlying: cache,
		isLeaderF:  isLeaderF,
		logger:     logger,
	}
}

func (c *ClusterAwareCache) Get(ctx context.Context, name string) ([]byte, error) {
	isLeader := c.isLeaderF()
	c.logger.Debug("cluster cache: Get certificate request", "name", name, "is_leader", isLeader)

	data, err := c.underlying.Get(ctx, name)
	if err != nil {
		if err == autocert.ErrCacheMiss {
			c.logger.Debug("cluster cache: certificate not found (cache miss)", "name", name, "is_leader", isLeader)
		} else {
			c.logger.Error("cluster cache: error getting certificate",
				"name", name,
				"is_leader", isLeader,
				"error", err,
				"error_type", fmt.Sprintf("%T", err))
		}
		return nil, err
	}

	c.logger.Debug("cluster cache: certificate retrieved successfully", "name", name, "is_leader", isLeader, "bytes", len(data))
	return data, nil
}

func (c *ClusterAwareCache) Put(ctx context.Context, name string, data []byte) error {
	if isLeader := c.isLeaderF(); !isLeader {
		// Only a certificate may be stored by a non-leader. Ordering is gated at
		// the transport, so a certificate in hand was obtained while this node
		// was still leader, and refusing it would throw away an issuance the CA
		// has already charged for.
		//
		// The account key and challenge responses are not like that. autocert
		// generates the account key and writes it *before* it registers, so this
		// is the only thing standing between a node coming up against an empty
		// bucket and its own key landing on top of the leader's - leaving the
		// cluster with two ACME accounts once the leader restarts.
		if !isCertificateKey(name) {
			c.logger.Warn("cluster cache: refusing to store shared ACME state - not cluster leader", "name", name)
			return fmt.Errorf("%w: refused to store %s", ErrNotLeader, name)
		}
		c.logger.Warn("cluster cache: storing a certificate obtained before this node stopped being leader", "name", name)
	}

	c.logger.Info("cluster cache: storing certificate", "name", name)
	if err := c.underlying.Put(ctx, name, data); err != nil {
		c.logger.Error("cluster cache: failed to store certificate", "name", name, "error", err)
		return err
	}

	c.logger.Info("cluster cache: certificate stored", "name", name)
	return nil
}

// isCertificateKey reports whether a cache key holds an issued certificate,
// as opposed to the ACME account key or a challenge response.
func isCertificateKey(key string) bool {
	return !isChallengeKey(key) && !strings.HasPrefix(key, "acme_account")
}

func (c *ClusterAwareCache) Delete(ctx context.Context, name string) error {
	isLeader := c.isLeaderF()

	c.logger.Debug("cluster cache: Delete certificate request", "name", name, "is_leader", isLeader)

	if !isLeader {
		c.logger.Debug("cluster cache: skipping certificate delete (not cluster leader)", "name", name)
		return fmt.Errorf("%w: refused to delete %s", ErrNotLeader, name)
	}

	c.logger.Info("cluster cache: cluster leader deleting certificate", "name", name)
	if err := c.underlying.Delete(ctx, name); err != nil {
		c.logger.Error("cluster cache: failed to delete certificate", "name", name, "error", err)
		return err
	}

	c.logger.Info("cluster cache: certificate deleted by leader", "name", name)
	return nil
}
