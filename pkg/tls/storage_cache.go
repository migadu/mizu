package tls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"migadu/mizu/pkg/storage"

	"golang.org/x/crypto/acme/autocert"
)

// StorageCache implements autocert.Cache using the storage.Backend interface.
// This allows certificates to be shared across multiple instances using either S3 or filesystem storage.
type StorageCache struct {
	backend storage.Backend
	prefix  string // Key prefix for certificate storage (default: "autocert/")
	logger  *slog.Logger
}

// NewStorageCache creates a new storage-backed autocert cache.
func NewStorageCache(backend storage.Backend, prefix string, logger *slog.Logger) (*StorageCache, error) {
	ctx := context.Background()

	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	cache := &StorageCache{
		backend: backend,
		prefix:  prefix + "autocert/",
		logger:  logger,
	}

	// Verify storage access
	if err := cache.verifyStorageAccess(ctx); err != nil {
		return nil, fmt.Errorf("failed to verify storage access: %w", err)
	}

	logger.Info("Storage autocert cache initialized", "prefix", cache.prefix)
	return cache, nil
}

// verifyStorageAccess checks if the storage backend is accessible.
func (c *StorageCache) verifyStorageAccess(ctx context.Context) error {
	exists, err := c.backend.BucketExists(ctx)
	if err != nil {
		return fmt.Errorf("failed to check storage existence: %w", err)
	}
	if !exists {
		return fmt.Errorf("storage does not exist")
	}
	return nil
}

// Get retrieves a certificate data from storage.
func (c *StorageCache) Get(ctx context.Context, key string) ([]byte, error) {
	storageKey := c.prefix + hashKey(key)

	c.logger.Debug("Storage-Cache: Getting certificate", "key", key, "storage_key", storageKey)

	// Get object from storage
	obj, err := c.backend.GetObject(ctx, storageKey)
	if err != nil {
		// Check if error indicates object not found
		if isNotFoundError(err) {
			c.logger.Debug("Storage-Cache: Certificate not found (cache miss)", "key", key, "storage_key", storageKey)
			return nil, autocert.ErrCacheMiss
		}
		// Return the actual error for transient S3 failures (timeout, network, etc.).
		// Returning ErrCacheMiss here would cause autocert to provision a new certificate
		// and callers like SyncAllToS3 to re-upload certs on every cycle.
		c.logger.Error("Storage-Cache: Failed to get object from storage",
			"key", key,
			"storage_key", storageKey,
			"error", err,
			"error_type", fmt.Sprintf("%T", err))
		return nil, fmt.Errorf("storage get failed for %s: %w", key, err)
	}
	defer obj.Close()

	// Read object data
	data, err := io.ReadAll(obj)
	if err != nil {
		// Return actual error - transient read failures should not trigger
		// certificate re-provisioning or unnecessary S3 re-uploads.
		c.logger.Error("Storage-Cache: Failed to read object data",
			"key", key,
			"storage_key", storageKey,
			"error", err)
		return nil, fmt.Errorf("storage read failed for %s: %w", key, err)
	}

	c.logger.Debug("Storage-Cache: Successfully retrieved certificate", "key", key, "storage_key", storageKey, "bytes", len(data))
	return data, nil
}

// Put stores certificate data in storage.
func (c *StorageCache) Put(ctx context.Context, key string, data []byte) error {
	storageKey := c.prefix + hashKey(key)

	c.logger.Debug("Storage-Cache: Putting certificate", "key", key, "storage_key", storageKey, "bytes", len(data))

	// Upload to storage
	err := c.backend.PutObject(
		ctx,
		storageKey,
		bytes.NewReader(data),
		int64(len(data)),
		storage.PutOptions{
			ContentType: "application/octet-stream",
		},
	)
	if err != nil {
		c.logger.Error("Storage-Cache: Failed to upload certificate to storage",
			"key", key,
			"storage_key", storageKey,
			"error", err,
			"error_type", fmt.Sprintf("%T", err))
		return fmt.Errorf("failed to upload to storage: %w", err)
	}

	c.logger.Debug("Storage-Cache: Successfully stored certificate", "key", key, "storage_key", storageKey)
	return nil
}

// Delete removes certificate data from storage.
func (c *StorageCache) Delete(ctx context.Context, key string) error {
	storageKey := c.prefix + hashKey(key)

	c.logger.Debug("Storage-Cache: Deleting certificate", "key", key, "storage_key", storageKey)

	// Delete from storage
	err := c.backend.RemoveObject(ctx, storageKey)
	if err != nil {
		// Check if object doesn't exist (which is fine for Delete)
		if isNotFoundError(err) {
			c.logger.Debug("Storage-Cache: Certificate already deleted or doesn't exist", "key", key)
			return nil
		}
		c.logger.Error("Storage-Cache: Failed to delete certificate from storage", "error", err)
		return fmt.Errorf("failed to delete from storage: %w", err)
	}

	c.logger.Debug("Storage-Cache: Successfully deleted certificate", "key", key)
	return nil
}

// isNotFoundError checks if an error indicates object not found
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// Storage backends return os.ErrNotExist for not found errors
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	// Also check for common "not found" error patterns in error string
	errStr := err.Error()
	return strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "NoSuchKey") ||
		strings.Contains(errStr, "does not exist")
}
