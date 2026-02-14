package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"migadu/mizu/pkg/config"
)

// NewLogger creates a configured slog.Logger based on the LoggingConfig.
func NewLogger(cfg config.LoggingConfig) (*slog.Logger, error) {
	// Parse log level
	level, err := parseLogLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	// Determine output writer
	writer, err := getLogWriter(cfg.Output)
	if err != nil {
		return nil, fmt.Errorf("failed to create log writer: %w", err)
	}

	// Create handler based on format
	var handler slog.Handler
	opts := &slog.HandlerOptions{
		Level: level,
	}

	switch strings.ToLower(cfg.Format) {
	case "json":
		handler = slog.NewJSONHandler(writer, opts)
	case "console", "":
		handler = slog.NewTextHandler(writer, opts)
	default:
		return nil, fmt.Errorf("invalid log format: %s (must be 'console' or 'json')", cfg.Format)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger, nil
}

// parseLogLevel converts a string log level to slog.Level.
func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown level: %s (must be debug, info, warn, or error)", level)
	}
}

// getLogWriter creates an io.Writer based on the output configuration.
func getLogWriter(output string) (io.Writer, error) {
	switch strings.ToLower(output) {
	case "stderr":
		return os.Stderr, nil
	case "stdout":
		return os.Stdout, nil
	case "syslog", "":
		// For syslog, we'll use stderr as a fallback since slog doesn't have built-in syslog support.
		// Users can pipe stderr to syslog using systemd or other tools.
		return os.Stderr, nil
	default:
		// Assume it's a file path
		file, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file %s: %w", output, err)
		}
		return file, nil
	}
}

// Setup initializes a slog logger based on the provided format and verbosity.
// Deprecated: Use NewLogger with config.LoggingConfig instead.
func Setup(format string, verbose bool) (*slog.Logger, error) {
	var level slog.Level
	if verbose {
		level = slog.LevelDebug
	} else {
		level = slog.LevelInfo
	}

	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: level,
		})
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger, nil
}

// NewTestLogger creates a logger for testing that discards output
func NewTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}
