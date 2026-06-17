package spamcheck

import (
	"context"
	"maps"
	"strings"

	"migadu/mizu/pkg/smtp"
)

// Adapter wraps rspamd Client to implement the smtp.SpamChecker interface
type Adapter struct {
	client          *Client
	spamHeader      string // Header name to add when spam detected (e.g., "X-Junk")
	spamHeaderValue string // Header value for spam (e.g., "yes")
	hamHeaderValue  string // Header value for ham (empty = don't add for ham)
	rejectOnAction  string // Reject if rspamd action matches this (e.g., "reject")
}

// NewAdapter creates a new spam checker adapter
func NewAdapter(client *Client, spamHeader, spamHeaderValue, hamHeaderValue, rejectOnAction string) *Adapter {
	// Set defaults
	if spamHeader == "" {
		spamHeader = "X-Junk"
	}
	if spamHeaderValue == "" {
		spamHeaderValue = "yes"
	}

	return &Adapter{
		client:          client,
		spamHeader:      spamHeader,
		spamHeaderValue: spamHeaderValue,
		hamHeaderValue:  hamHeaderValue,
		rejectOnAction:  rejectOnAction,
	}
}

// Check performs spam checking and returns result
func (a *Adapter) Check(ctx context.Context, traceID, message, clientIP, from string, rcpt []string, helo string) (smtp.SpamCheckResult, error) {
	// Call rspamd
	result, err := a.client.Check(ctx, traceID, message, clientIP, from, rcpt, helo)
	if err != nil {
		return smtp.SpamCheckResult{}, err
	}

	// Copy so we can add the configured spam/ham header without mutating
	// the rspamd result.
	adapterResult := smtp.SpamCheckResult{
		IsSpam:     result.IsSpam,
		Action:     result.Action,
		Score:      result.Score,
		AddHeaders: make(map[string][]string, len(result.AddHeaders)+1),
	}
	maps.Copy(adapterResult.AddHeaders, result.AddHeaders)

	// Check if we should reject based on configured action
	if a.rejectOnAction != "" && strings.EqualFold(result.Action, a.rejectOnAction) {
		adapterResult.ShouldReject = true
	}

	// Add configured spam/ham header based on result
	if result.IsSpam && a.spamHeaderValue != "" {
		adapterResult.AddHeaders[a.spamHeader] = []string{a.spamHeaderValue}
	} else if !result.IsSpam && a.hamHeaderValue != "" {
		adapterResult.AddHeaders[a.spamHeader] = []string{a.hamHeaderValue}
	}

	return adapterResult, nil
}
