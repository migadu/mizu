package config

// exampleServer returns the [[server]] block written by generate-config: every
// option the server section accepts, set to the value it takes when omitted
// (or, for options with no default, to an inert placeholder). Features that
// need an external endpoint are present but disabled.
//
// It is only used to render the example file. DefaultConfig keeps Servers
// empty, so a config with no [[server]] section is still rejected.
func exampleServer() ServerConfig {
	t := true
	f := false
	return ServerConfig{
		Name:       "mx-primary",
		Type:       "relay",
		ListenAddr: ":25",
		Hostname:   "mail.example.com",

		ProxyProtocol:        false,
		ProxyProtocolTrusted: []string{},

		MaxMessageSize:          25 * 1024 * 1024,
		MaxRecipientsPerMessage: 100,

		Limits: ServerLimitsConfig{
			MaxConnections:               100,
			MaxConnectionsPerIP:          0,
			MaxConnectionsPerUser:        0,
			MaxConnectionDurationSeconds: 300,
		},

		TLS: ServerTLSConfig{
			Enabled:           true,
			Mode:              "starttls",
			Required:          false,
			MinTLSVersion:     "1.2",
			MaxTLSVersion:     "",
			ExtraCipherSuites: []string{},
		},

		TimeoutSeconds:         300,
		ShutdownTimeoutSeconds: 60,

		LegacyAuthCap:   &t,
		AdvertiseLimits: false,
		Debug:           false,

		EnableTraceIDHeader:     &t,
		EnableAuthResultsHeader: &t,
		EnableJunkHeader:        &t,
		EnableEnvelopeToHeader:  &t, // false: one POST per message, the backend stamps X-Envelope-To

		// Per-type default: true on submission, false on relay.
		StripClientIdentity: &f,

		// Per-type default: true on relay, false on submission.
		HELOValidation:        &t,
		SPFCheck:              false,
		DKIMCheck:             false,
		ARCCheck:              false,
		DMARCCheck:            false,
		DMARCRejectAction:     "reject",
		DMARCQuarantineAction: "junk",

		Validation: ServerValidationConfig{
			MissingHeadersAction: "fix", // submission default: "reject"
			LoopDetection:        &t,
			MaxHops:              30,
		},

		Reputation: ServerReputationConfig{
			Enabled:        true, // submission default: false
			MinIPScore:     -0.2,
			MinDomainScore: -0.2,
			RejectCode:     421,
			RejectMessage:  "poor reputation, please try again later",
			WhitelistIPs:   []string{},
			WhitelistHosts: []string{},
			DNSBL: ServerReputationDNSBLConfig{
				Enabled:        false,
				IPv4Lists:      []string{},
				IPv6Lists:      []string{},
				TimeoutSeconds: 3,
				Weight:         5,
			},
		},

		// Authentication is for submission servers; kept disabled here.
		Auth: ServerAuthConfig{
			Enabled:   false,
			Required:  false,
			URL:       "",
			AuthToken: "",
			Cache: ServerAuthCacheConfig{
				Enabled:                    true,
				PositiveTTL:                "5m",
				NegativeTTL:                "1m",
				MaxSize:                    50000,
				CleanupInterval:            "5m",
				PositiveRevalidationWindow: "30s",
			},
			RateLimit: ServerAuthRateLimitConfig{
				Enabled:                  true,
				MaxAttemptsPerIPUsername: 5,
				IPUsernameBlockDuration:  "15m",
				IPUsernameWindowDuration: "10m",
				MaxAttemptsPerIP:         50,
				IPBlockDuration:          "30m",
				IPWindowDuration:         "30m",
				SubnetMaxDistinctIPs:     8,
				SubnetMinFailures:        15,
				SubnetWindowDuration:     "30m",
				SubnetBlockDuration:      "30m",
				SubnetIPv4Prefix:         24,
				SubnetIPv6Prefix:         48,
				SubnetExempt:             []string{},
				SuccessExemptDuration:    "24h",
				MaxAttemptsPerUsername:   100,
				UsernameWindowDuration:   "1h",
				DelayStartThreshold:      3,
				InitialDelay:             "1s",
				MaxDelay:                 "30s",
				DelayMultiplier:          2.0,
				CacheCleanupInterval:     "5m",
				MaxIPUsernameEntries:     100000,
				MaxIPEntries:             50000,
				MaxUsernameEntries:       50000,
				MaxSubnetEntries:         10000,
				ClusterSyncEnabled:       true,
				SyncBlocks:               true,
				SyncFailureCounts:        true,
			},
		},

		DNSChecks: ServerDNSChecksConfig{
			RequireRDNS:           false,
			RequireSenderMX:       false,
			RequireResolvableHELO: false,
			RDNSWhitelistIPs:      []string{},
		},

		Junk: ServerJunkConfig{
			RejectNullSender: false,
			CheckHeaders:     []string{},
			ApplyAction:      "header",
			SubjectPattern:   "[spam] %s",
			Header:           "X-Spam",
		},

		SpamCheck: ServerSpamCheckConfig{
			Enabled:            false,
			URL:                "http://rspamd:11333/checkv2",
			Password:           "",
			HTTPTimeoutSeconds: 15,
			SpamHeader:         "X-Junk",
			SpamHeaderValue:    "yes",
			HamHeaderValue:     "",
			RejectOnAction:     "",
		},

		RateLimit: RateLimitConfig{
			Enabled:                        false,
			GossipEnabled:                  false,
			GossipIntervalSeconds:          5,
			WhitelistedIPs:                 []string{},
			WhitelistedDomains:             []string{},
			WhitelistedSenders:             []string{},
			WhitelistedIPsFile:             "",
			WhitelistedDomainsFile:         "",
			WhitelistedSendersFile:         "",
			WhitelistReloadIntervalSeconds: 10,
			Dimensions: []RateLimitDimension{
				{Name: "per-ip", Keys: []string{"IP"}, Limit: 100, WindowSeconds: 60},
			},
		},

		Distributed: DistributedLimitsConfig{
			Enabled:                  false,
			GlobalMaxPerIP:           0,
			GossipIntervalSeconds:    5,
			S3SyncIntervalSeconds:    30,
			RecipientCacheTTLSeconds: 900,
		},

		SenderValidation: SenderValidationConfig{
			Enabled:            false,
			URL:                "https://backend.example.com/validate/sender?from=$from&ip=$ip",
			AuthToken:          "",
			HTTPTimeoutSeconds: 5,
			CacheTTLSeconds:    300,
		},

		RecipientValidation: RecipientValidationConfig{
			Enabled:            false,
			URL:                "https://backend.example.com/validate/recipient?email=$email&from=$from&ip=$ip",
			AuthToken:          "",
			HTTPTimeoutSeconds: 5,
			CacheTTLSeconds:    300,
		},

		Delivery: DeliveryConfig{
			URL:                    "https://backend.example.com/deliver",
			AuthToken:              "",
			MaxRetryAttempts:       3,
			HTTPTimeoutSeconds:     30,
			MaxIdleConnsPerHost:    100,
			MaxConnsPerHost:        0,
			IdleConnTimeoutSeconds: 90,
			CircuitBreaker: CircuitBreakerConfig{
				Enabled:             true,
				FailureThreshold:    5,
				SuccessThreshold:    2,
				TimeoutSeconds:      30,
				HalfOpenMaxCalls:    1,
				ResetTimeoutSeconds: 60,
			},
		},
	}
}
