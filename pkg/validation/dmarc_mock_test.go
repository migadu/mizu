package validation

import (
	"github.com/emersion/go-msgauth/dmarc"
)

// This file contains a mock for DMARC lookups to make tests reliable and independent of external DNS.

var dmarcRecords = map[string]*dmarc.Record{
	"dmarc.io": {
		Policy: dmarc.PolicyReject,
	},
	"st.dmarc.io": {
		Policy:        dmarc.PolicyReject,
		SPFAlignment:  dmarc.AlignmentStrict,
		DKIMAlignment: dmarc.AlignmentStrict,
	},
	"qt.dmarc.io": {
		Policy: dmarc.PolicyQuarantine,
	},
}

func init() {
	// Save the original lookup function to fall back to it.
	originalDmarcLookup := dmarcLookup
	// Replace our package's dmarcLookup variable with a mock implementation for tests.
	dmarcLookup = func(domain string, lookupTXT func(string) ([]string, error)) (*dmarc.Record, error) {
		if record, ok := dmarcRecords[domain]; ok {
			return record, nil
		}
		// If not in our mock map, fall back to the real lookup.
		// This is useful for TestCheckDMARC_NoDMARCRecord.
		return originalDmarcLookup(domain, lookupTXT)
	}
}
