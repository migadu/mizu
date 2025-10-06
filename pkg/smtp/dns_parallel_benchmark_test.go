package smtp

import (
	"sync"
	"testing"
	"time"

	"migadu/mizu/pkg/validation"

	"github.com/emersion/go-msgauth/authres"
)

// BenchmarkSequentialDNS benchmarks the old sequential SPF+MX lookup pattern
func BenchmarkSequentialDNS(b *testing.B) {
	// Simulate DNS lookup delay (50ms is typical for remote DNS)
	dnsDelay := 50 * time.Millisecond

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Sequential: SPF then MX (old approach)
		var spfResult *validation.SPFResult

		// SPF check
		time.Sleep(dnsDelay) // Simulate DNS query
		spfResult = &validation.SPFResult{
			Result: authres.SPFResult{
				Value: authres.ResultPass,
			},
		}

		// MX check
		time.Sleep(dnsDelay) // Simulate DNS query
		hasMX := true

		// Use results to prevent optimization
		_ = spfResult
		_ = hasMX
	}
}

// BenchmarkParallelDNS benchmarks the new parallel SPF+MX lookup pattern
func BenchmarkParallelDNS(b *testing.B) {
	domain := "example.com"

	// Simulate DNS lookup delay (50ms is typical for remote DNS)
	dnsDelay := 50 * time.Millisecond

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Parallel: SPF and MX together (new approach)
		var wg sync.WaitGroup
		var spfMu sync.Mutex
		var spfResult *validation.SPFResult
		var hasMX bool

		// SPF check in parallel
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(dnsDelay) // Simulate DNS query
			spfMu.Lock()
			spfResult = &validation.SPFResult{
				Domain: domain,
				Result: authres.SPFResult{
					Value: authres.ResultPass,
				},
			}
			spfMu.Unlock()
		}()

		// MX check in parallel
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(dnsDelay) // Simulate DNS query
			hasMX = true
		}()

		wg.Wait()

		// Use results to prevent optimization
		_ = spfResult
		_ = hasMX
	}
}

// BenchmarkRealWorldScenario simulates realistic DNS query patterns
func BenchmarkRealWorldScenario(b *testing.B) {
	scenarios := []struct {
		name     string
		spfDelay time.Duration
		mxDelay  time.Duration
		parallel bool
	}{
		{"Sequential_Fast", 10 * time.Millisecond, 10 * time.Millisecond, false},
		{"Parallel_Fast", 10 * time.Millisecond, 10 * time.Millisecond, true},
		{"Sequential_Typical", 50 * time.Millisecond, 50 * time.Millisecond, false},
		{"Parallel_Typical", 50 * time.Millisecond, 50 * time.Millisecond, true},
		{"Sequential_Slow", 100 * time.Millisecond, 100 * time.Millisecond, false},
		{"Parallel_Slow", 100 * time.Millisecond, 100 * time.Millisecond, true},
	}

	for _, scenario := range scenarios {
		b.Run(scenario.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if scenario.parallel {
					// Parallel execution
					var wg sync.WaitGroup
					wg.Add(2)
					go func() {
						defer wg.Done()
						time.Sleep(scenario.spfDelay)
					}()
					go func() {
						defer wg.Done()
						time.Sleep(scenario.mxDelay)
					}()
					wg.Wait()
				} else {
					// Sequential execution
					time.Sleep(scenario.spfDelay)
					time.Sleep(scenario.mxDelay)
				}
			}
		})
	}
}
