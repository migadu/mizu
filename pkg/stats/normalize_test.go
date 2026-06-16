package stats

import "testing"

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
		wantOK bool
	}{
		{"ipv4", "192.168.1.1", "192.168.1.1", true},
		{"ipv6 compressed", "::1", "::1", true},
		{"ipv6 expanded", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1", true},
		{"ipv6 mixed case", "2001:0DB8::1", "2001:db8::1", true},
		{"ipv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8:85a3::8a2e:370:7334", true},
		{"invalid", "not-an-ip", "", false},
		{"empty", "", "", false},
		{"ipv4 with port", "192.168.1.1:8080", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizeIP(tt.input)
			if ok != tt.wantOK {
				t.Errorf("NormalizeIP(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("NormalizeIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
