package main

import "testing"

func TestProductVulnerabilities(t *testing.T) {
	tests := []struct {
		name    string
		product string
		version string
		cve     string
		want    bool
	}{
		{
			name:    "FortiClientEMS 7.2.2 has CVE-2023-48788",
			product: "FortiClientEMS",
			version: "7.2.2",
			cve:     "CVE-2023-48788",
			want:    true,
		},
		{
			name:    "FortiClientEMS 7.2.3 lacks CVE-2023-48788",
			product: "FortiClientEMS",
			version: "7.2.3",
			cve:     "CVE-2023-48788",
			want:    false,
		},
		{
			name:    "FortiOS 6.4.10 has CVE-2022-42475",
			product: "FortiOS",
			version: "6.4.10",
			cve:     "CVE-2022-42475",
			want:    true,
		},
		{
			name:    "FortiOS 6.4.11 lacks CVE-2022-42475",
			product: "FortiOS",
			version: "6.4.11",
			cve:     "CVE-2022-42475",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisories, err := getAffectedAdvisories(tt.product, tt.version)
			if err != nil {
				t.Fatalf("failed to load advisories: %v", err)
			}

			found := false
			for _, a := range advisories {
				for _, cve := range a.Vulnerability.CVE {
					if cve == tt.cve {
						found = true
						break
					}
				}
				if found {
					break
				}
			}

			if found != tt.want {
				t.Fatalf("CVE %s affected=%v, want %v", tt.cve, found, tt.want)
			}
		})
	}
}
