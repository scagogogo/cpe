package cpeskills

import (
	"testing"
)

// TestSearch tests the Search function
func TestSearch(t *testing.T) {
	cpes := []*CPE{
		{
			Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
		},
		{
			Cpe23:       "cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "11",
		},
		{
			Cpe23:       "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "office",
			Version:     "2019",
		},
		{
			Cpe23:       "cpe:2.3:a:adobe:reader:dc:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      "adobe",
			ProductName: "reader",
			Version:     "dc",
		},
	}

	tests := []struct {
		name     string
		criteria *CPE
		options  *MatchOptions
		expected int
	}{
		{
			name: "search by vendor",
			criteria: &CPE{
				Vendor: "microsoft",
			},
			options:  nil,
			expected: 3,
		},
		{
			name: "search by product",
			criteria: &CPE{
				ProductName: "windows",
			},
			options:  nil,
			expected: 2,
		},
		{
			name: "search with version range",
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options: &MatchOptions{
				VersionRange: true,
				MinVersion:   "10",
				MaxVersion:   "11",
			},
			expected: 2,
		},
		{
			name: "search with regex vendor",
			criteria: &CPE{
				Vendor: "micro.*",
			},
			options: &MatchOptions{
				UseRegex: true,
			},
			expected: 3,
		},
		{
			name: "search with no matches",
			criteria: &CPE{
				Vendor:      "google",
				ProductName: "chrome",
			},
			options:  nil,
			expected: 0,
		},
		{
			name: "search with nil options uses defaults",
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options:  nil,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Search(cpes, tt.criteria, tt.options)
			if len(result) != tt.expected {
				t.Errorf("Search() returned %d results, want %d", len(result), tt.expected)
			}
		})
	}
}

// TestMatchCPEPrivate tests the private matchCPE function in search.go
func TestMatchCPEPrivate(t *testing.T) {
	tests := []struct {
		name     string
		cpe      *CPE
		criteria *CPE
		options  *MatchOptions
		expected bool
	}{
		{
			name: "version range - min version only",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "11",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options: &MatchOptions{
				VersionRange: true,
				MinVersion:   "10",
			},
			expected: true,
		},
		{
			name: "version range - max version only",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "9",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options: &MatchOptions{
				VersionRange: true,
				MaxVersion:   "10",
			},
			expected: true,
		},
		{
			name: "version range - below min",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "8",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &MatchOptions{
				VersionRange: true,
				MinVersion:   "10",
			},
			expected: false,
		},
		{
			name: "version range - above max",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "12",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &MatchOptions{
				VersionRange: true,
				MaxVersion:   "10",
			},
			expected: false,
		},
		{
			name: "sub version matching - prefix match",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10.0.1",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &MatchOptions{
				AllowSubVersions: true,
			},
			expected: true,
		},
		{
			name: "sub version matching - no prefix match",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "11.0.1",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &MatchOptions{
				AllowSubVersions: true,
			},
			expected: false,
		},
		{
			name: "regex match on product",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			criteria: &CPE{
				ProductName: "win.*",
			},
			options: &MatchOptions{
				UseRegex: true,
			},
			expected: true,
		},
		{
			name: "regex match on update",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp1",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp.*",
			},
			options: &MatchOptions{
				UseRegex: true,
			},
			expected: true,
		},
		{
			name: "update mismatch without regex",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp1",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
				Update:      "sp2",
			},
			options: &MatchOptions{},
			expected: false,
		},
		{
			name: "exact version match",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &MatchOptions{
				AllowSubVersions: false,
			},
			expected: true,
		},
		{
			name: "exact version mismatch",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "11",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &MatchOptions{
				AllowSubVersions: false,
			},
			expected: false,
		},
		{
			name: "ignore version",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "11",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			options: &MatchOptions{
				IgnoreVersion: true,
			},
			expected: true,
		},
		{
			name: "vendor wildcard matches any",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			criteria: &CPE{
				ProductName: "windows",
				Vendor:      "*",
			},
			options:  DefaultMatchOptions(),
			expected: true,
		},
		{
			name: "product wildcard matches any",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
				Version:     "10",
			},
			criteria: &CPE{
				Vendor:      "microsoft",
				ProductName: "*",
			},
			options:  DefaultMatchOptions(),
			expected: true,
		},
		{
			name: "part must match",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			criteria: &CPE{
				Part:        *PartOperationSystem,
				Vendor:      "microsoft",
				ProductName: "windows",
			},
			options:  DefaultMatchOptions(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchCPE(tt.cpe, tt.criteria, tt.options); got != tt.expected {
				t.Errorf("matchCPE() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestFindVulnerableCPEs tests the FindVulnerableCPEs function
func TestFindVulnerableCPEs(t *testing.T) {
	cpes := []*CPE{
		{
			Cpe23:       "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      "apache",
			ProductName: "log4j",
			Version:     "2.0",
			Cve:         "CVE-2021-44228",
		},
		{
			Cpe23:       "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      "apache",
			ProductName: "log4j",
			Version:     "2.14",
			Cve:         "CVE-2021-44228",
		},
		{
			Cpe23:       "cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      "apache",
			ProductName: "tomcat",
			Version:     "9.0",
			Cve:         "CVE-2021-45046",
		},
		{
			Cpe23:       "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
			Cve:         "",
		},
	}

	tests := []struct {
		name     string
		cves     []string
		expected int
	}{
		{
			name:     "find by single CVE",
			cves:     []string{"CVE-2021-44228"},
			expected: 2,
		},
		{
			name:     "find by multiple CVEs",
			cves:     []string{"CVE-2021-44228", "CVE-2021-45046"},
			expected: 3,
		},
		{
			name:     "find by non-existent CVE",
			cves:     []string{"CVE-2099-99999"},
			expected: 0,
		},
		{
			name:     "empty CVE list",
			cves:     []string{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindVulnerableCPEs(cpes, tt.cves)
			if len(result) != tt.expected {
				t.Errorf("FindVulnerableCPEs() returned %d results, want %d", len(result), tt.expected)
			}
		})
	}
}

// TestDefaultMatchOptionsSearch tests DefaultMatchOptions
func TestDefaultMatchOptionsSearch(t *testing.T) {
	options := DefaultMatchOptions()
	if options.IgnoreVersion != false {
		t.Errorf("DefaultMatchOptions().IgnoreVersion = %v, want false", options.IgnoreVersion)
	}
	if options.AllowSubVersions != true {
		t.Errorf("DefaultMatchOptions().AllowSubVersions = %v, want true", options.AllowSubVersions)
	}
	if options.UseRegex != false {
		t.Errorf("DefaultMatchOptions().UseRegex = %v, want false", options.UseRegex)
	}
	if options.VersionRange != false {
		t.Errorf("DefaultMatchOptions().VersionRange = %v, want false", options.VersionRange)
	}
}

// TestMatchCPE_ProductRegexMismatch tests matchCPE with UseRegex and non-matching product
func TestMatchCPE_ProductRegexMismatch(t *testing.T) {
	cpe := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
	}
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("^nginx$"),
	}
	options := &MatchOptions{UseRegex: true}
	if matchCPE(cpe, criteria, options) {
		t.Error("matchCPE with UseRegex and non-matching product should return false")
	}
}

// TestMatchCPE_UpdateRegexMismatch tests matchCPE with UseRegex and non-matching update
func TestMatchCPE_UpdateRegexMismatch(t *testing.T) {
	cpe := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Update:      Update("sp1"),
	}
	criteria := &CPE{
		Part:        *PartApplication,
		Vendor:      Vendor("apache"),
		ProductName: Product("tomcat"),
		Update:      Update("^sp2$"),
	}
	options := &MatchOptions{UseRegex: true}
	if matchCPE(cpe, criteria, options) {
		t.Error("matchCPE with UseRegex and non-matching update should return false")
	}
}

	// TestMatchCPE_CoverageGap_UpdateRegexMismatch tests matchCPE with regex update mismatch
	func TestMatchCPE_CoverageGap_UpdateRegexMismatch(t *testing.T) {
		cpe := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
			Update:      "sp1",
		}
		criteria := &CPE{
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
			Update:      "sp[0-9]0",
		}
		options := &MatchOptions{
			UseRegex: true,
		}
		if matchCPE(cpe, criteria, options) {
			t.Error("matchCPE with regex update mismatch should return false")
		}
	}

	// TestMatchCPE_CoverageGap_VersionRangeWithMinAndMax tests matchCPE version range with both bounds
	func TestMatchCPE_CoverageGap_VersionRangeWithMinAndMax(t *testing.T) {
		cpe := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
		}
		criteria := &CPE{
			Vendor:      "microsoft",
			ProductName: "windows",
		}
		options := &MatchOptions{
			VersionRange: true,
			MinVersion:   "9",
			MaxVersion:   "11",
		}
		if !matchCPE(cpe, criteria, options) {
			t.Error("matchCPE with version in range should return true")
		}
	}

	// TestMatchCPE_CoverageGap_ExactVersionNoSubVersions tests matchCPE with exact version match (no sub-version)
	func TestMatchCPE_CoverageGap_ExactVersionNoSubVersions(t *testing.T) {
		cpe := &CPE{
			Part:        *PartApplication,
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "10",
		}
		criteria := &CPE{
			Vendor:      "microsoft",
			ProductName: "windows",
			Version:     "11",
		}
		options := &MatchOptions{
			AllowSubVersions: false,
		}
		if matchCPE(cpe, criteria, options) {
			t.Error("matchCPE with exact version mismatch should return false")
		}
	}
