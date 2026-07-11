package cpeskills

import (
	"testing"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "1.1.0", -1},
		{"1.1.0", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"10", "9", 1},
		{"9", "10", -1},
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			result := CompareVersions(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

func TestIsVersionInRange(t *testing.T) {
	tests := []struct {
		version    string
		minVersion string
		maxVersion string
		expected   bool
	}{
		{"1.5", "1.0", "2.0", true},
		{"1.0", "1.0", "2.0", true},
		{"2.0", "1.0", "2.0", true},
		{"0.5", "1.0", "2.0", false},
		{"2.5", "1.0", "2.0", false},
		{"1.5", "", "", true},      // no bounds
		{"1.5", "1.0", "", true},   // no max
		{"0.5", "1.0", "", false},  // below min
		{"1.5", "", "2.0", true},   // no min
		{"2.5", "", "2.0", false},  // above max
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := IsVersionInRange(tt.version, tt.minVersion, tt.maxVersion); got != tt.expected {
				t.Errorf("IsVersionInRange(%q, %q, %q) = %v, want %v",
					tt.version, tt.minVersion, tt.maxVersion, got, tt.expected)
			}
		})
	}
}

func TestIsSubVersion(t *testing.T) {
	tests := []struct {
		parent    string
		child     string
		expected  bool
	}{
		{"1.0", "1.0.1", true},
		{"1.0", "1.0", true},
		{"1.0", "1.1", false},
		{"1", "1.0", true},
		{"2.0", "1.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.parent+"_"+tt.child, func(t *testing.T) {
			if got := IsSubVersion(tt.parent, tt.child); got != tt.expected {
				t.Errorf("IsSubVersion(%q, %q) = %v, want %v",
					tt.parent, tt.child, got, tt.expected)
			}
		})
	}
}

func TestParseVersionRange(t *testing.T) {
	tests := []struct {
		input     string
		min       string
		max       string
		wantErr   bool
	}{
		{"1.0", "1.0", "1.0", false},
		{"1.0-2.0", "1.0", "2.0", false},
		{"1.0+", "1.0", "", false},
		{"", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			vr, err := ParseVersionRange(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseVersionRange(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if vr.MinVersion != tt.min {
					t.Errorf("MinVersion = %q, want %q", vr.MinVersion, tt.min)
				}
				if vr.MaxVersion != tt.max {
					t.Errorf("MaxVersion = %q, want %q", vr.MaxVersion, tt.max)
				}
			}
		})
	}
}

func TestVersionRangeContains(t *testing.T) {
	vr, _ := ParseVersionRange("1.0-2.0")

	if !vr.Contains("1.5") {
		t.Error("Expected 1.5 to be in range 1.0-2.0")
	}
	if vr.Contains("0.5") {
		t.Error("Expected 0.5 to not be in range 1.0-2.0")
	}
	if vr.Contains("2.5") {
		t.Error("Expected 2.5 to not be in range 1.0-2.0")
	}
}

func TestIsSubVersionEdgeCases(t *testing.T) {
	// Same version with suffix - should return true when suffix matches
	result := IsSubVersion("1.0", "1.0")
	if !result {
		t.Error("IsSubVersion('1.0', '1.0') should be true")
	}

	// Child with extra version numbers
	result = IsSubVersion("1.0", "1.0.1")
	if !result {
		t.Error("IsSubVersion('1.0', '1.0.1') should be true")
	}

	// Different prefix
	result = IsSubVersion("1.0", "2.0.1")
	if result {
		t.Error("IsSubVersion('1.0', '2.0.1') should be false")
	}

	// Child shorter than parent
	result = IsSubVersion("1.0.1", "1.0")
	if result {
		t.Error("IsSubVersion('1.0.1', '1.0') should be false - child shorter")
	}
}
