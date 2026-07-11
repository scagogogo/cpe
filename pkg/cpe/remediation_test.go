package cpeskills

import (
	"testing"
)

func TestFindRemediation(t *testing.T) {
	comp := NewSBOMComponent("log4j-core", "2.14.1")

	findings := []*VulnerabilityFinding{
		{
			CVE: &CVEReference{
				CVEID:     "CVE-2021-44228",
				CVSSScore: 10.0,
				Severity:  "Critical",
			},
			FixedVersion: "2.17.0",
			KEVListed:    true,
		},
		{
			CVE: &CVEReference{
				CVEID:     "CVE-2021-45046",
				CVSSScore: 9.0,
				Severity:  "Critical",
			},
			FixedVersion: "2.17.0",
		},
	}

	advice := FindRemediation(comp, findings)
	if advice.RecommendedVersion != "2.17.0" {
		t.Errorf("expected recommended version '2.17.0', got %q", advice.RecommendedVersion)
	}
	if advice.Priority != 0 {
		t.Errorf("expected priority 0 (critical), got %d", advice.Priority)
	}
	if !advice.HasFixAvailable() {
		t.Error("expected fix available")
	}

	// Breaking change: 2.x → 3.x
	comp2 := NewSBOMComponent("pkg", "2.0.0")
	findings2 := []*VulnerabilityFinding{
		{FixedVersion: "3.0.0", CVE: &CVEReference{CVEID: "CVE-2023-1", Severity: "High"}},
	}
	advice2 := FindRemediation(comp2, findings2)
	if !advice2.BreakingChange {
		t.Error("expected breaking change for major version bump")
	}
}

func TestIsBreakingChange(t *testing.T) {
	if !isBreakingChange("1.0.0", "2.0.0") {
		t.Error("1.0.0 → 2.0.0 should be breaking")
	}
	if isBreakingChange("1.0.0", "1.1.0") {
		t.Error("1.0.0 → 1.1.0 should not be breaking")
	}
	if isBreakingChange("1.0.0", "1.0.1") {
		t.Error("1.0.0 → 1.0.1 should not be breaking")
	}
}

func TestRemediationAdvice_IsUrgent(t *testing.T) {
	comp := NewSBOMComponent("pkg", "1.0.0")
	findings := []*VulnerabilityFinding{
		{
			CVE:       &CVEReference{CVEID: "CVE-2023-1", Severity: "Critical", CVSSScore: 10.0},
			KEVListed: true,
		},
	}
	advice := FindRemediation(comp, findings)
	if !advice.IsUrgent(findings) {
		t.Error("expected urgent for Critical+KEV")
	}

	findings2 := []*VulnerabilityFinding{
		{CVE: &CVEReference{CVEID: "CVE-2023-2", Severity: "Medium"}},
	}
	advice2 := FindRemediation(comp, findings2)
	if advice2.IsUrgent(findings2) {
		t.Error("expected not urgent for Medium")
	}
}
