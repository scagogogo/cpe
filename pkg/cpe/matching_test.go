package cpeskills

import (
	"testing"
)

func TestRelationString(t *testing.T) {
	tests := []struct {
		relation Relation
		expected string
	}{
		{RelationDisjoint, "disjoint"},
		{RelationSubset, "subset"},
		{RelationSuperset, "superset"},
		{RelationEqual, "equal"},
		{RelationOverlap, "overlap"},
		{RelationUnknown, "unknown"},
	}

	for _, tt := range tests {
		if got := tt.relation.String(); got != tt.expected {
			t.Errorf("Relation(%d).String() = %q, want %q", tt.relation, got, tt.expected)
		}
	}
}

func TestCompareAttributes(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		target   string
		expected int
	}{
		{"both ANY", ValueANY, ValueANY, 0},
		{"source ANY", ValueANY, "windows", 1},
		{"target ANY", "windows", ValueANY, -1},
		{"both NA", ValueNA, ValueNA, 0},
		{"source NA", ValueNA, "windows", -2},
		{"target NA", "windows", ValueNA, -2},
		{"equal values", "windows", "windows", 0},
		{"different values", "windows", "linux", -2},
		{"both empty", "", "", 0},
		{"source empty", "", "windows", 1},
		{"target empty", "windows", "", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareAttributes(tt.source, tt.target); got != tt.expected {
				t.Errorf("CompareAttributes(%q, %q) = %d, want %d", tt.source, tt.target, got, tt.expected)
			}
		})
	}
}

func TestCompareWFNs(t *testing.T) {
	source := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: ValueANY, // ANY = superset for this attribute
	}
	target := &WFN{
		Part:    "a",
		Vendor:  "microsoft",
		Product: "windows",
		Version: "10",
	}

	comparisons := CompareWFNs(source, target)

	if comparisons[AttrPart] != 0 {
		t.Errorf("Part comparison = %d, want 0", comparisons[AttrPart])
	}
	if comparisons[AttrVersion] != 1 {
		t.Errorf("Version comparison = %d, want 1 (superset)", comparisons[AttrVersion])
	}
}

func TestCompareWFNRelation(t *testing.T) {
	tests := []struct {
		name        string
		comparisons map[string]int
		expected    Relation
	}{
		{
			name:        "all equal",
			comparisons: map[string]int{AttrPart: 0, AttrVendor: 0},
			expected:    RelationEqual,
		},
		{
			name:        "superset",
			comparisons: map[string]int{AttrPart: 0, AttrVersion: 1},
			expected:    RelationSuperset,
		},
		{
			name:        "subset",
			comparisons: map[string]int{AttrPart: 0, AttrVersion: -1},
			expected:    RelationSubset,
		},
		{
			name:        "disjoint",
			comparisons: map[string]int{AttrPart: 0, AttrVendor: -2},
			expected:    RelationDisjoint,
		},
		{
			name:        "overlap",
			comparisons: map[string]int{AttrPart: 1, AttrVersion: -1},
			expected:    RelationOverlap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareWFNRelation(tt.comparisons); got != tt.expected {
				t.Errorf("CompareWFNRelation() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCPEDisjoint(t *testing.T) {
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "adobe",
		ProductName: "reader",
		Version:     "10",
	}

	if !CPEDisjoint(a, b) {
		t.Error("Expected CPEs to be disjoint")
	}

	c := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	if CPEDisjoint(a, c) {
		t.Error("Expected equal CPEs to not be disjoint")
	}

	if !CPEDisjoint(nil, a) {
		t.Error("Expected nil CPE to be disjoint")
	}
}

func TestCPEEqual(t *testing.T) {
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	if !CPEEqual(a, b) {
		t.Error("Expected CPEs to be equal")
	}

	c := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "11",
	}
	if CPEEqual(a, c) {
		t.Error("Expected different version CPEs to not be equal")
	}

	if CPEEqual(nil, a) {
		t.Error("Expected nil CPE to not be equal")
	}
}

func TestCPESubset(t *testing.T) {
	// a with specific version is subset of b with ANY version
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     ValueANY,
	}

	if !CPESubset(a, b) {
		t.Error("Expected specific version to be subset of ANY version")
	}
}

func TestCPESuperset(t *testing.T) {
	// a with ANY version is superset of b with specific version
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     ValueANY,
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}

	if !CPESuperset(a, b) {
		t.Error("Expected ANY version to be superset of specific version")
	}
}

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		source   string
		target   string
		expected bool
	}{
		{"windows", "windows", true},
		{"win*", "windows", true},
		{"win*", "win", true},
		{"win*dows", "windows", true},
		{"win?ows", "windows", true},
		{"win?ows", "winsows", true},
		{"windows", "linux", false},
		{"*", "anything", true},
		{"*", "", true},
		{"*s", "windows", true},
		{"win*s", "windows", true},
		{"w*n*s", "windows", true},
		{"abc", "xyz", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "abbc", false},
		{`\*`, "*", true},    // escaped star should match literal star
		{`\?`, "?", true},    // escaped question mark should match literal question mark
		{`\*`, "a", false},   // escaped star should not match 'a'
		{`\a`, "a", true},    // escaped 'a' matches 'a'
		{`\a`, "b", false},   // escaped 'a' should not match 'b'
		{"abc", "ab", false}, // source longer than target with no star
		{"", "", true},       // empty matches empty
		{"abc*", "abc", true}, // star at end matching nothing extra
	}

	for _, tt := range tests {
		if got := wildcardMatch(tt.source, tt.target); got != tt.expected {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", tt.source, tt.target, got, tt.expected)
		}
	}
}

func TestCompareAttributesExtended(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		target   string
		expected int
	}{
		{"both ANY", ValueANY, ValueANY, 0},
		{"source ANY", ValueANY, "windows", 1},
		{"target ANY", "windows", ValueANY, -1},
		{"both NA", ValueNA, ValueNA, 0},
		{"source NA", ValueNA, "windows", -2},
		{"target NA", "windows", ValueNA, -2},
		{"equal values", "windows", "windows", 0},
		{"different values", "windows", "linux", -2},
		{"both empty", "", "", 0},
		{"source empty (treated as ANY)", "", "windows", 1},
		{"target empty (treated as ANY)", "windows", "", -1},
		{"source wildcard superset", "win*", "windows", 1},
		{"target wildcard - source not matching target pattern", "windows", "win*", -2}, // "windows" as pattern does not match "win*" as value
		{"both wildcard matching", "win*", "win*", 0},
		{"wildcard not matching", "abc*", "xyz", -2},
		{"source wildcard question mark", "win?ows", "windows", 1},
		{"target wildcard question mark - no match as pattern", "windows", "win?ows", -2}, // "windows" as pattern doesn't match "win?ows"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareAttributes(tt.source, tt.target); got != tt.expected {
				t.Errorf("CompareAttributes(%q, %q) = %d, want %d", tt.source, tt.target, got, tt.expected)
			}
		})
	}
}

func TestCompareWFNsExtended(t *testing.T) {
	// Test with nil source
	comparisons := CompareWFNs(nil, &WFN{Part: "a", Vendor: "microsoft"})
	if comparisons[AttrPart] != 1 { // empty (ANY) vs "a" -> superset
		t.Errorf("nil source Part comparison = %d, want 1", comparisons[AttrPart])
	}

	// Test with nil target
	comparisons = CompareWFNs(&WFN{Part: "a", Vendor: "microsoft"}, nil)
	if comparisons[AttrPart] != -1 { // "a" vs empty (ANY) -> subset
		t.Errorf("nil target Part comparison = %d, want -1", comparisons[AttrPart])
	}

	// Test with both nil
	comparisons = CompareWFNs(nil, nil)
	if comparisons[AttrPart] != 0 { // ANY vs ANY -> equal
		t.Errorf("both nil Part comparison = %d, want 0", comparisons[AttrPart])
	}

	// Test with full attributes
	source := &WFN{
		Part:            "a",
		Vendor:          "microsoft",
		Product:         "windows",
		Version:         ValueANY,
		Update:          "sp1",
		Edition:         "pro",
		Language:        "en",
		SoftwareEdition: "enterprise",
		TargetSoftware:  "linux",
		TargetHardware:  "x86",
		Other:           "custom",
	}
	target := &WFN{
		Part:            "a",
		Vendor:          "microsoft",
		Product:         "windows",
		Version:         "10",
		Update:          "sp1",
		Edition:         "pro",
		Language:        "en",
		SoftwareEdition: "enterprise",
		TargetSoftware:  "linux",
		TargetHardware:  "x86",
		Other:           "custom",
	}
	comparisons = CompareWFNs(source, target)
	if comparisons[AttrVersion] != 1 {
		t.Errorf("ANY vs specific Version = %d, want 1", comparisons[AttrVersion])
	}
	if comparisons[AttrPart] != 0 {
		t.Errorf("equal Part = %d, want 0", comparisons[AttrPart])
	}
}

func TestCPESubsetExtended(t *testing.T) {
	// nil cases
	if CPESubset(nil, &CPE{}) {
		t.Error("Expected nil source not to be subset")
	}
	if CPESubset(&CPE{}, nil) {
		t.Error("Expected nil target not to allow subset")
	}

	// Equal CPEs are subsets of each other
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	if !CPESubset(a, b) {
		t.Error("Expected equal CPEs to be subset")
	}

	// Disjoint CPEs are not subsets
	c := &CPE{
		Part:        *PartApplication,
		Vendor:      "adobe",
		ProductName: "reader",
		Version:     "10",
	}
	if CPESubset(a, c) {
		t.Error("Expected disjoint CPEs not to be subset")
	}
}

func TestCPESupersetExtended(t *testing.T) {
	// nil cases
	if CPESuperset(nil, &CPE{}) {
		t.Error("Expected nil source not to be superset")
	}
	if CPESuperset(&CPE{}, nil) {
		t.Error("Expected nil target not to allow superset")
	}

	// Equal CPEs are supersets of each other
	a := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	b := &CPE{
		Part:        *PartApplication,
		Vendor:      "microsoft",
		ProductName: "windows",
		Version:     "10",
	}
	if !CPESuperset(a, b) {
		t.Error("Expected equal CPEs to be superset")
	}

	// Disjoint CPEs are not supersets
	c := &CPE{
		Part:        *PartApplication,
		Vendor:      "adobe",
		ProductName: "reader",
		Version:     "10",
	}
	if CPESuperset(a, c) {
		t.Error("Expected disjoint CPEs not to be superset")
	}
}

func TestHasWildcardPattern(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"windows", false},
		{"win*", true},
		{"win?dows", true},
		{`\*`, false}, // escaped wildcard is not a wildcard pattern
		{`\?`, false}, // escaped question mark is not a wildcard pattern
		{"", false},
		{"*", true},
		{"?", true},
	}

	for _, tt := range tests {
		if got := hasWildcardPattern(tt.value); got != tt.expected {
			t.Errorf("hasWildcardPattern(%q) = %v, want %v", tt.value, got, tt.expected)
		}
	}
}

func TestRelationStringExtended(t *testing.T) {
	// Test the unknown/default case
	unknownRelation := Relation(99)
	if unknownRelation.String() != "unknown" {
		t.Errorf("Relation(99).String() = %q, want %q", unknownRelation.String(), "unknown")
	}
}

func TestCompareAttributesWithWildcards(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		target   string
		expected int
	}{
		{"source wildcard matches target", "win*", "windows", 1},
		{"target wildcard - source doesn't match pattern", "windows", "win*", -2},
		{"both wildcards matching", "win*", "win*", 0},
		{"wildcard not matching", "abc*", "xyz", -2},
		{"source question mark", "win?ows", "windows", 1},
		{"target question mark mismatch", "windows", "win?ows", -2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareAttributes(tt.source, tt.target); got != tt.expected {
				t.Errorf("CompareAttributes(%q, %q) = %d, want %d", tt.source, tt.target, got, tt.expected)
			}
		})
	}
}

func TestWildcardMatchExtended(t *testing.T) {
	tests := []struct {
		source   string
		target   string
		expected bool
	}{
		// Multiple stars
		{"*x*", "xyz", true},
		// Star at beginning
		{"*ows", "windows", true},
		// Source longer than target no star at end
		{"windows10", "windows", false},
		// Escaped backslash followed by escaped char at end
		{`test\\`, "test\\", true},
		// Empty source matches empty target
		{"", "", true},
		// Non-empty source doesn't match empty target
		{"abc", "", false},
		// Escaped backslash with next char
		{`\\a`, `\a`, true},
	}

	for _, tt := range tests {
		if got := wildcardMatch(tt.source, tt.target); got != tt.expected {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", tt.source, tt.target, got, tt.expected)
		}
	}
}

func TestCompareWFNRelationOverlap(t *testing.T) {
	// Test overlap case: has both superset and subset but no disjoint
	comparisons := map[string]int{
		AttrPart:    0,  // equal
		AttrVendor:  1,  // superset
		AttrVersion: -1, // subset
	}
	if got := CompareWFNRelation(comparisons); got != RelationOverlap {
		t.Errorf("CompareWFNRelation() = %v, want %v", got, RelationOverlap)
	}
}

// TestCompareAttributes_OnlyTargetWildcard tests that when only target has a wildcard, wildcardMatch fails and result is -2
func TestCompareAttributes_OnlyTargetWildcard(t *testing.T) {
	// source="apache" (no wildcard), target="apac*" (has wildcard)
	// wildcardMatch("apache", "apac*") returns false because source is literal pattern
	// and 'h' != '*', so the overall result is -2
	result := CompareAttributes("apache", "apac*")
	if result != -2 {
		t.Errorf("CompareAttributes() with only target wildcard = %d, want -2", result)
	}
}

// TestCompareAttributes_EscapedWildcardSourceRealWildcardTarget tests the -1 return when source
// has escaped wildcards (not a wildcard pattern) but target has real wildcards, and they match
func TestCompareAttributes_EscapedWildcardSourceRealWildcardTarget(t *testing.T) {
	// source has escaped star \* -> hasWildcardPattern returns false
	// target has real star * -> hasWildcardPattern returns true
	// wildcardMatch(\*, *) returns true (escaped star matches literal star)
	// Result should be -1 (target has wildcard, source is subset)
	result := CompareAttributes("\\*", "*")
	if result != -1 {
		t.Errorf("CompareAttributes() with escaped wildcard source and real wildcard target = %d, want -1", result)
	}
}

// TestWildcardMatch_EscapedCharMismatch tests wildcardMatch with escaped char that doesn't match target
func TestWildcardMatch_EscapedCharMismatch(t *testing.T) {
	// Source has escaped char \a, target has different char
	result := wildcardMatch("\\a", "b")
	if result {
		t.Error("wildcardMatch() escaped char mismatch should return false")
	}
}

// TestWildcardMatch_EscapedCharInTrailingSource tests wildcardMatch with escaped char in trailing source
func TestWildcardMatch_EscapedCharInTrailingSource(t *testing.T) {
	// After target is consumed, source has escaped char followed by more - should break the loop
	result := wildcardMatch("abc\\d", "abc")
	if result {
		t.Error("wildcardMatch() with trailing escaped char should return false")
	}
}

// TestCompareWFNRelation_Equal tests CompareWFNRelation returning RelationEqual
func TestCompareWFNRelation_Equal(t *testing.T) {
	comparisons := map[string]int{
		"part":    0,
		"vendor":  0,
		"product": 0,
	}
	result := CompareWFNRelation(comparisons)
	if result != RelationEqual {
		t.Errorf("CompareWFNRelation() all equal = %v, want %v", result, RelationEqual)
	}
}

	// TestCompareAttributes_CoverageGap_TargetWildcardSubset tests CompareAttributes when only target has wildcard
	func TestCompareAttributes_CoverageGap_BothWildcards(t *testing.T) {
		// source is specific, target has wildcard -> source is subset
		result := CompareAttributes("win*", "win*")
		if result != 0 {
			t.Errorf("CompareAttributes(windows, win*) = %d, want -1 (subset)", result)
		}
	}

	// TestWildcardMatch_CoverageGap_EscapeAtEndOfSource tests wildcardMatch with escape at end of source (no next char)
	func TestWildcardMatch_CoverageGap_EscapeAtEndOfSource(t *testing.T) {
		// source ends with backslash but no next char - the escape handling branch at line 248
		result := wildcardMatch(`test\`, "test\\")
		if !result {
			t.Errorf("wildcardMatch with backslash at end should match")
		}
	}

	// TestCompareAttributes_CoverageGap_TargetWildcardOnly tests CompareAttributes when only target has wildcard but wildcardMatch succeeds
	func TestCompareAttributes_CoverageGap_TargetWildcardOnly(t *testing.T) {
		// When source has escaped wildcard "win\*" (literal asterisk) and target has "win*" (unquoted wildcard),
		// hasWildcardPattern(source) is false (escaped * is not a wildcard), hasWildcardPattern(target) is true.
		// wildcardMatch matches because the escaped * in source matches the literal * in target.
		// Then !hasWildcardPattern(source) && hasWildcardPattern(target) -> return -1
		result := CompareAttributes(`win\*`, "win*")
		if result != -1 {
			t.Errorf("CompareAttributes(win\\*, win*) = %d, want -1 (subset)", result)
		}
	}
