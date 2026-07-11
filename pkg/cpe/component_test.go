package cpeskills

import (
	"testing"
)

func TestParsePart(t *testing.T) {
	tests := []struct {
		input    string
		short    string
		wantErr  bool
	}{
		{"a", "a", false},
		{"h", "h", false},
		{"o", "o", false},
		{"A", "a", false},
		{"*", "*", false},
		{"x", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p, err := ParsePart(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePart(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && p.ShortName != tt.short {
				t.Errorf("ParsePart(%q).ShortName = %q, want %q", tt.input, p.ShortName, tt.short)
			}
		})
	}
}

func TestVendorMethods(t *testing.T) {
	tests := []struct {
		name     string
		vendor   Vendor
		isANY    bool
		isNA     bool
		isSet    bool
	}{
		{"ANY", Vendor(ValueANY), true, false, false},
		{"NA", Vendor(ValueNA), false, true, false},
		{"empty", Vendor(""), false, false, false},
		{"set", Vendor("microsoft"), false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.vendor.IsANY() != tt.isANY {
				t.Errorf("IsANY() = %v, want %v", tt.vendor.IsANY(), tt.isANY)
			}
			if tt.vendor.IsNA() != tt.isNA {
				t.Errorf("IsNA() = %v, want %v", tt.vendor.IsNA(), tt.isNA)
			}
			if tt.vendor.IsSet() != tt.isSet {
				t.Errorf("IsSet() = %v, want %v", tt.vendor.IsSet(), tt.isSet)
			}
		})
	}
}

func TestProductMethods(t *testing.T) {
	p := Product("windows")
	if p.String() != "windows" {
		t.Errorf("String() = %q, want %q", p.String(), "windows")
	}
	if p.IsANY() {
		t.Error("IsANY() should be false")
	}
	if !p.IsSet() {
		t.Error("IsSet() should be true")
	}
	if p.Normalize() != "windows" {
		t.Errorf("Normalize() = %q, want %q", p.Normalize(), "windows")
	}
}

func TestVersionMethods(t *testing.T) {
	v := Version("10.0")
	if v.String() != "10.0" {
		t.Errorf("String() = %q, want %q", v.String(), "10.0")
	}
	if v.IsANY() {
		t.Error("IsANY() should be false")
	}
	if !v.IsSet() {
		t.Error("IsSet() should be true")
	}
}

func TestEditionMethods(t *testing.T) {
	e := Edition("pro")
	if !e.IsSet() {
		t.Error("IsSet() should be true")
	}
	if e.IsANY() {
		t.Error("IsANY() should be false")
	}
}

func TestLanguageMethods(t *testing.T) {
	l := Language("en")
	if !l.IsSet() {
		t.Error("IsSet() should be true")
	}
	if l.IsNA() {
		t.Error("IsNA() should be false")
	}
}

func TestUpdateMethods(t *testing.T) {
	u := Update("sp1")
	if !u.IsSet() {
		t.Error("IsSet() should be true")
	}
	if u.IsANY() {
		t.Error("IsANY() should be false")
	}
}

func TestPartMethods(t *testing.T) {
	p := *PartApplication
	if p.IsANY() {
		t.Error("IsANY() should be false for application")
	}
	if !p.IsSet() {
		t.Error("IsSet() should be true for application")
	}
	if p.Normalize() != "a" {
		t.Errorf("Normalize() = %q, want %q", p.Normalize(), "a")
	}

	anyPart := Part{ShortName: ValueANY}
	if !anyPart.IsANY() {
		t.Error("IsANY() should be true for ANY part")
	}
}

func TestVendorNormalize(t *testing.T) {
	v := Vendor("Microsoft Corporation")
	if v.Normalize() != "microsoft_corporation" {
		t.Errorf("Normalize() = %q, want %q", v.Normalize(), "microsoft_corporation")
	}
}

func TestVendorStringAndIsNA(t *testing.T) {
	// String
	v := Vendor("microsoft")
	if v.String() != "microsoft" {
		t.Errorf("String() = %q, want %q", v.String(), "microsoft")
	}

	// IsNA
	na := Vendor(ValueNA)
	if !na.IsNA() {
		t.Error("IsNA() should be true for NA value")
	}
	anyV := Vendor(ValueANY)
	if anyV.IsNA() {
		t.Error("IsNA() should be false for ANY value")
	}
}

func TestProductIsNA(t *testing.T) {
	p := Product(ValueNA)
	if !p.IsNA() {
		t.Error("IsNA() should be true for NA value")
	}

	p2 := Product("windows")
	if p2.IsNA() {
		t.Error("IsNA() should be false for non-NA value")
	}
}

func TestVersionIsNA(t *testing.T) {
	v := Version(ValueNA)
	if !v.IsNA() {
		t.Error("IsNA() should be true for NA value")
	}

	v2 := Version("10")
	if v2.IsNA() {
		t.Error("IsNA() should be false for non-NA value")
	}
}

func TestEditionStringAndNormalize(t *testing.T) {
	e := Edition("pro edition")
	if e.String() != "pro edition" {
		t.Errorf("String() = %q, want %q", e.String(), "pro edition")
	}
	if e.Normalize() != "pro_edition" {
		t.Errorf("Normalize() = %q, want %q", e.Normalize(), "pro_edition")
	}

	// IsNA
	eNA := Edition(ValueNA)
	if !eNA.IsNA() {
		t.Error("IsNA() should be true for NA value")
	}
}

func TestLanguageStringAndNormalize(t *testing.T) {
	l := Language("en-US")
	if l.String() != "en-US" {
		t.Errorf("String() = %q, want %q", l.String(), "en-US")
	}
	if l.Normalize() != "en-us" {
		t.Errorf("Normalize() = %q, want %q", l.Normalize(), "en-us")
	}

	// IsNA
	lNA := Language(ValueNA)
	if !lNA.IsNA() {
		t.Error("IsNA() should be true for NA value")
	}
}

func TestUpdateStringAndNormalize(t *testing.T) {
	u := Update("sp1")
	if u.String() != "sp1" {
		t.Errorf("String() = %q, want %q", u.String(), "sp1")
	}

	// IsNA
	uNA := Update(ValueNA)
	if !uNA.IsNA() {
		t.Error("IsNA() should be true for NA value")
	}
}

func TestPartIsNA(t *testing.T) {
	p := Part{ShortName: ValueNA}
	if !p.IsNA() {
		t.Error("IsNA() should be true for NA value")
	}

	p2 := Part{ShortName: "a"}
	if p2.IsNA() {
		t.Error("IsNA() should be false for application part")
	}
}

func TestComponentInterfaceMethods(t *testing.T) {
	// Verify all Component interface implementations return expected values

	// Vendor: empty string case for IsSet
	emptyVendor := Vendor("")
	if emptyVendor.IsSet() {
		t.Error("IsSet() should be false for empty string")
	}

	// Product: NA case for IsSet
	naProduct := Product(ValueNA)
	if naProduct.IsSet() {
		t.Error("IsSet() should be false for NA value")
	}

	// Version: ANY case for IsSet
	anyVersion := Version(ValueANY)
	if anyVersion.IsSet() {
		t.Error("IsSet() should be false for ANY value")
	}

	// Edition: empty string case
	emptyEdition := Edition("")
	if emptyEdition.IsSet() {
		t.Error("IsSet() should be false for empty string")
	}

	// Language: ANY case
	anyLanguage := Language(ValueANY)
	if anyLanguage.IsSet() {
		t.Error("IsSet() should be false for ANY value")
	}

	// Language: NA case
	naLanguage := Language(ValueNA)
	if naLanguage.IsSet() {
		t.Error("IsSet() should be false for NA value")
	}

	// Update: empty case
	emptyUpdate := Update("")
	if emptyUpdate.IsSet() {
		t.Error("IsSet() should be false for empty string")
	}

	// Update: ANY case
	anyUpdate := Update(ValueANY)
	if anyUpdate.IsSet() {
		t.Error("IsSet() should be false for ANY value")
	}

	// Update: NA case
	naUpdate := Update(ValueNA)
	if naUpdate.IsSet() {
		t.Error("IsSet() should be false for NA value")
	}

	// Part: NA case for IsSet
	naPart := Part{ShortName: ValueNA}
	if naPart.IsSet() {
		t.Error("IsSet() should be false for NA part")
	}
}

func TestVersionNormalize(t *testing.T) {
	v := Version("10.0 Beta")
	if v.Normalize() != "10.0_beta" {
		t.Errorf("Normalize() = %q, want %q", v.Normalize(), "10.0_beta")
	}
}

func TestUpdateNormalize(t *testing.T) {
	u := Update("Service Pack 1")
	if u.Normalize() != "service_pack_1" {
		t.Errorf("Normalize() = %q, want %q", u.Normalize(), "service_pack_1")
	}
}

func TestLanguageIsANY(t *testing.T) {
	l := Language(ValueANY)
	if !l.IsANY() {
		t.Error("IsANY() should be true for ANY value")
	}

	l2 := Language("en")
	if l2.IsANY() {
		t.Error("IsANY() should be false for non-ANY value")
	}
}

func TestUpdateIsANY(t *testing.T) {
	u := Update(ValueANY)
	if !u.IsANY() {
		t.Error("IsANY() should be true for ANY value")
	}

	u2 := Update("sp1")
	if u2.IsANY() {
		t.Error("IsANY() should be false for non-ANY value")
	}
}
