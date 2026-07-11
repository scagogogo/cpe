package cpeskills

import (
	"testing"
)

func TestIsAlphanumeric(t *testing.T) {
	tests := []struct {
		char     byte
		expected bool
	}{
		{'a', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'*', false},
		{'.', false},
		{'-', false},
		{'_', false},
	}

	for _, tt := range tests {
		if got := isAlphanumeric(tt.char); got != tt.expected {
			t.Errorf("isAlphanumeric(%c) = %v, want %v", tt.char, got, tt.expected)
		}
	}
}

func TestIsLogicalValue(t *testing.T) {
	if !isLogicalValue(ValueANY) {
		t.Errorf("isLogicalValue(%q) should be true", ValueANY)
	}
	if !isLogicalValue(ValueNA) {
		t.Errorf("isLogicalValue(%q) should be true", ValueNA)
	}
	if isLogicalValue("windows") {
		t.Error("isLogicalValue(\"windows\") should be false")
	}
	if isLogicalValue("") {
		t.Error("isLogicalValue(\"\") should be false")
	}
}

func TestHasUnquotedWildcard(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"windows", false},
		{"win*dows", true},
		{"win?dows", true},
		{"win\\*dows", false},
		{"win\\?dows", false},
		{"*windows", true},
		{"windows*", true},
		{"\\*", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := hasUnquotedWildcard(tt.value); got != tt.expected {
			t.Errorf("hasUnquotedWildcard(%q) = %v, want %v", tt.value, got, tt.expected)
		}
	}
}

func TestEscapeForFS(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"simple value", "windows", "windows"},
		{"dot escaped", "example.com", "example\\.com"},
		{"hyphen escaped", "service-pack", "service\\-pack"},
		{"underscore escaped", "red_hat", "red\\_hat"},
		{"colon encoded", "product:name", "product%3aname"},
		{"slash encoded", "a/b", "a%2fb"},
		{"tilde encoded", "version~rc1", "version%7erc1"},
		{"mixed special", "a.b-c_d:e/f~g", "a\\.b\\-c\\_d%3ae%2ff%7eg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeForFS(tt.value); got != tt.expected {
				t.Errorf("escapeForFS(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestUnescapeFromFS(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"simple value", "windows", "windows"},
		{"dot unescaped", "example\\.com", "example.com"},
		{"hyphen unescaped", "service\\-pack", "service-pack"},
		{"underscore unescaped", "red\\_hat", "red_hat"},
		{"colon decoded", "product%3aname", "product:name"},
		{"slash decoded", "a%2fb", "a/b"},
		{"tilde decoded", "version%7erc1", "version~rc1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unescapeFromFS(tt.value); got != tt.expected {
				t.Errorf("unescapeFromFS(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestEscapeForURI(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"simple value", "windows", "windows"},
		{"dot encoded", "example.com", "example%2ecom"},
		{"hyphen encoded", "service-pack", "service%2dpack"},
		{"underscore encoded", "red_hat", "red%5fhat"},
		{"colon encoded", "product:name", "product%3aname"},
		{"slash encoded", "a/b", "a%2fb"},
		{"tilde encoded", "version~rc1", "version%7erc1"},
		{"escaped sequence - backslash+dot", `\.`, "%5c%2e"},                      // backslash then dot - both encoded
		{"escaped sequence - backslash+alpha", `\a`, "%5ca"},                       // backslash encoded, alpha stays
		{"escaped sequence - backslash+special", `\:`, "%5c%3a"},                   // both encoded in URI
		{"backslash at end", `test\`, "test%5c"},                                   // trailing backslash with no next char
		{"non-quoted special char - space", "hello world", "hello%20world"},        // space is not in quotedCharToPercentEncode, uses toHex
		{"non-quoted special char - tab", "hello\tworld", "hello%09world"},         // tab uses toHex
		{"question mark", "what?", "what%3f"},                                       // question mark not in map? actually it's not
		{"exclamation mark", "hello!", "hello%21"},
		{"at sign", "user@host", "user%40host"},
		{"equals sign", "key=value", "key%3dvalue"},
		{"plus sign", "a+b", "a%2bb"},
		{"comma", "a,b", "a%2cb"},
		{"brackets", "a[b]c", "a%5bb%5dc"},
		{"caret", "a^b", "a%5eb"},
		{"backtick", "a`b", "a%60b"},
		{"braces", "a{b}c", "a%7bb%7dc"},
		{"pipe", "a|b", "a%7cb"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeForURI(tt.value); got != tt.expected {
				t.Errorf("escapeForURI(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestUnescapeFromURI(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"simple value", "windows", "windows"},
		{"dot decoded", "example%2ecom", "example.com"},
		{"hyphen decoded", "service%2dpack", "service-pack"},
		{"underscore decoded", "red%5fhat", "red_hat"},
		{"colon decoded", "product%3aname", "product:name"},
		{"slash decoded", "a%2fb", "a/b"},
		{"tilde decoded", "version%7erc1", "version~rc1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unescapeFromURI(tt.value); got != tt.expected {
				t.Errorf("unescapeFromURI(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestPackUnpackExtendedAttributes(t *testing.T) {
	tests := []struct {
		name                                       string
		edition, language, swEdition, targetSw, targetHw, other string
	}{
		{"all empty", "", "", "", "", "", ""},
		{"all ANY", ValueANY, ValueANY, ValueANY, ValueANY, ValueANY, ValueANY},
		{"only sw_edition", ValueANY, ValueANY, "enterprise", ValueANY, ValueANY, ValueANY},
		{"all set", "pro", "en", "enterprise", "linux", "x86", "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packed := packExtendedAttributes(tt.edition, tt.language, tt.swEdition, tt.targetSw, tt.targetHw, tt.other)
			e, l, s, ts, th, o := unpackExtendedAttributes(packed)

			// Normalize for comparison
			normalize := func(v string) string {
				if v == "" {
					return ValueANY
				}
				return v
			}

			if normalize(e) != normalize(tt.edition) {
				t.Errorf("edition = %q, want %q", e, tt.edition)
			}
			if normalize(l) != normalize(tt.language) {
				t.Errorf("language = %q, want %q", l, tt.language)
			}
			if normalize(s) != normalize(tt.swEdition) {
				t.Errorf("swEdition = %q, want %q", s, tt.swEdition)
			}
			if normalize(ts) != normalize(tt.targetSw) {
				t.Errorf("targetSw = %q, want %q", ts, tt.targetSw)
			}
			if normalize(th) != normalize(tt.targetHw) {
				t.Errorf("targetHw = %q, want %q", th, tt.targetHw)
			}
			if normalize(o) != normalize(tt.other) {
				t.Errorf("other = %q, want %q", o, tt.other)
			}
		})
	}
}

func TestQuoteForWFN(t *testing.T) {
	tests := []struct {
		value    string
		expected string
	}{
		{ValueANY, ValueANY},
		{ValueNA, ValueNA},
		{"windows", "windows"},
		{`value"with"quotes`, `value\"with\"quotes`},
		{`escaped\\backslash`, `escaped\\backslash`}, // backslash followed by another char stays as-is
		{`just_a_value`, `just_a_value`},
		{`value"only`, `value\"only`},
		{"", ""}, // empty string is not a logical value, so it passes through
	}

	for _, tt := range tests {
		if got := quoteForWFN(tt.value); got != tt.expected {
			t.Errorf("quoteForWFN(%q) = %q, want %q", tt.value, got, tt.expected)
		}
	}
}

func TestUnquoteFromWFN(t *testing.T) {
	tests := []struct {
		value    string
		expected string
	}{
		{`value\"with\"quotes`, `value"with"quotes`},
		{`escaped\\backslash`, `escaped\backslash`},
		{`windows`, "windows"},
	}

	for _, tt := range tests {
		if got := unquoteFromWFN(tt.value); got != tt.expected {
			t.Errorf("unquoteFromWFN(%q) = %q, want %q", tt.value, got, tt.expected)
		}
	}
}

func TestEscapeValueBackwardCompat(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"simple value", "windows", "windows"},
		{"dot escaped", "example.com", "example\\.com"},
		{"hyphen escaped", "service-pack", "service\\-pack"},
		{"underscore escaped", "red_hat", "red\\_hat"},
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"colon encoded", "product:name", "product%3aname"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeValue(tt.value); got != tt.expected {
				t.Errorf("escapeValue(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestUnescapeValueBackwardCompat(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"simple value", "windows", "windows"},
		{"dot unescaped", "example\\.com", "example.com"},
		{"hyphen unescaped", "service\\-pack", "service-pack"},
		{"underscore unescaped", "red\\_hat", "red_hat"},
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"colon decoded", "product%3aname", "product:name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unescapeValue(tt.value); got != tt.expected {
				t.Errorf("unescapeValue(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestEscapeCpe22ValueBackwardCompat(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"simple value", "windows", "windows"},
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"dot encoded", "example.com", "example%2ecom"},
		{"colon encoded", "product:name", "product%3aname"},
		{"slash encoded", "a/b", "a%2fb"},
		{"tilde encoded", "version~rc1", "version%7erc1"},
		{"hyphen encoded", "service-pack", "service%2dpack"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeCpe22Value(tt.value); got != tt.expected {
				t.Errorf("escapeCpe22Value(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestUnescapeCpe22ValueBackwardCompat(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"simple value", "windows", "windows"},
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"dot decoded", "example%2ecom", "example.com"},
		{"colon decoded", "product%3aname", "product:name"},
		{"slash decoded", "a%2fb", "a/b"},
		{"tilde decoded", "version%7erc1", "version~rc1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unescapeCpe22Value(tt.value); got != tt.expected {
				t.Errorf("unescapeCpe22Value(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestToHex(t *testing.T) {
	tests := []struct {
		char     byte
		expected string
	}{
		{' ', "20"},
		{'\t', "09"},
		{'\n', "0a"},
		{0x00, "00"},
		{0xff, "ff"},
		{0x1f, "1f"},
		{'?', "3f"},
	}

	for _, tt := range tests {
		if got := toHex(tt.char); got != tt.expected {
			t.Errorf("toHex(%d) = %q, want %q", tt.char, got, tt.expected)
		}
	}
}

func TestEscapeValueForCpe22(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"simple value", "windows", "windows"},
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"dot encoded", "example.com", "example%2ecom"},
		{"colon encoded", "product:name", "product%3aname"},
		{"hyphen encoded", "service-pack", "service%2dpack"},
		{"underscore encoded", "red_hat", "red%5fhat"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeValueForCpe22(tt.value); got != tt.expected {
				t.Errorf("escapeValueForCpe22(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestUnescapeValueForCpe22(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"simple value", "windows", "windows"},
		{"logical ANY", ValueANY, ValueANY},
		{"logical NA", ValueNA, ValueNA},
		{"empty string", "", ""},
		{"dot decoded", "example%2ecom", "example.com"},
		{"colon decoded", "product%3aname", "product:name"},
		{"hyphen decoded", "service%2dpack", "service-pack"},
		{"underscore decoded", "red%5fhat", "red_hat"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unescapeValueForCpe22(tt.value); got != tt.expected {
				t.Errorf("unescapeValueForCpe22(%q) = %q, want %q", tt.value, got, tt.expected)
			}
		})
	}
}

func TestUnescapeFromURIPercentUnknown(t *testing.T) {
	// Test with a percent-encoding that is not in our known map
	result := unescapeFromURI("test%zzvalue")
	// %zz is not a known encoding, so it should be preserved as-is
	if result != "test%zzvalue" {
		t.Errorf("unescapeFromURI with unknown percent encoding = %q, want %q", result, "test%zzvalue")
	}
}

func TestEscapeForURIUnknownCharNotInMap(t *testing.T) {
	// Test the else branch in escapeForURI where a character is not alphanumeric
	// and not in the quotedCharToPercentEncode map - it uses toHex
	// Space character is not in the map, so it should be percent-encoded via toHex
	result := escapeForURI("hello world")
	if result != "hello%20world" {
		t.Errorf("escapeForURI with space = %q, want %q", result, "hello%20world")
	}

	// Tab character
	result = escapeForURI("hello\tworld")
	if result != "hello%09world" {
		t.Errorf("escapeForURI with tab = %q, want %q", result, "hello%09world")
	}

	// Backslash followed by non-alphanumeric not in map (space)
	result = escapeForURI(`\ `)
	// Backslash encoded as %5c, then space uses toHex -> %20
	if result != "%5c%20" {
		t.Errorf("escapeForURI with backslash+space = %q, want %q", result, "%5c%20")
	}
}

func TestEscapeForFSWithBackslash(t *testing.T) {
	// Test that backslash is passed through as-is in escapeForFS
	result := escapeForFS(`test\value`)
	if result != `test\value` {
		t.Errorf("escapeForFS with backslash = %q, want %q", result, `test\value`)
	}
}

func TestEscapeForFSWithUnknownSpecialChar(t *testing.T) {
	// Test that a special character not in the quotedCharToPercentEncode map
	// is passed through as-is (line 98 in escapeForFS)
	// Space is not in the map
	result := escapeForFS("hello world")
	if result != "hello world" {
		t.Errorf("escapeForFS with space = %q, want %q", result, "hello world")
	}
}

func TestUnescapeFromFSWithTrailingBackslash(t *testing.T) {
	// Test unescaping with a trailing backslash (incomplete escape)
	result := unescapeFromFS(`test\`)
	if result != `test\` {
		t.Errorf("unescapeFromFS with trailing backslash = %q, want %q", result, `test\`)
	}
}

func TestUnescapeFromFSWithUnknownPercent(t *testing.T) {
	// Test unescaping with an unknown percent-encoding
	result := unescapeFromFS("test%zzvalue")
	if result != "test%zzvalue" {
		t.Errorf("unescapeFromFS with unknown percent = %q, want %q", result, "test%zzvalue")
	}
}
