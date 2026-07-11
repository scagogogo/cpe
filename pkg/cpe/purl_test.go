package cpeskills

import (
	"testing"
)

func TestParsePURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *PackageURL
		wantErr bool
	}{
		{
			name:  "basic npm",
			input: "pkg:npm/express@4.17.1",
			want:  NewPURL("npm", "", "express", "4.17.1"),
		},
		{
			name:  "npm with scope",
			input: "pkg:npm/%40angular/core@14.0.0",
			want:  NewPURL("npm", "@angular", "core", "14.0.0"),
		},
		{
			name:  "maven with namespace",
			input: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			want:  NewPURL("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"),
		},
		{
			name:  "pypi",
			input: "pkg:pypi/django@4.2.0",
			want:  NewPURL("pypi", "", "django", "4.2.0"),
		},
		{
			name:  "golang",
			input: "pkg:golang/github.com/gin-gonic/gin@1.9.0",
			want:  NewPURL("golang", "github.com", "gin-gonic/gin", "1.9.0"),
		},
		{
			name:  "nuget",
			input: "pkg:nuget/Newtonsoft.Json@13.0.1",
			want:  NewPURL("nuget", "", "Newtonsoft.Json", "13.0.1"),
		},
		{
			name:  "docker",
			input: "pkg:docker/library/nginx@1.21",
			want:  NewPURL("docker", "library", "nginx", "1.21"),
		},
		{
			name:  "with qualifiers",
			input: "pkg:npm/express@4.17.1?arch=x64&os=linux",
			want: &PackageURL{
				Type:       "npm",
				Name:       "express",
				Version:    "4.17.1",
				Qualifiers: map[string]string{"arch": "x64", "os": "linux"},
			},
		},
		{
			name:  "with subpath",
			input: "pkg:npm/express@4.17.1#dist/main.js",
			want: &PackageURL{
				Type:    "npm",
				Name:    "express",
				Version: "4.17.1",
				Subpath: "dist/main.js",
			},
		},
		{
			name:  "no version",
			input: "pkg:npm/express",
			want:  NewPURL("npm", "", "express", ""),
		},
		{
			name:  "cargo",
			input: "pkg:cargo/serde@1.0.0",
			want:  NewPURL("cargo", "", "serde", "1.0.0"),
		},
		{
			name:  "composer",
			input: "pkg:composer/laravel/framework@10.0.0",
			want:  NewPURL("composer", "laravel", "framework", "10.0.0"),
		},
		{
			name:  "gem",
			input: "pkg:gem/rails@7.0.0",
			want:  NewPURL("gem", "", "rails", "7.0.0"),
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "no scheme",
			input:   "npm/express@4.17.1",
			wantErr: true,
		},
		{
			name:    "missing name",
			input:   "pkg:npm",
			wantErr: true,
		},
		{
			name:    "empty type",
			input:   "pkg:/name@1.0",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePURL(%q): expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParsePURL(%q): unexpected error: %v", tt.input, err)
				return
			}
			if got.Type != tt.want.Type {
				t.Errorf("Type: expected %q, got %q", tt.want.Type, got.Type)
			}
			if got.Namespace != tt.want.Namespace {
				t.Errorf("Namespace: expected %q, got %q", tt.want.Namespace, got.Namespace)
			}
			if got.Name != tt.want.Name {
				t.Errorf("Name: expected %q, got %q", tt.want.Name, got.Name)
			}
			if got.Version != tt.want.Version {
				t.Errorf("Version: expected %q, got %q", tt.want.Version, got.Version)
			}
			if got.Subpath != tt.want.Subpath {
				t.Errorf("Subpath: expected %q, got %q", tt.want.Subpath, got.Subpath)
			}
			if len(got.Qualifiers) != len(tt.want.Qualifiers) {
				t.Errorf("Qualifiers length: expected %d, got %d", len(tt.want.Qualifiers), len(got.Qualifiers))
			}
			for k, v := range tt.want.Qualifiers {
				if gv, ok := got.Qualifiers[k]; !ok || gv != v {
					t.Errorf("Qualifier %q: expected %q, got %q", k, v, gv)
				}
			}
		})
	}
}

func TestPackageURL_String(t *testing.T) {
	tests := []struct {
		name string
		purl *PackageURL
		want string
	}{
		{
			name: "basic npm",
			purl: NewPURL("npm", "", "express", "4.17.1"),
			want: "pkg:npm/express@4.17.1",
		},
		{
			name: "maven",
			purl: NewPURL("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"),
			want: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		},
		{
			name: "no version",
			purl: NewPURL("npm", "", "lodash", ""),
			want: "pkg:npm/lodash",
		},
		{
			name: "with qualifiers",
			purl: &PackageURL{
				Type:       "npm",
				Name:       "express",
				Version:    "4.17.1",
				Qualifiers: map[string]string{"arch": "x64", "os": "linux"},
			},
			want: "pkg:npm/express@4.17.1?arch=x64&os=linux",
		},
		{
			name: "with subpath",
			purl: &PackageURL{
				Type:    "npm",
				Name:    "express",
				Version: "4.17.1",
				Subpath: "dist/main.js",
			},
			want: "pkg:npm/express@4.17.1#dist/main.js",
		},
		{
			name: "nil",
			purl: nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.purl.String()
			if got != tt.want {
				t.Errorf("String(): expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestParsePURL_RoundTrip(t *testing.T) {
	inputs := []string{
		"pkg:npm/express@4.17.1",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		"pkg:pypi/django@4.2.0",
		"pkg:golang/github.com/gin-gonic/gin@1.9.0",
		"pkg:nuget/Newtonsoft.Json@13.0.1",
		"pkg:docker/library/nginx@1.21",
		"pkg:cargo/serde@1.0.0",
		"pkg:composer/laravel/framework@10.0.0",
		"pkg:gem/rails@7.0.0",
		"pkg:npm/express@4.17.1?arch=x64&os=linux",
		"pkg:npm/express@4.17.1#dist/main.js",
	}

	for _, input := range inputs {
		purl, err := ParsePURL(input)
		if err != nil {
			t.Errorf("ParsePURL(%q): unexpected error: %v", input, err)
			continue
		}
		output := purl.String()
		// 重新解析输出，验证一致性
		purl2, err := ParsePURL(output)
		if err != nil {
			t.Errorf("re-parse(%q): unexpected error: %v", output, err)
			continue
		}
		if !purl.Equals(purl2) {
			t.Errorf("round-trip mismatch for %q: %+v vs %+v", input, purl, purl2)
		}
	}
}

func TestPackageURL_IsValid(t *testing.T) {
	tests := []struct {
		purl *PackageURL
		want bool
	}{
		{NewPURL("npm", "", "express", "4.17.1"), true},
		{NewPURL("", "", "express", "4.17.1"), false},
		{NewPURL("npm", "", "", "4.17.1"), false},
		{nil, false},
	}
	for _, tt := range tests {
		got := tt.purl.IsValid()
		if got != tt.want {
			t.Errorf("IsValid() for %v: expected %v, got %v", tt.purl, tt.want, got)
		}
	}
}

func TestPackageURL_Ecosystem(t *testing.T) {
	purl := NewPURL("npm", "", "express", "4.17.1")
	if purl.Ecosystem() != EcosystemNPM {
		t.Errorf("expected EcosystemNPM, got %s", purl.Ecosystem())
	}

	purl = NewPURL("maven", "org.apache", "log4j", "2.14.1")
	if purl.Ecosystem() != EcosystemMaven {
		t.Errorf("expected EcosystemMaven, got %s", purl.Ecosystem())
	}

	var nilPurl *PackageURL
	if nilPurl.Ecosystem() != EcosystemGeneric {
		t.Errorf("expected EcosystemGeneric for nil PURL")
	}
}

func TestPackageURL_FullName(t *testing.T) {
	tests := []struct {
		purl *PackageURL
		want string
	}{
		{NewPURL("npm", "", "express", "4.17.1"), "express"},
		{NewPURL("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"), "org.apache.logging.log4j/log4j-core"},
		{NewPURL("npm", "@angular", "core", "14.0.0"), "@angular/core"},
		{nil, ""},
	}
	for _, tt := range tests {
		got := tt.purl.FullName()
		if got != tt.want {
			t.Errorf("FullName(): expected %q, got %q", tt.want, got)
		}
	}
}

func TestPackageURL_Copy(t *testing.T) {
	original := &PackageURL{
		Type:       "npm",
		Namespace:  "@scope",
		Name:       "pkg",
		Version:    "1.0.0",
		Qualifiers: map[string]string{"arch": "x64"},
		Subpath:    "dist/index.js",
	}
	cp := original.Copy()
	if !original.Equals(cp) {
		t.Error("copy should equal original")
	}
	// 修改 copy 不应影响 original
	cp.Version = "2.0.0"
	if original.Version == "2.0.0" {
		t.Error("modifying copy should not affect original")
	}
}

func TestPackageURL_WithoutVersion(t *testing.T) {
	purl := NewPURL("npm", "", "express", "4.17.1")
	noVer := purl.WithoutVersion()
	if noVer.Version != "" {
		t.Errorf("expected empty version, got %q", noVer.Version)
	}
	if noVer.Name != "express" {
		t.Errorf("expected name 'express', got %q", noVer.Name)
	}
}

func TestPackageURL_WithVersion(t *testing.T) {
	purl := NewPURL("npm", "", "express", "")
	withVer := purl.WithVersion("5.0.0")
	if withVer.Version != "5.0.0" {
		t.Errorf("expected version '5.0.0', got %q", withVer.Version)
	}
}

func TestPackageURL_Equals(t *testing.T) {
	a := NewPURL("npm", "", "express", "4.17.1")
	b := NewPURL("npm", "", "express", "4.17.1")
	c := NewPURL("npm", "", "express", "4.17.2")
	d := NewPURL("npm", "", "lodash", "4.17.1")

	if !a.Equals(b) {
		t.Error("identical PURLs should be equal")
	}
	if a.Equals(c) {
		t.Error("different versions should not be equal")
	}
	if a.Equals(d) {
		t.Error("different names should not be equal")
	}
	if a.Equals(nil) {
		t.Error("should not equal nil")
	}

	var nilA, nilB *PackageURL
	if !nilA.Equals(nilB) {
		t.Error("two nil PURLs should be equal")
	}
}

func TestNewPURLWithEcosystem(t *testing.T) {
	purl, err := NewPURLWithEcosystem(EcosystemNPM, "@scope", "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if purl.Type != "npm" {
		t.Errorf("expected type 'npm', got %q", purl.Type)
	}
	if purl.Namespace != "@scope" {
		t.Errorf("expected namespace '@scope', got %q", purl.Namespace)
	}

	_, err = NewPURLWithEcosystem(Ecosystem("nonexistent"), "", "pkg", "1.0.0")
	if err == nil {
		t.Error("expected error for unknown ecosystem")
	}
}

func TestParsePURL_EdgeCases(t *testing.T) {
	// 带有特殊字符的版本号
	purl, err := ParsePURL("pkg:npm/pkg@1.0.0-beta.1+build.123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if purl.Version != "1.0.0-beta.1+build.123" {
		t.Errorf("expected version with special chars, got %q", purl.Version)
	}

	// 空的 qualifiers
	purl, err = ParsePURL("pkg:npm/pkg@1.0.0?")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(purl.Qualifiers) != 0 {
		t.Errorf("expected empty qualifiers, got %v", purl.Qualifiers)
	}

	// 多级命名空间
	purl, err = ParsePURL("pkg:maven/com.example.group/artifact@1.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if purl.Namespace != "com.example.group" {
		t.Errorf("expected namespace 'com.example.group', got %q", purl.Namespace)
	}
}
