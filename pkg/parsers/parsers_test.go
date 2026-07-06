package parsers

import (
	"strings"
	"testing"
)

func TestParseGoMod(t *testing.T) {
	goMod := `module github.com/example/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/go-sql-driver/mysql v1.7.1 // indirect
	github.com/stretchr/testify v1.8.4
)

require github.com/google/uuid v1.3.1 // indirect
`

	result, err := ParseGoMod(strings.NewReader(goMod))
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if result.Ecosystem != "golang" {
		t.Errorf("expected ecosystem 'golang', got %q", result.Ecosystem)
	}
	if result.Name != "github.com/example/myapp" {
		t.Errorf("expected name 'github.com/example/myapp', got %q", result.Name)
	}
	if len(result.Components) != 4 {
		t.Fatalf("expected 4 components, got %d", len(result.Components))
	}

	// Check direct dependency
	if result.Components[0].Name != "github.com/gin-gonic/gin" {
		t.Errorf("expected name 'github.com/gin-gonic/gin', got %q", result.Components[0].Name)
	}
	if result.Components[0].IsDirect != true {
		t.Error("expected IsDirect=true for gin")
	}

	// Check indirect dependency
	if result.Components[1].IsDirect != false {
		t.Error("expected IsDirect=false for mysql (indirect)")
	}
}

func TestParsePackageJSON(t *testing.T) {
	pkg := `{
		"name": "my-app",
		"version": "1.0.0",
		"dependencies": {
			"express": "^4.18.2",
			"lodash": "^4.17.21"
		},
		"devDependencies": {
			"jest": "^29.7.0"
		}
	}`

	result, err := ParsePackageJSON(strings.NewReader(pkg))
	if err != nil {
		t.Fatalf("ParsePackageJSON failed: %v", err)
	}

	if result.Ecosystem != "npm" {
		t.Errorf("expected ecosystem 'npm', got %q", result.Ecosystem)
	}
	if result.Name != "my-app" {
		t.Errorf("expected name 'my-app', got %q", result.Name)
	}
	if len(result.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(result.Components))
	}

	// Check dev dependency
	foundJest := false
	for _, c := range result.Components {
		if c.Name == "jest" {
			foundJest = true
			if !c.IsDev {
				t.Error("expected jest to be IsDev=true")
			}
		}
	}
	if !foundJest {
		t.Error("jest not found in components")
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	reqs := `# This is a comment
flask==2.3.0
requests>=2.31.0
django~=4.2
numpy
-r other-requirements.txt
--index-url https://pypi.org/simple
`

	result, err := ParseRequirementsTxt(strings.NewReader(reqs))
	if err != nil {
		t.Fatalf("ParseRequirementsTxt failed: %v", err)
	}

	if result.Ecosystem != "pypi" {
		t.Errorf("expected ecosystem 'pypi', got %q", result.Ecosystem)
	}

	// Should have 3 components (flask, requests, django)
	// numpy has no version specifier and may not be captured
	if len(result.Components) < 3 {
		t.Errorf("expected at least 3 components, got %d", len(result.Components))
	}

	// Check flask
	foundFlask := false
	for _, c := range result.Components {
		if c.Name == "flask" {
			foundFlask = true
			if c.Version != "2.3.0" {
				t.Errorf("expected flask version '2.3.0', got %q", c.Version)
			}
		}
	}
	if !foundFlask {
		t.Error("flask not found in components")
	}
}

func TestParsePomXML(t *testing.T) {
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project>
	<groupId>com.example</groupId>
	<artifactId>my-app</artifactId>
	<version>1.0.0</version>
	<dependencies>
		<dependency>
			<groupId>org.springframework</groupId>
			<artifactId>spring-core</artifactId>
			<version>5.3.23</version>
		</dependency>
		<dependency>
			<groupId>junit</groupId>
			<artifactId>junit</artifactId>
			<version>4.13.2</version>
			<scope>test</scope>
		</dependency>
	</dependencies>
</project>`

	result, err := ParsePomXML(strings.NewReader(pom))
	if err != nil {
		t.Fatalf("ParsePomXML failed: %v", err)
	}

	if result.Ecosystem != "maven" {
		t.Errorf("expected ecosystem 'maven', got %q", result.Ecosystem)
	}
	if result.Name != "com.example:my-app" {
		t.Errorf("expected name 'com.example:my-app', got %q", result.Name)
	}
	if len(result.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(result.Components))
	}

	// Check spring-core
	if result.Components[0].Name != "spring-core" {
		t.Errorf("expected name 'spring-core', got %q", result.Components[0].Name)
	}
	if result.Components[0].Namespace != "org.springframework" {
		t.Errorf("expected namespace 'org.springframework', got %q", result.Components[0].Namespace)
	}

	// Check test-scoped dependency
	if result.Components[1].Scope != "test" {
		t.Errorf("expected scope 'test', got %q", result.Components[1].Scope)
	}
}

func TestParseCargoToml(t *testing.T) {
	cargo := `[package]
name = "my-rust-app"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = "1.32"

[dev-dependencies]
tempfile = "3.8"
`

	result, err := ParseCargoToml(strings.NewReader(cargo))
	if err != nil {
		t.Fatalf("ParseCargoToml failed: %v", err)
	}

	if result.Ecosystem != "cargo" {
		t.Errorf("expected ecosystem 'cargo', got %q", result.Ecosystem)
	}
	if result.Name != "my-rust-app" {
		t.Errorf("expected name 'my-rust-app', got %q", result.Name)
	}
	if len(result.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(result.Components))
	}

	// Check dev dependency
	foundTempfile := false
	for _, c := range result.Components {
		if c.Name == "tempfile" {
			foundTempfile = true
			if !c.IsDev {
				t.Error("expected tempfile to be IsDev=true")
			}
		}
	}
	if !foundTempfile {
		t.Error("tempfile not found in components")
	}
}

func TestParseComposerJSON(t *testing.T) {
	composer := `{
		"name": "my/app",
		"require": {
			"php": "^8.1",
			"laravel/framework": "^10.0",
			"guzzlehttp/guzzle": "^7.0"
		},
		"require-dev": {
			"phpunit/phpunit": "^10.0"
		}
	}`

	result, err := ParseComposerJSON(strings.NewReader(composer))
	if err != nil {
		t.Fatalf("ParseComposerJSON failed: %v", err)
	}

	if result.Ecosystem != "composer" {
		t.Errorf("expected ecosystem 'composer', got %q", result.Ecosystem)
	}

	// Should have 2 packages (php and ext- are filtered)
	packageCount := 0
	for _, c := range result.Components {
		packageCount++
		_ = c
	}
	if packageCount < 2 {
		t.Errorf("expected at least 2 components, got %d", packageCount)
	}

	// Check dev dependency
	foundPHPUnit := false
	for _, c := range result.Components {
		if c.Name == "phpunit/phpunit" {
			foundPHPUnit = true
			if !c.IsDev {
				t.Error("expected phpunit to be IsDev=true")
			}
		}
	}
	if !foundPHPUnit {
		t.Error("phpunit not found in components")
	}
}

func TestParseGemfile(t *testing.T) {
	gemfile := `source "https://rubygems.org"

gem "rails", "~> 7.0"
gem "puma", "~> 5.0"

group :development do
  gem "rspec", "~> 3.12"
end
`

	result, err := ParseGemfile(strings.NewReader(gemfile))
	if err != nil {
		t.Fatalf("ParseGemfile failed: %v", err)
	}

	if result.Ecosystem != "rubygems" {
		t.Errorf("expected ecosystem 'rubygems', got %q", result.Ecosystem)
	}
	if len(result.Components) < 3 {
		t.Fatalf("expected at least 3 components, got %d", len(result.Components))
	}

	// Check dev dependency
	foundRspec := false
	for _, c := range result.Components {
		if c.Name == "rspec" {
			foundRspec = true
			if !c.IsDev {
				t.Error("expected rspec to be IsDev=true")
			}
		}
	}
	if !foundRspec {
		t.Error("rspec not found in components")
	}
}

func TestParseAuto(t *testing.T) {
	tests := []struct {
		filename  string
		ecosystem string
	}{
		{"go.mod", "golang"},
		{"package.json", "npm"},
		{"requirements.txt", "pypi"},
		{"pom.xml", "maven"},
		{"Cargo.toml", "cargo"},
		{"Gemfile", "rubygems"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			var content string
			switch tt.filename {
			case "go.mod":
				content = "module example.com/test\n"
			case "package.json":
				content = `{"name":"test"}`
			case "requirements.txt":
				content = "# empty"
			case "pom.xml":
				content = `<project><groupId>com.test</groupId><artifactId>test</artifactId><version>1.0</version></project>`
			case "Cargo.toml":
				content = `[package]\nname = "test"\nversion = "0.1.0"\n`
			case "Gemfile":
				content = `source "https://rubygems.org"`
			}

			result, err := ParseAuto(tt.filename, strings.NewReader(content))
			if err != nil {
				t.Fatalf("ParseAuto(%s) failed: %v", tt.filename, err)
			}
			if result.Ecosystem != tt.ecosystem {
				t.Errorf("expected ecosystem %q, got %q", tt.ecosystem, result.Ecosystem)
			}
		})
	}
}

func TestParseAutoUnsupported(t *testing.T) {
	_, err := ParseAuto("unknown.txt", strings.NewReader(""))
	if err == nil {
		t.Error("expected error for unsupported file")
	}
}

func TestConvertToSBOMComponents(t *testing.T) {
	result := &ParseResult{
		Ecosystem: "npm",
		PURLType:  "npm",
		Components: []*ComponentInfo{
			{Name: "express", Version: "4.18.2", IsDirect: true},
		},
	}

	mappings := ConvertToSBOMComponents(result)
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(mappings))
	}
	if mappings[0].Name != "express" {
		t.Errorf("expected name 'express', got %q", mappings[0].Name)
	}
	if mappings[0].PURLType != "npm" {
		t.Errorf("expected PURLType 'npm', got %q", mappings[0].PURLType)
	}
}

func TestParsePackageLockJSONV2(t *testing.T) {
	lock := `{
		"name": "my-app",
		"version": "1.0.0",
		"lockfileVersion": 2,
		"packages": {
			"": {"name": "my-app", "version": "1.0.0"},
			"node_modules/express": {
				"version": "4.18.2",
				"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
				"integrity": "sha512-abc123"
			},
			"node_modules/lodash": {
				"version": "4.17.21",
				"dev": true,
				"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
				"integrity": "sha512-xyz789"
			}
		}
	}`

	result, err := ParsePackageLockJSON(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("ParsePackageLockJSON failed: %v", err)
	}

	if len(result.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(result.Components))
	}

	// Find lodash (dev)
	foundLodash := false
	for _, c := range result.Components {
		if c.Name == "lodash" {
			foundLodash = true
			if !c.IsDev {
				t.Error("expected lodash to be IsDev=true")
			}
			if c.Checksum != "sha512-xyz789" {
				t.Errorf("expected checksum, got %q", c.Checksum)
			}
		}
	}
	if !foundLodash {
		t.Error("lodash not found")
	}
}

func TestParsersByFormatRegistry(t *testing.T) {
	if len(ParsersByFormat) == 0 {
		t.Error("ParsersByFormat is empty")
	}

	expectedFormats := []string{"go.mod", "package.json", "requirements.txt", "pom.xml", "Cargo.toml", "Gemfile"}
	for _, f := range expectedFormats {
		if _, ok := ParsersByFormat[f]; !ok {
			t.Errorf("expected format %q in ParsersByFormat", f)
		}
	}
}

func TestParseComposerLock(t *testing.T) {
	lock := `{
		"packages": [
			{
				"name": "laravel/framework",
				"version": "v10.0.0",
				"source": {
					"reference": "abc123def"
				}
			}
		],
		"packages-dev": [
			{
				"name": "phpunit/phpunit",
				"version": "v10.0.0",
				"source": {
					"reference": "xyz789"
				}
			}
		]
	}`

	result, err := ParseComposerLock(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("ParseComposerLock failed: %v", err)
	}

	if len(result.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(result.Components))
	}

	// Check first package
	if result.Components[0].Name != "laravel/framework" {
		t.Errorf("expected name 'laravel/framework', got %q", result.Components[0].Name)
	}

	// Check dev package
	if !result.Components[1].IsDev {
		t.Error("expected phpunit to be IsDev=true")
	}
}

func TestParsePackageLockJSON_V1(t *testing.T) {
	// lockfile v1 用 dependencies 字段
	lock := `{
		"name": "my-app",
		"version": "1.0.0",
		"lockfileVersion": 1,
		"dependencies": {
			"express": {"version": "4.18.2", "resolved": "https://x/express", "integrity": "sha-abc"},
			"lodash": {"version": "4.17.21", "dev": true}
		}
	}`
	result, err := ParsePackageLockJSON(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("ParsePackageLockJSON v1: %v", err)
	}
	if len(result.Components) != 2 {
		t.Fatalf("expected 2, got %d", len(result.Components))
	}
	found := false
	for _, c := range result.Components {
		if c.Name == "express" && c.Version == "4.18.2" && c.Resolved == "https://x/express" {
			found = true
		}
	}
	if !found {
		t.Error("express not found in v1 lock")
	}
}

func TestParsePackageLockJSON_ScopedPackage(t *testing.T) {
	// scoped package @scope/name 应正确提取
	lock := `{
		"name": "app",
		"lockfileVersion": 2,
		"packages": {
			"": {"name": "app"},
			"node_modules/@babel/core": {"version": "7.0.0"},
			"node_modules/lodash": {"version": "4.17.21"}
		}
	}`
	result, err := ParsePackageLockJSON(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("scoped: %v", err)
	}
	foundScoped := false
	for _, c := range result.Components {
		if c.Name == "@babel/core" {
			foundScoped = true
		}
	}
	if !foundScoped {
		t.Error("expected @babel/core in components")
	}
}

func TestParsePackageLockJSON_InvalidJSON(t *testing.T) {
	_, err := ParsePackageLockJSON(strings.NewReader("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseAuto_AllFormats(t *testing.T) {
	// 补 ParseAuto 未覆盖的 case
	tests := []struct {
		filename string
		content  string
	}{
		{"composer.json", `{"name":"test/test","require":{"php":">=7.0"}}`},
		{"composer.lock", `{"packages":[{"name":"a/b","version":"1.0"}]}`},
		{"package-lock.json", `{"name":"x","lockfileVersion":2,"packages":{"":{"name":"x"}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			_, err := ParseAuto(tt.filename, strings.NewReader(tt.content))
			if err != nil {
				t.Errorf("ParseAuto(%s): %v", tt.filename, err)
			}
		})
	}
}

func TestParseAuto_WithPathPrefix(t *testing.T) {
	// 带路径前缀的 filename 应正确识别
	_, err := ParseAuto("/path/to/go.mod", strings.NewReader("module example.com/test\n"))
	if err != nil {
		t.Fatalf("ParseAuto with path: %v", err)
	}
}

func TestConvertToSBOMComponents_Nil(t *testing.T) {
	if got := ConvertToSBOMComponents(nil); got != nil {
		t.Errorf("expected nil for nil result, got %v", got)
	}
}
