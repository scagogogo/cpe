package cpeskills

import (
	"testing"
)

// 本文件补充 ecosystem.go 与 cpe_purl_mapping.go 的未覆盖分支：
// NormalizeEcosystemName 的剩余 alias case、inferEcosystem 的 product 启发式、
// inferVendorProductFromPURL 的各 ecosystem case、buildPURLFromCPE 错误路径。

// ---- NormalizeEcosystemName：补已有测试未覆盖的 alias case ----

func TestNormalizeEcosystemName_MoreAliases(t *testing.T) {
	cases := map[string]Ecosystem{
		"node":       EcosystemNPM,
		"java":       EcosystemMaven,
		"kotlin":     EcosystemMaven,
		"pip":        EcosystemPyPI,
		"python":     EcosystemPyPI,
		"go modules": EcosystemGo,
		"csharp":     EcosystemNuGet,
		".net":       EcosystemNuGet,
		"container":  EcosystemDocker,
		"oci":        EcosystemDocker,
		"ruby":       EcosystemRubyGems,
		"gem":        EcosystemRubyGems,
		"php":        EcosystemComposer,
		"c++":        EcosystemConan,
		"cpp":        EcosystemConan,
		"c":          EcosystemConan,
		"anaconda":   EcosystemConda,
		"elixir":     EcosystemHex,
		"erlang":     EcosystemHex,
		"dart":       EcosystemPub,
		"flutter":    EcosystemPub,
		"swiftpm":    EcosystemSwift,
		"swift":      EcosystemSwift,
		"apk":        EcosystemAlpine,
		"alpine":     EcosystemAlpine,
		"deb":        EcosystemDebian,
		"ubuntu":     EcosystemDebian,
		"debian":     EcosystemDebian,
		"redhat":     EcosystemRPM,
		"fedora":     EcosystemRPM,
		"centos":     EcosystemRPM,
		"rpm":        EcosystemRPM,
		"other":      EcosystemGeneric,
		"unknown":    EcosystemGeneric,
	}
	for name, want := range cases {
		eco, err := NormalizeEcosystemName(name)
		if err != nil {
			t.Errorf("NormalizeEcosystemName(%q): unexpected error: %v", name, err)
			continue
		}
		if eco != want {
			t.Errorf("NormalizeEcosystemName(%q): expected %s, got %s", name, want, eco)
		}
	}
}

func TestNormalizeEcosystemName_DirectConstantMatch(t *testing.T) {
	// default 分支：直接匹配 Ecosystem 常量名
	eco, err := NormalizeEcosystemName(string(EcosystemNPM))
	if err != nil || eco != EcosystemNPM {
		t.Errorf("direct constant match failed: eco=%s err=%v", eco, err)
	}
}

// ---- inferEcosystem：补 product 启发式分支 ----

func TestInferEcosystem_ProductHeuristics(t *testing.T) {
	cases := []struct {
		vendor, product string
		want            Ecosystem
	}{
		{"unknown_vendor", "npm-foo", EcosystemNPM},
		{"unknown_vendor", "node-bar", EcosystemNPM},
		{"unknown_vendor", "python-foo", EcosystemPyPI},
		{"unknown_vendor", "python_bar", EcosystemPyPI},
		{"unknown_vendor", "go-foo", EcosystemGo},
		{"unknown_vendor", "foo-go-module", EcosystemGo},
		{"unknown_vendor", "foonuget", EcosystemNuGet},
		{"unknown_vendor", "dotnet-foo", EcosystemNuGet},
	}
	for _, tt := range cases {
		eco, _ := inferEcosystem(tt.vendor, tt.product)
		if eco != tt.want {
			t.Errorf("inferEcosystem(%q,%q): expected %s, got %s", tt.vendor, tt.product, tt.want, eco)
		}
	}
}

// ---- inferVendorProductFromPURL：各 ecosystem case ----

func TestInferVendorProductFromPURL_AllEcosystems(t *testing.T) {
	maven := NewPURL("maven", "org.apache", "log4j", "2.14")
	v, p := inferVendorProductFromPURL(maven, EcosystemMaven)
	if v != "org" || p != "log4j" {
		t.Errorf("maven: vendor=%q product=%q", v, p)
	}

	// Maven 无 namespace
	mavenNoNS := NewPURL("maven", "", "log4j", "2.14")
	v, _ = inferVendorProductFromPURL(mavenNoNS, EcosystemMaven)
	if v != "unknown" {
		t.Errorf("maven no-ns: vendor=%q", v)
	}

	// NPM 带 scope
	npmScoped := NewPURL("npm", "@scope", "pkg", "1.0")
	v, _ = inferVendorProductFromPURL(npmScoped, EcosystemNPM)
	if v != "scope" {
		t.Errorf("npm scoped: vendor=%q", v)
	}

	// NPM 无 scope、name 含 /
	npmSlash := &PackageURL{Type: "npm", Name: "scope/pkg"}
	v, p = inferVendorProductFromPURL(npmSlash, EcosystemNPM)
	if v != "scope" || p != "pkg" {
		t.Errorf("npm slash: vendor=%q product=%q", v, p)
	}

	// NPM 无 scope、单 name
	npmSimple := NewPURL("npm", "", "express", "1.0")
	v, p = inferVendorProductFromPURL(npmSimple, EcosystemNPM)
	if v != "npm" || p != "express" {
		t.Errorf("npm simple: vendor=%q product=%q", v, p)
	}

	// Go name 含多段
	goP := &PackageURL{Type: "go", Name: "github.com/gin-gonic/gin"}
	v, p = inferVendorProductFromPURL(goP, EcosystemGo)
	if v != "github.com" || p != "gin" {
		t.Errorf("go multi: vendor=%q product=%q", v, p)
	}

	// Go 单段
	goSingle := &PackageURL{Type: "go", Name: "gin"}
	v, p = inferVendorProductFromPURL(goSingle, EcosystemGo)
	if v != "golang" || p != "gin" {
		t.Errorf("go single: vendor=%q product=%q", v, p)
	}

	// PyPI
	pypi := NewPURL("pypi", "", "django", "4.0")
	v, p = inferVendorProductFromPURL(pypi, EcosystemPyPI)
	if v != "python" || p != "django" {
		t.Errorf("pypi: vendor=%q product=%q", v, p)
	}

	// NuGet 有 namespace
	nugetNS := NewPURL("nuget", "microsoft", "aspnet", "6.0")
	v, _ = inferVendorProductFromPURL(nugetNS, EcosystemNuGet)
	if v != "microsoft" {
		t.Errorf("nuget ns: vendor=%q", v)
	}

	// NuGet 无 namespace
	nugetNoNS := NewPURL("nuget", "", "newtonsoft.json", "13.0")
	v, _ = inferVendorProductFromPURL(nugetNoNS, EcosystemNuGet)
	if v != "microsoft" {
		t.Errorf("nuget no-ns: vendor=%q", v)
	}

	// Docker 有 namespace
	dockerNS := NewPURL("docker", "library", "nginx", "latest")
	v, _ = inferVendorProductFromPURL(dockerNS, EcosystemDocker)
	if v != "library" {
		t.Errorf("docker ns: vendor=%q", v)
	}

	// Docker 无 ns、name 含 /
	dockerSlash := &PackageURL{Type: "docker", Name: "library/nginx"}
	v, p = inferVendorProductFromPURL(dockerSlash, EcosystemDocker)
	if v != "library" || p != "nginx" {
		t.Errorf("docker slash: vendor=%q product=%q", v, p)
	}

	// Docker 无 ns、单 name → vendor="_"
	dockerSimple := NewPURL("docker", "", "nginx", "latest")
	v, p = inferVendorProductFromPURL(dockerSimple, EcosystemDocker)
	if v != "_" || p != "nginx" {
		t.Errorf("docker simple: vendor=%q product=%q", v, p)
	}

	// RubyGems
	gem := NewPURL("gem", "", "rails", "7.0")
	v, p = inferVendorProductFromPURL(gem, EcosystemRubyGems)
	if v != "rubygems" || p != "rails" {
		t.Errorf("gem: vendor=%q product=%q", v, p)
	}

	// Cargo
	cargo := NewPURL("cargo", "", "serde", "1.0")
	v, _ = inferVendorProductFromPURL(cargo, EcosystemCargo)
	if v != "rust" {
		t.Errorf("cargo: vendor=%q", v)
	}

	// Composer name 含 /
	composerSlash := &PackageURL{Type: "composer", Name: "vendor/pkg"}
	v, p = inferVendorProductFromPURL(composerSlash, EcosystemComposer)
	if v != "vendor" || p != "pkg" {
		t.Errorf("composer slash: vendor=%q product=%q", v, p)
	}

	// Composer 单 name
	composerSimple := NewPURL("composer", "", "pkg", "1.0")
	v, _ = inferVendorProductFromPURL(composerSimple, EcosystemComposer)
	if v != "packagist" {
		t.Errorf("composer simple: vendor=%q", v)
	}

	// Alpine / Debian / RPM
	for _, eco := range []Ecosystem{EcosystemAlpine, EcosystemDebian, EcosystemRPM} {
		pkg := NewPURL(string(eco), "", "pkg", "1.0")
		v, _ = inferVendorProductFromPURL(pkg, eco)
		if v != string(eco) {
			t.Errorf("%s: vendor=%q want %q", eco, v, eco)
		}
	}

	// default 分支：未知 ecosystem
	unknown := NewPURL("gem", "", "pkg", "1.0")
	v, p = inferVendorProductFromPURL(unknown, EcosystemGeneric)
	if v != "gem" || p != "pkg" {
		t.Errorf("default: vendor=%q product=%q", v, p)
	}
}

// ---- buildPURLFromCPE：GetEcosystemInfo fallback 路径 ----

func TestBuildPURLFromCPE_UnknownEcosystem(t *testing.T) {
	cpe := &CPE{
		Part:        *PartApplication,
		Vendor:      "apache",
		ProductName: "log4j",
		Version:     "2.14",
	}
	// 传入未知 ecosystem → GetEcosystemInfo 失败 → fallback to generic PURLType
	purl, err := buildPURLFromCPE(cpe, Ecosystem("unknown-eco"), "apache", "log4j", "2.14")
	if err != nil {
		t.Fatalf("expected nil error (fallback), got: %v", err)
	}
	if purl == nil {
		t.Fatal("expected non-nil purl")
	}
	if purl.Type != "generic" {
		t.Errorf("expected generic PURLType, got %q", purl.Type)
	}
}

// ---- buildPURLFromCPE：各 ecosystem 的 namespace 分支 ----

func TestBuildPURLFromCPE_NamespaceBranches(t *testing.T) {
	cpe := &CPE{Part: *PartApplication, Vendor: "apache", ProductName: "log4j", Version: "2.14"}

	// Maven → Namespace = vendor
	p, _ := buildPURLFromCPE(cpe, EcosystemMaven, "apache", "log4j", "2.14")
	if p.Namespace != "apache" {
		t.Errorf("maven namespace=%q", p.Namespace)
	}

	// NPM → Namespace = "@vendor"
	p, _ = buildPURLFromCPE(cpe, EcosystemNPM, "scope", "pkg", "1.0")
	if p.Namespace != "@scope" {
		t.Errorf("npm namespace=%q", p.Namespace)
	}

	// Go → Name = "vendor/product"（vendor != google）
	p, _ = buildPURLFromCPE(cpe, EcosystemGo, "github.com", "gin", "1.0")
	if p.Name != "github.com/gin" {
		t.Errorf("go name=%q", p.Name)
	}

	// Docker → Namespace = vendor
	p, _ = buildPURLFromCPE(cpe, EcosystemDocker, "library", "nginx", "latest")
	if p.Namespace != "library" {
		t.Errorf("docker namespace=%q", p.Namespace)
	}

	// vendor == ValueANY → namespace 不设
	p, _ = buildPURLFromCPE(cpe, EcosystemMaven, string(ValueANY), "log4j", "2.14")
	if p.Namespace != "" {
		t.Errorf("ANY vendor namespace should be empty, got %q", p.Namespace)
	}
}
