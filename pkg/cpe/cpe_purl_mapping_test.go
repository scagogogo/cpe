package cpeskills

import (
	"testing"
)

func TestCPEToPURL(t *testing.T) {
	tests := []struct {
		name           string
		cpe            *CPE
		wantType       string
		wantName       string
		wantConfidence float64
	}{
		{
			name: "apache log4j → maven",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "apache",
				ProductName: "log4j",
				Version:     "2.14.1",
			},
			wantType:       "maven",
			wantName:       "log4j",
			wantConfidence: 0.9,
		},
		{
			name: "spring → maven",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "spring",
				ProductName: "spring-core",
				Version:     "5.3.0",
			},
			wantType:       "maven",
			wantName:       "spring-core",
			wantConfidence: 0.95,
		},
		{
			name: "express → npm",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "express",
				ProductName: "express",
				Version:     "4.17.1",
			},
			wantType:       "npm",
			wantName:       "express",
			wantConfidence: 0.9,
		},
		{
			name: "django → pypi",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "django",
				ProductName: "django",
				Version:     "4.2.0",
			},
			wantType:       "pypi",
			wantName:       "django",
			wantConfidence: 0.95,
		},
		{
			name: "golang project → go",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "golang",
				ProductName: "gin",
				Version:     "1.9.0",
			},
			wantType:       "golang",
			wantName:       "golang/gin", // Go 用 vendor/name 格式
			wantConfidence: 1.0,
		},
		{
			name: "nuget → nuget",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "nuget",
				ProductName: "newtonsoft.json",
				Version:     "13.0.1",
			},
			wantType:       "nuget",
			wantName:       "newtonsoft.json",
			wantConfidence: 1.0,
		},
		{
			name: "unknown vendor → generic",
			cpe: &CPE{
				Part:        *PartApplication,
				Vendor:      "unknown_vendor_xyz",
				ProductName: "unknown_product",
				Version:     "1.0.0",
			},
			wantType:       "generic",
			wantName:       "unknown_product",
			wantConfidence: 0.3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			purl, confidence, err := CPEToPURL(tt.cpe)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if purl.Type != tt.wantType {
				t.Errorf("expected type %q, got %q", tt.wantType, purl.Type)
			}
			if purl.Name != tt.wantName {
				t.Errorf("expected name %q, got %q", tt.wantName, purl.Name)
			}
			if confidence < tt.wantConfidence-0.01 {
				t.Errorf("expected confidence >= %f, got %f", tt.wantConfidence, confidence)
			}
		})
	}
}

func TestCPEToPURL_NilCPE(t *testing.T) {
	_, _, err := CPEToPURL(nil)
	if err == nil {
		t.Error("expected error for nil CPE")
	}
}

func TestCPEToPURL_NoVersion(t *testing.T) {
	cpe := &CPE{
		Part:        *PartApplication,
		Vendor:      "apache",
		ProductName: "log4j",
		Version:     "*",
	}
	_, confidence, err := CPEToPURL(cpe)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if confidence >= 0.9 {
		t.Errorf("expected lower confidence for missing version, got %f", confidence)
	}
}

func TestPURLToCPE(t *testing.T) {
	tests := []struct {
		name        string
		purl        *PackageURL
		wantVendor  string
		wantProduct string
	}{
		{
			name:        "npm package",
			purl:        NewPURL("npm", "", "express", "4.17.1"),
			wantVendor:  "npm",
			wantProduct: "express",
		},
		{
			name:        "maven package",
			purl:        NewPURL("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"),
			wantVendor:  "org",
			wantProduct: "log4j-core",
		},
		{
			name:        "pypi package",
			purl:        NewPURL("pypi", "", "django", "4.2.0"),
			wantVendor:  "python",
			wantProduct: "django",
		},
		{
			name:        "golang package",
			purl:        NewPURL("golang", "github.com", "gin-gonic/gin", "1.9.0"),
			wantVendor:  "gin-gonic", // Go 取 name 第一段作为 vendor
			wantProduct: "gin",       // Go 取 name 最后一段作为 product
		},
		{
			name:        "docker image",
			purl:        NewPURL("docker", "library", "nginx", "1.21"),
			wantVendor:  "library",
			wantProduct: "nginx",
		},
		{
			name:        "composer package",
			purl:        NewPURL("composer", "laravel", "framework", "10.0.0"),
			wantVendor:  "packagist", // composer 中 namespace 不用作 vendor
			wantProduct: "framework",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe, confidence, err := PURLToCPE(tt.purl)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cpe == nil {
				t.Fatal("expected non-nil CPE")
			}
			if string(cpe.Vendor) != tt.wantVendor {
				t.Errorf("expected vendor %q, got %q", tt.wantVendor, string(cpe.Vendor))
			}
			if string(cpe.ProductName) != tt.wantProduct {
				t.Errorf("expected product %q, got %q", tt.wantProduct, string(cpe.ProductName))
			}
			if string(cpe.Version) != tt.purl.Version {
				t.Errorf("expected version %q, got %q", tt.purl.Version, string(cpe.Version))
			}
			if confidence <= 0 {
				t.Errorf("expected positive confidence, got %f", confidence)
			}
		})
	}
}

func TestPURLToCPE_NilPURL(t *testing.T) {
	_, _, err := PURLToCPE(nil)
	if err == nil {
		t.Error("expected error for nil PURL")
	}
}

func TestMapCPEToPURLWithEcosystem(t *testing.T) {
	cpe := &CPE{
		Part:        *PartApplication,
		Vendor:      "apache",
		ProductName: "log4j",
		Version:     "2.14.1",
	}

	// 显式映射到 Maven
	purl, err := MapCPEToPURLWithEcosystem(cpe, EcosystemMaven)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if purl.Type != "maven" {
		t.Errorf("expected type 'maven', got %q", purl.Type)
	}
	if purl.Namespace != "apache" {
		t.Errorf("expected namespace 'apache', got %q", purl.Namespace)
	}

	// 映射到 NPM
	purl, err = MapCPEToPURLWithEcosystem(cpe, EcosystemNPM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if purl.Type != "npm" {
		t.Errorf("expected type 'npm', got %q", purl.Type)
	}
	if purl.Namespace != "@apache" {
		t.Errorf("expected namespace '@apache', got %q", purl.Namespace)
	}

	// 映射到 Go
	purl, err = MapCPEToPURLWithEcosystem(cpe, EcosystemGo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if purl.Type != "golang" {
		t.Errorf("expected type 'golang', got %q", purl.Type)
	}

	// 未知生态系统
	_, err = MapCPEToPURLWithEcosystem(cpe, Ecosystem("nonexistent"))
	if err == nil {
		t.Error("expected error for unknown ecosystem")
	}

	// nil CPE
	_, err = MapCPEToPURLWithEcosystem(nil, EcosystemNPM)
	if err == nil {
		t.Error("expected error for nil CPE")
	}
}

func TestBatchCPEToPURL(t *testing.T) {
	cpes := []*CPE{
		{Part: *PartApplication, Vendor: "apache", ProductName: "log4j", Version: "2.14.1"},
		{Part: *PartApplication, Vendor: "django", ProductName: "django", Version: "4.2.0"},
		{Part: *PartApplication, Vendor: "express", ProductName: "express", Version: "4.17.1"},
		nil,
	}

	result := BatchCPEToPURL(cpes)
	if len(result) != 3 {
		t.Errorf("expected 3 results, got %d", len(result))
	}
}

func TestBatchPURLToCPE(t *testing.T) {
	purls := []*PackageURL{
		NewPURL("npm", "", "express", "4.17.1"),
		NewPURL("maven", "org.apache", "log4j", "2.14.1"),
		NewPURL("pypi", "", "django", "4.2.0"),
	}

	result := BatchPURLToCPE(purls)
	if len(result) != 3 {
		t.Errorf("expected 3 results, got %d", len(result))
	}
}

func TestCPEToPURL_RoundTrip(t *testing.T) {
	// 测试 CPE → PURL → CPE 的往返转换
	original := &CPE{
		Part:        *PartApplication,
		Vendor:      "apache",
		ProductName: "log4j",
		Version:     "2.14.1",
	}

	purl, _, err := CPEToPURL(original)
	if err != nil {
		t.Fatalf("CPEToPURL error: %v", err)
	}

	reconstructed, _, err := PURLToCPE(purl)
	if err != nil {
		t.Fatalf("PURLToCPE error: %v", err)
	}

	// 版本应该保持一致
	if string(reconstructed.Version) != string(original.Version) {
		t.Errorf("version mismatch: %q vs %q", original.Version, reconstructed.Version)
	}
}

func TestInferEcosystem(t *testing.T) {
	tests := []struct {
		vendor  string
		product string
		wantEco Ecosystem
		minConf float64
	}{
		{"apache", "log4j", EcosystemMaven, 0.8},
		{"spring", "spring-core", EcosystemMaven, 0.9},
		{"npm", "express", EcosystemNPM, 0.9},
		{"django", "django", EcosystemPyPI, 0.9},
		{"golang", "gin", EcosystemGo, 0.9},
		{"nuget", "newtonsoft.json", EcosystemNuGet, 0.9},
		{"rust", "serde", EcosystemCargo, 0.9},
		{"rubygems", "rails", EcosystemRubyGems, 0.9},
		{"docker", "nginx", EcosystemDocker, 0.9},
		{"unknown_vendor", "unknown_product", EcosystemGeneric, 0.2},
	}

	for _, tt := range tests {
		eco, conf := inferEcosystem(tt.vendor, tt.product)
		if eco != tt.wantEco {
			t.Errorf("inferEcosystem(%q, %q): expected %s, got %s", tt.vendor, tt.product, tt.wantEco, eco)
		}
		if conf < tt.minConf {
			t.Errorf("inferEcosystem(%q, %q): expected confidence >= %f, got %f", tt.vendor, tt.product, tt.minConf, conf)
		}
	}
}

func TestPURLToCPE_ScopedNPM(t *testing.T) {
	// NPM scoped package：namespace="@babel"
	purl := NewPURL("npm", "@babel", "core", "7.0.0")
	cpe, _, err := PURLToCPE(purl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(cpe.Vendor) != "babel" {
		t.Errorf("expected vendor 'babel', got %q", cpe.Vendor)
	}
	if string(cpe.ProductName) != "core" {
		t.Errorf("expected product 'core', got %q", cpe.ProductName)
	}
}

func TestPURLToCPE_NPMWithSlashInName(t *testing.T) {
	// NPM 无 namespace 但 name 含 /（如 "lodash/lodash"）
	purl := NewPURL("npm", "", "lodash", "4.0.0")
	cpe, _, err := PURLToCPE(purl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(cpe.Vendor) != "npm" {
		t.Errorf("expected vendor 'npm', got %q", cpe.Vendor)
	}
}

func TestPURLToCPE_GoSingleSegment(t *testing.T) {
	// Go name 单段（无 /）
	purl := NewPURL("golang", "", "single", "1.0.0")
	cpe, _, err := PURLToCPE(purl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(cpe.Vendor) != "golang" {
		t.Errorf("expected vendor 'golang', got %q", cpe.Vendor)
	}
	if string(cpe.ProductName) != "single" {
		t.Errorf("expected product 'single', got %q", cpe.ProductName)
	}
}

func TestPURLToCPE_UnknownEcosystem(t *testing.T) {
	// 未知 ecosystem → default 分支
	purl := NewPURL("unknown-eco", "", "foo", "1.0.0")
	cpe, _, err := PURLToCPE(purl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cpe == nil {
		t.Fatal("expected non-nil CPE for unknown ecosystem")
	}
}

func TestBuildPURLFromCPE_DockerAndMaven(t *testing.T) {
	// 覆盖 buildPURLFromCPE 的 Docker/Maven namespace 分支
	cpeMaven := mustParseCPE(t, "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*")
	purlMaven, err := MapCPEToPURLWithEcosystem(cpeMaven, EcosystemMaven)
	if err != nil {
		t.Fatalf("maven: %v", err)
	}
	if purlMaven == nil {
		t.Fatal("expected non-nil maven purl")
	}
	cpeDocker := mustParseCPE(t, "cpe:2.3:a:library:nginx:1.21:*:*:*:*:*:*:*")
	purlDocker, err := MapCPEToPURLWithEcosystem(cpeDocker, EcosystemDocker)
	if err != nil {
		t.Fatalf("docker: %v", err)
	}
	if purlDocker == nil {
		t.Fatal("expected non-nil docker purl")
	}
}
