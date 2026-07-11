package cpeskills

import (
	"testing"
)

func TestEcosystemConstants(t *testing.T) {
	// 验证常用生态系统常量
	ecosystems := []Ecosystem{
		EcosystemNPM, EcosystemMaven, EcosystemPyPI, EcosystemGo,
		EcosystemNuGet, EcosystemDocker, EcosystemRubyGems, EcosystemCargo,
		EcosystemComposer, EcosystemConan, EcosystemConda, EcosystemHex,
		EcosystemPub, EcosystemSwift, EcosystemAlpine, EcosystemDebian,
		EcosystemRPM, EcosystemGeneric,
	}
	for _, eco := range ecosystems {
		if !IsEcosystemSupported(eco) {
			t.Errorf("ecosystem %s should be supported", eco)
		}
	}
}

func TestGetEcosystemInfo(t *testing.T) {
	info, err := GetEcosystemInfo(EcosystemNPM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.PURLType != "npm" {
		t.Errorf("expected purl type 'npm', got '%s'", info.PURLType)
	}
	if info.Name != "npm" {
		t.Errorf("expected name 'npm', got '%s'", info.Name)
	}

	_, err = GetEcosystemInfo(Ecosystem("nonexistent"))
	if err == nil {
		t.Error("expected error for unknown ecosystem")
	}
}

func TestListEcosystems(t *testing.T) {
	list := ListEcosystems()
	if len(list) == 0 {
		t.Error("expected non-empty ecosystem list")
	}
	foundGeneric := false
	for _, eco := range list {
		if eco == EcosystemGeneric {
			foundGeneric = true
			break
		}
	}
	if !foundGeneric {
		t.Error("expected EcosystemGeneric in list")
	}
}

func TestEcosystemFromPURLType(t *testing.T) {
	tests := []struct {
		purlType  string
		ecosystem Ecosystem
	}{
		{"npm", EcosystemNPM},
		{"maven", EcosystemMaven},
		{"pypi", EcosystemPyPI},
		{"golang", EcosystemGo},
		{"nuget", EcosystemNuGet},
		{"docker", EcosystemDocker},
		{"gem", EcosystemRubyGems},
		{"cargo", EcosystemCargo},
		{"composer", EcosystemComposer},
		{"conan", EcosystemConan},
		{"conda", EcosystemConda},
		{"hex", EcosystemHex},
		{"pub", EcosystemPub},
		{"swift", EcosystemSwift},
		{"alpine", EcosystemAlpine},
		{"deb", EcosystemDebian},
		{"rpm", EcosystemRPM},
		{"generic", EcosystemGeneric},
		{"unknown-type", EcosystemGeneric},
	}
	for _, tt := range tests {
		result := EcosystemFromPURLType(tt.purlType)
		if result != tt.ecosystem {
			t.Errorf("EcosystemFromPURLType(%q): expected %s, got %s", tt.purlType, tt.ecosystem, result)
		}
	}
}

func TestNormalizeEcosystemName(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem Ecosystem
		wantErr   bool
	}{
		{"npm", EcosystemNPM, false},
		{"node.js", EcosystemNPM, false},
		{"nodejs", EcosystemNPM, false},
		{"maven", EcosystemMaven, false},
		{"java", EcosystemMaven, false},
		{"pypi", EcosystemPyPI, false},
		{"python", EcosystemPyPI, false},
		{"golang", EcosystemGo, false},
		{"go", EcosystemGo, false},
		{"nuget", EcosystemNuGet, false},
		{"dotnet", EcosystemNuGet, false},
		{"docker", EcosystemDocker, false},
		{"rubygems", EcosystemRubyGems, false},
		{"cargo", EcosystemCargo, false},
		{"rust", EcosystemCargo, false},
		{"composer", EcosystemComposer, false},
		{"php", EcosystemComposer, false},
		{"generic", EcosystemGeneric, false},
		{"completely-unknown-name", "", true},
	}
	for _, tt := range tests {
		eco, err := NormalizeEcosystemName(tt.name)
		if tt.wantErr && err == nil {
			t.Errorf("NormalizeEcosystemName(%q): expected error", tt.name)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("NormalizeEcosystemName(%q): unexpected error: %v", tt.name, err)
		}
		if eco != tt.ecosystem {
			t.Errorf("NormalizeEcosystemName(%q): expected %s, got %s", tt.name, tt.ecosystem, eco)
		}
	}
}

func TestCPEPartToEcosystemHint(t *testing.T) {
	// Application part
	hints := CPEPartToEcosystemHint(PartApplication)
	if len(hints) == 0 {
		t.Error("expected non-empty hints for application part")
	}

	// OS part
	hints = CPEPartToEcosystemHint(PartOperationSystem)
	foundAlpine := false
	for _, h := range hints {
		if h == EcosystemAlpine {
			foundAlpine = true
			break
		}
	}
	if !foundAlpine {
		t.Error("expected Alpine in OS ecosystem hints")
	}

	// Hardware part
	hints = CPEPartToEcosystemHint(PartHardware)
	if len(hints) != 1 || hints[0] != EcosystemGeneric {
		t.Errorf("expected only Generic for hardware part, got %v", hints)
	}

	// Nil part
	hints = CPEPartToEcosystemHint(nil)
	if hints != nil {
		t.Errorf("expected nil hints for nil part, got %v", hints)
	}
}
