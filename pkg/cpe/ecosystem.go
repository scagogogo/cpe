package cpeskills

import "fmt"

// Ecosystem 表示包管理生态系统类型
// 用于标识软件包所属的包管理器/注册表，是 PURL 和 SBOM 的核心概念
type Ecosystem string

const (
	// EcosystemNPM Node.js 包管理器 (npm)
	EcosystemNPM Ecosystem = "npm"

	// EcosystemMaven Java/Kotlin 项目 (Maven Central, Google Android)
	EcosystemMaven Ecosystem = "maven"

	// EcosystemPyPI Python 包索引
	EcosystemPyPI Ecosystem = "pypi"

	// EcosystemGo Go 模块
	EcosystemGo Ecosystem = "golang"

	// EcosystemNuGet .NET 包管理器
	EcosystemNuGet Ecosystem = "nuget"

	// EcosystemDocker Docker 容器镜像
	EcosystemDocker Ecosystem = "docker"

	// EcosystemRubyGems Ruby 包管理器
	EcosystemRubyGems Ecosystem = "gem"

	// EcosystemCargo Rust 包管理器
	EcosystemCargo Ecosystem = "cargo"

	// EcosystemComposer PHP 包管理器
	EcosystemComposer Ecosystem = "composer"

	// EcosystemConan C/C++ 包管理器
	EcosystemConan Ecosystem = "conan"

	// EcosystemConda 跨语言包管理器
	EcosystemConda Ecosystem = "conda"

	// EcosystemHex Elixir/Erlang 生态系统
	EcosystemHex Ecosystem = "hex"

	// EcosystemPub Dart/Flutter 包管理器
	EcosystemPub Ecosystem = "pub"

	// EcosystemSwift Swift 包管理器
	EcosystemSwift Ecosystem = "swift"

	// EcosystemAlpine Alpine Linux (apk) 包
	EcosystemAlpine Ecosystem = "alpine"

	// EcosystemDebian Debian/Ubuntu (deb) 包
	EcosystemDebian Ecosystem = "deb"

	// EcosystemRPM Red Hat/Fedora (rpm) 包
	EcosystemRPM Ecosystem = "rpm"

	// EcosystemGeneric 通用/未知生态系统
	EcosystemGeneric Ecosystem = "generic"
)

// allEcosystems 包含所有已注册的生态系统
var allEcosystems = map[Ecosystem]EcosystemInfo{
	EcosystemNPM: {
		Name:        "npm",
		FullName:    "Node Package Manager",
		RegistryURL: "https://registry.npmjs.org",
		PURLType:    "npm",
	},
	EcosystemMaven: {
		Name:        "Maven",
		FullName:    "Maven Central",
		RegistryURL: "https://repo.maven.apache.org/maven2",
		PURLType:    "maven",
	},
	EcosystemPyPI: {
		Name:        "PyPI",
		FullName:    "Python Package Index",
		RegistryURL: "https://pypi.org",
		PURLType:    "pypi",
	},
	EcosystemGo: {
		Name:        "Go Modules",
		FullName:    "Go Module Index",
		RegistryURL: "https://proxy.golang.org",
		PURLType:    "golang",
	},
	EcosystemNuGet: {
		Name:        "NuGet",
		FullName:    ".NET Package Manager",
		RegistryURL: "https://api.nuget.org",
		PURLType:    "nuget",
	},
	EcosystemDocker: {
		Name:        "Docker",
		FullName:    "Docker Container Images",
		RegistryURL: "https://hub.docker.com",
		PURLType:    "docker",
	},
	EcosystemRubyGems: {
		Name:        "RubyGems",
		FullName:    "Ruby Package Manager",
		RegistryURL: "https://rubygems.org",
		PURLType:    "gem",
	},
	EcosystemCargo: {
		Name:        "Cargo",
		FullName:    "Rust Package Manager",
		RegistryURL: "https://crates.io",
		PURLType:    "cargo",
	},
	EcosystemComposer: {
		Name:        "Composer",
		FullName:    "PHP Package Manager",
		RegistryURL: "https://packagist.org",
		PURLType:    "composer",
	},
	EcosystemConan: {
		Name:        "Conan",
		FullName:    "C/C++ Package Manager",
		RegistryURL: "https://conan.io/center",
		PURLType:    "conan",
	},
	EcosystemConda: {
		Name:        "Conda",
		FullName:    "Conda Package Manager",
		RegistryURL: "https://anaconda.org",
		PURLType:    "conda",
	},
	EcosystemHex: {
		Name:        "Hex",
		FullName:    "Elixir/Erlang Package Manager",
		RegistryURL: "https://hex.pm",
		PURLType:    "hex",
	},
	EcosystemPub: {
		Name:        "Pub",
		FullName:    "Dart/Flutter Package Manager",
		RegistryURL: "https://pub.dev",
		PURLType:    "pub",
	},
	EcosystemSwift: {
		Name:        "SwiftPM",
		FullName:    "Swift Package Manager",
		RegistryURL: "https://swiftpackageindex.com",
		PURLType:    "swift",
	},
	EcosystemAlpine: {
		Name:        "Alpine Linux",
		FullName:    "Alpine Linux Packages",
		RegistryURL: "https://pkgs.alpinelinux.org",
		PURLType:    "alpine",
	},
	EcosystemDebian: {
		Name:        "Debian",
		FullName:    "Debian Packages",
		RegistryURL: "https://packages.debian.org",
		PURLType:    "deb",
	},
	EcosystemRPM: {
		Name:        "RPM",
		FullName:    "RPM Package Manager",
		RegistryURL: "https://rpmfind.net",
		PURLType:    "rpm",
	},
	EcosystemGeneric: {
		Name:        "Generic",
		FullName:    "Generic Package",
		PURLType:    "generic",
	},
}

// EcosystemInfo 包含生态系统的元数据信息
type EcosystemInfo struct {
	// Name 生态系统名称
	Name string

	// FullName 生态系统全名
	FullName string

	// RegistryURL 默认注册表 URL
	RegistryURL string

	// PURLType PURL type 字段值
	PURLType string
}

// GetEcosystemInfo 获取生态系统信息
func GetEcosystemInfo(ecosystem Ecosystem) (EcosystemInfo, error) {
	info, ok := allEcosystems[ecosystem]
	if !ok {
		return EcosystemInfo{}, fmt.Errorf("unknown ecosystem: %s", ecosystem)
	}
	return info, nil
}

// ListEcosystems 列出所有支持的生态系统
func ListEcosystems() []Ecosystem {
	result := make([]Ecosystem, 0, len(allEcosystems))
	for eco := range allEcosystems {
		result = append(result, eco)
	}
	return result
}

// EcosystemFromPURLType 根据 PURL type 字段确定生态系统
func EcosystemFromPURLType(purlType string) Ecosystem {
	for eco, info := range allEcosystems {
		if info.PURLType == purlType {
			return eco
		}
	}
	return EcosystemGeneric
}

// IsEcosystemSupported 检查生态系统是否被支持
func IsEcosystemSupported(ecosystem Ecosystem) bool {
	_, ok := allEcosystems[ecosystem]
	return ok
}

// CPEPartToEcosystemHint 根据 CPE Part 推断可能的生态系统
// 这是一个启发式方法，用于辅助 CPE→PURL 映射
func CPEPartToEcosystemHint(part *Part) []Ecosystem {
	if part == nil {
		return nil
	}
	switch part.ShortName {
	case "a":
		// 应用程序 — 可能来自任何包生态系统
		return []Ecosystem{
			EcosystemNPM, EcosystemMaven, EcosystemPyPI, EcosystemGo,
			EcosystemNuGet, EcosystemRubyGems, EcosystemCargo,
			EcosystemComposer, EcosystemConan, EcosystemConda,
			EcosystemPub, EcosystemSwift, EcosystemGeneric,
		}
	case "o":
		// 操作系统 — 通常是 Linux 发行版包
		return []Ecosystem{EcosystemAlpine, EcosystemDebian, EcosystemRPM, EcosystemGeneric}
	case "h":
		// 硬件 — 通常不在包生态系统中
		return []Ecosystem{EcosystemGeneric}
	default:
		return []Ecosystem{EcosystemGeneric}
	}
}

// NormalizeEcosystemName 标准化生态系统名称
// 支持常见别名，如 "node.js" → EcosystemNPM, "java" → EcosystemMaven
func NormalizeEcosystemName(name string) (Ecosystem, error) {
	switch name {
	case "npm", "node", "node.js", "nodejs":
		return EcosystemNPM, nil
	case "maven", "java", "kotlin":
		return EcosystemMaven, nil
	case "pypi", "python", "pip":
		return EcosystemPyPI, nil
	case "golang", "go", "go modules":
		return EcosystemGo, nil
	case "nuget", "csharp", "dotnet", ".net":
		return EcosystemNuGet, nil
	case "docker", "container", "oci":
		return EcosystemDocker, nil
	case "rubygems", "ruby", "gem":
		return EcosystemRubyGems, nil
	case "cargo", "rust":
		return EcosystemCargo, nil
	case "composer", "php":
		return EcosystemComposer, nil
	case "conan", "c++", "cpp", "c":
		return EcosystemConan, nil
	case "conda", "anaconda":
		return EcosystemConda, nil
	case "hex", "elixir", "erlang":
		return EcosystemHex, nil
	case "pub", "dart", "flutter":
		return EcosystemPub, nil
	case "swift", "swiftpm":
		return EcosystemSwift, nil
	case "alpine", "apk":
		return EcosystemAlpine, nil
	case "debian", "deb", "ubuntu":
		return EcosystemDebian, nil
	case "rpm", "redhat", "fedora", "centos":
		return EcosystemRPM, nil
	case "generic", "other", "unknown":
		return EcosystemGeneric, nil
	default:
		// 尝试直接匹配 Ecosystem 常量
		if IsEcosystemSupported(Ecosystem(name)) {
			return Ecosystem(name), nil
		}
		return "", fmt.Errorf("unknown ecosystem name: %s", name)
	}
}
