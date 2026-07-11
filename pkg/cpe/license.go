package cpeskills

// License 表示一个软件许可证
// 基于 SPDX 许可证列表标准
type License struct {
	// SPDXID SPDX 许可证标识符 (如 "MIT", "Apache-2.0", "GPL-3.0-only")
	SPDXID string `json:"id"`

	// Name 许可证全名
	Name string `json:"name"`

	// URL 许可证文本链接
	URL string `json:"url,omitempty"`

	// IsCopyleft 是否为 Copyleft 许可证
	IsCopyleft bool `json:"isCopyleft"`

	// IsOSIApproved 是否为 OSI 批准的许可证
	IsOSIApproved bool `json:"isOSIApproved"`

	// Restrictions 使用限制说明
	Restrictions []string `json:"restrictions,omitempty"`
}

// NewLicense 创建一个新的许可证
func NewLicense(spdxID, name string) *License {
	return &License{
		SPDXID:        spdxID,
		Name:          name,
		IsOSIApproved: isOSIApproved(spdxID),
		IsCopyleft:    isCopyleft(spdxID),
	}
}

// String 返回许可证的 SPDX 标识符
func (l *License) String() string {
	if l == nil {
		return ""
	}
	return l.SPDXID
}

// isOSIApproved 检查 SPDX ID 是否为 OSI 批准的许可证
func isOSIApproved(spdxID string) bool {
	osiApproved := map[string]bool{
		"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
		"GPL-2.0-only": true, "GPL-2.0-or-later": true, "GPL-3.0-only": true, "GPL-3.0-or-later": true,
		"LGPL-2.1-only": true, "LGPL-2.1-or-later": true, "LGPL-3.0-only": true, "LGPL-3.0-or-later": true,
		"MPL-2.0": true, "CDDL-1.0": true, "EPL-1.0": true, "EPL-2.0": true,
		"AGPL-3.0-only": true, "AGPL-3.0-or-later": true,
		"Unlicense": true, "Zlib": true, "PostgreSQL": true,
		"ISC": true, "Artistic-2.0": true, "CECILL-2.1": true,
		"OSL-3.0": true, "AFL-3.0": true, "EUPL-1.2": true,
	}
	return osiApproved[spdxID]
}

// isCopyleft 检查 SPDX ID 是否为 Copyleft 许可证
func isCopyleft(spdxID string) bool {
	copyleft := map[string]bool{
		"GPL-2.0-only": true, "GPL-2.0-or-later": true,
		"GPL-3.0-only": true, "GPL-3.0-or-later": true,
		"LGPL-2.1-only": true, "LGPL-2.1-or-later": true,
		"LGPL-3.0-only": true, "LGPL-3.0-or-later": true,
		"AGPL-3.0-only": true, "AGPL-3.0-or-later": true,
		"MPL-2.0": true, "CDDL-1.0": true,
		"EPL-1.0": true, "EPL-2.0": true,
		"EUPL-1.2": true, "OSL-3.0": true,
	}
	return copyleft[spdxID]
}

// CommonLicenses 返回常见许可证列表
func CommonLicenses() []*License {
	return []*License{
		NewLicense("MIT", "MIT License"),
		NewLicense("Apache-2.0", "Apache License 2.0"),
		NewLicense("BSD-3-Clause", "BSD 3-Clause License"),
		NewLicense("BSD-2-Clause", "BSD 2-Clause License"),
		NewLicense("GPL-3.0-only", "GNU General Public License v3.0 only"),
		NewLicense("GPL-3.0-or-later", "GNU General Public License v3.0 or later"),
		NewLicense("LGPL-3.0-only", "GNU Lesser General Public License v3.0 only"),
		NewLicense("MPL-2.0", "Mozilla Public License 2.0"),
		NewLicense("ISC", "ISC License"),
		NewLicense("Unlicense", "The Unlicense"),
	}
}

// DetectLicenseByName 根据许可证名称或 SPDX ID 检测许可证
func DetectLicenseByName(name string) *License {
	knownLicenses := map[string]string{
		"mit": "MIT", "mit license": "MIT",
		"apache-2.0": "Apache-2.0", "apache 2.0": "Apache-2.0", "apache2": "Apache-2.0",
		"apache license 2.0": "Apache-2.0",
		"bsd-3-clause": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause", "bsd3": "BSD-3-Clause",
		"bsd-2-clause": "BSD-2-Clause", "bsd 2-clause": "BSD-2-Clause", "bsd2": "BSD-2-Clause",
		"gpl-3.0": "GPL-3.0-only", "gpl-3.0-only": "GPL-3.0-only", "gpl3": "GPL-3.0-only",
		"gpl-3.0-or-later": "GPL-3.0-or-later",
		"gpl-2.0": "GPL-2.0-only", "gpl-2.0-only": "GPL-2.0-only", "gpl2": "GPL-2.0-only",
		"lgpl-3.0": "LGPL-3.0-only", "lgpl3": "LGPL-3.0-only",
		"mpl-2.0": "MPL-2.0", "mpl2": "MPL-2.0",
		"isc": "ISC", "isc license": "ISC",
		"unlicense": "Unlicense",
		"cc0-1.0": "CC0-1.0", "cc0": "CC0-1.0",
	}

	normalized := toLower(name)
	if spdxID, ok := knownLicenses[normalized]; ok {
		return NewLicense(spdxID, spdxID)
	}
	return nil
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}
