package cpe

import (
	"fmt"
	"testing"
	"time"
)

// TestCVEReference_RemoveAffectedCPE 测试移除受影响的CPE功能
func TestCVEReference_RemoveAffectedCPE(t *testing.T) {
	// 创建CVE引用
	cveRef := NewCVEReference("CVE-2021-44228")

	// 添加一些CPE
	cpe1 := "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"
	cpe2 := "cpe:2.3:a:apache:log4j:2.1:*:*:*:*:*:*:*"
	cpe3 := "cpe:2.3:a:apache:log4j:2.2:*:*:*:*:*:*:*"

	cveRef.AddAffectedCPE(cpe1)
	cveRef.AddAffectedCPE(cpe2)
	cveRef.AddAffectedCPE(cpe3)

	// 确认添加成功
	if len(cveRef.AffectedCPEs) != 3 {
		t.Errorf("添加CPE失败，期望3个CPE，实际有%d个", len(cveRef.AffectedCPEs))
	}

	// 测试移除存在的CPE
	result := cveRef.RemoveAffectedCPE(cpe2)
	if !result {
		t.Error("移除存在的CPE应返回true，但返回了false")
	}

	// 验证CPE已被移除
	if len(cveRef.AffectedCPEs) != 2 {
		t.Errorf("移除CPE失败，期望2个CPE，实际有%d个", len(cveRef.AffectedCPEs))
	}

	// 确保正确的CPE被移除
	for _, cpe := range cveRef.AffectedCPEs {
		if cpe == cpe2 {
			t.Error("CPE应该被移除，但仍然存在")
		}
	}

	// 测试移除不存在的CPE
	result = cveRef.RemoveAffectedCPE("cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*")
	if result {
		t.Error("移除不存在的CPE应返回false，但返回了true")
	}

	// 验证集合大小未变
	if len(cveRef.AffectedCPEs) != 2 {
		t.Errorf("移除不存在的CPE后，CPE数量应保持不变，期望2个CPE，实际有%d个", len(cveRef.AffectedCPEs))
	}
}

// TestCVEReference_AddReference 测试添加参考链接功能
func TestCVEReference_AddReference(t *testing.T) {
	// 创建CVE引用
	cveRef := NewCVEReference("CVE-2021-44228")

	// 添加参考链接
	ref1 := "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
	ref2 := "https://www.cve.org/CVERecord?id=CVE-2021-44228"

	cveRef.AddReference(ref1)
	cveRef.AddReference(ref2)

	// 确认添加成功
	if len(cveRef.References) != 2 {
		t.Errorf("添加参考链接失败，期望2个链接，实际有%d个", len(cveRef.References))
	}

	// 测试添加重复链接
	cveRef.AddReference(ref1)

	// 验证集合大小未变
	if len(cveRef.References) != 2 {
		t.Errorf("添加重复链接后，链接数量应保持不变，期望2个链接，实际有%d个", len(cveRef.References))
	}

	// 验证添加的链接存在
	foundRef1 := false
	foundRef2 := false
	for _, ref := range cveRef.References {
		if ref == ref1 {
			foundRef1 = true
		}
		if ref == ref2 {
			foundRef2 = true
		}
	}

	if !foundRef1 {
		t.Error("参考链接1未找到")
	}

	if !foundRef2 {
		t.Error("参考链接2未找到")
	}
}

// TestCVEReference_SetSeverity 测试设置严重性级别功能
func TestCVEReference_SetSeverity(t *testing.T) {
	// 创建CVE引用
	cveRef := NewCVEReference("CVE-2021-44228")

	// 测试临界值
	tests := []struct {
		score    float64
		severity string
	}{
		{9.5, "Critical"},
		{8.5, "High"},
		{5.5, "Medium"},
		{2.5, "Low"},
		{0.0, "Low"},
		{10.0, "Critical"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("CVSS%.1f", tt.score), func(t *testing.T) {
			oldDate := cveRef.LastModifiedDate
			time.Sleep(1 * time.Millisecond) // 确保时间戳变化

			cveRef.SetSeverity(tt.score)

			// 验证评分已设置
			if cveRef.CVSSScore != tt.score {
				t.Errorf("CVSS评分未正确设置，期望%.1f，实际为%.1f", tt.score, cveRef.CVSSScore)
			}

			// 验证严重性级别已设置
			if cveRef.Severity != tt.severity {
				t.Errorf("严重性级别未正确设置，期望%s，实际为%s", tt.severity, cveRef.Severity)
			}

			// 验证修改时间已更新
			if !cveRef.LastModifiedDate.After(oldDate) {
				t.Error("LastModifiedDate未更新")
			}
		})
	}
}

// TestCVEReference_SetGetRemoveMetadata 测试元数据相关功能
func TestCVEReference_SetGetRemoveMetadata(t *testing.T) {
	// 创建CVE引用
	cveRef := NewCVEReference("CVE-2021-44228")

	// 测试设置元数据
	cveRef.SetMetadata("exploitAvailable", true)
	cveRef.SetMetadata("patchDate", "2021-12-10")
	cveRef.SetMetadata("affectedVersions", []string{"2.0", "2.1", "2.2"})

	// 测试获取元数据
	if value, exists := cveRef.GetMetadata("exploitAvailable"); !exists {
		t.Error("元数据'exploitAvailable'应存在，但不存在")
	} else {
		boolValue, ok := value.(bool)
		if !ok {
			t.Error("元数据'exploitAvailable'类型错误，应为bool")
		} else if !boolValue {
			t.Error("元数据'exploitAvailable'值错误，应为true")
		}
	}

	if value, exists := cveRef.GetMetadata("patchDate"); !exists {
		t.Error("元数据'patchDate'应存在，但不存在")
	} else {
		strValue, ok := value.(string)
		if !ok {
			t.Error("元数据'patchDate'类型错误，应为string")
		} else if strValue != "2021-12-10" {
			t.Errorf("元数据'patchDate'值错误，期望'2021-12-10'，实际为'%s'", strValue)
		}
	}

	// 测试获取不存在的元数据
	if _, exists := cveRef.GetMetadata("nonExistentKey"); exists {
		t.Error("元数据'nonExistentKey'不应存在，但存在")
	}

	// 测试移除元数据
	oldDate := cveRef.LastModifiedDate
	time.Sleep(1 * time.Millisecond) // 确保时间戳变化

	// 移除存在的元数据
	result := cveRef.RemoveMetadata("patchDate")
	if !result {
		t.Error("移除存在的元数据应返回true，但返回false")
	}

	// 验证元数据已被移除
	if _, exists := cveRef.GetMetadata("patchDate"); exists {
		t.Error("元数据'patchDate'应已被移除，但仍存在")
	}

	// 验证修改时间已更新
	if !cveRef.LastModifiedDate.After(oldDate) {
		t.Error("LastModifiedDate未更新")
	}

	// 移除不存在的元数据
	result = cveRef.RemoveMetadata("nonExistentKey")
	if result {
		t.Error("移除不存在的元数据应返回false，但返回true")
	}
}

// TestGetCVEInfo 测试获取CVE信息功能
func TestGetCVEInfo(t *testing.T) {
	// 创建CVE引用列表
	cves := []*CVEReference{
		NewCVEReference("CVE-2021-44228"),
		NewCVEReference("CVE-2022-12345"),
		NewCVEReference("CVE-2020-98765"),
	}

	// 设置一些属性以便验证
	cves[0].Description = "Log4j远程代码执行漏洞"
	cves[1].Description = "示例漏洞描述"

	// 测试查找存在的CVE
	cveInfo := GetCVEInfo(cves, "CVE-2021-44228")
	if cveInfo == nil {
		t.Error("GetCVEInfo未找到应存在的CVE")
	} else {
		if cveInfo.Description != "Log4j远程代码执行漏洞" {
			t.Errorf("GetCVEInfo返回了错误的CVE，期望描述'Log4j远程代码执行漏洞'，实际为'%s'", cveInfo.Description)
		}
	}

	// 测试查找存在的CVE（不同格式）
	cveInfo = GetCVEInfo(cves, "cve-2022-12345")
	if cveInfo == nil {
		t.Error("GetCVEInfo未找到应存在的CVE（不同格式输入）")
	} else {
		if cveInfo.Description != "示例漏洞描述" {
			t.Errorf("GetCVEInfo返回了错误的CVE，期望描述'示例漏洞描述'，实际为'%s'", cveInfo.Description)
		}
	}

	// 测试查找不存在的CVE
	cveInfo = GetCVEInfo(cves, "CVE-2023-11111")
	if cveInfo != nil {
		t.Error("GetCVEInfo找到了不应存在的CVE")
	}
}

// TestExtractCVEsFromText 测试从文本中提取CVE ID
func TestExtractCVEsFromText(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		expected []string
	}{
		{
			name:     "简单提取",
			text:     "系统受到CVE-2021-44228漏洞的影响",
			expected: []string{"CVE-2021-44228"},
		},
		{
			name:     "多个CVE",
			text:     "系统受到CVE-2021-44228和CVE-2022-12345漏洞的影响",
			expected: []string{"CVE-2021-44228", "CVE-2022-12345"},
		},
		{
			name:     "格式不规范的CVE",
			text:     "系统受到cve-2021-44228漏洞的影响",
			expected: []string{"CVE-2021-44228"},
		},
		{
			name:     "没有CVE",
			text:     "系统运行正常，没有已知漏洞",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractCVEsFromText(tt.text)

			// 检查长度
			if len(result) != len(tt.expected) {
				t.Errorf("ExtractCVEsFromText() got %v items, want %v items", len(result), len(tt.expected))
				return
			}

			// 检查每个元素
			for i, cveID := range tt.expected {
				if i >= len(result) || result[i] != cveID {
					found := false
					for _, got := range result {
						if got == cveID {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("ExtractCVEsFromText() missing expected CVE: %v", cveID)
					}
				}
			}
		})
	}
}

// TestGroupCVEsByYear 测试按年份分组CVE ID
func TestGroupCVEsByYear(t *testing.T) {
	tests := []struct {
		name     string
		cveIDs   []string
		expected map[string][]string
	}{
		{
			name:   "按年份分组",
			cveIDs: []string{"CVE-2021-44228", "CVE-2022-12345", "CVE-2021-45046"},
			expected: map[string][]string{
				"2021": {"CVE-2021-44228", "CVE-2021-45046"},
				"2022": {"CVE-2022-12345"},
			},
		},
		{
			name:     "空列表",
			cveIDs:   []string{},
			expected: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GroupCVEsByYear(tt.cveIDs)

			// 检查长度
			if len(result) != len(tt.expected) {
				t.Errorf("GroupCVEsByYear() got %v groups, want %v groups", len(result), len(tt.expected))
				return
			}

			// 检查每个年份组
			for year, expectedIDs := range tt.expected {
				resultIDs, exists := result[year]
				if !exists {
					t.Errorf("GroupCVEsByYear() missing year group: %v", year)
					continue
				}

				if len(resultIDs) != len(expectedIDs) {
					t.Errorf("GroupCVEsByYear() year %v got %v items, want %v items",
						year, len(resultIDs), len(expectedIDs))
					continue
				}

				// 检查该年份的每个CVE
				for _, cveID := range expectedIDs {
					found := false
					for _, got := range resultIDs {
						if got == cveID {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("GroupCVEsByYear() year %v missing expected CVE: %v", year, cveID)
					}
				}
			}
		})
	}
}

// TestSortAndRemoveDuplicateCVEs 测试排序和去重CVE ID
func TestSortAndRemoveDuplicateCVEs(t *testing.T) {
	tests := []struct {
		name           string
		cveIDs         []string
		expectedUnique []string
		expectedSorted []string
	}{
		{
			name:           "排序和去重",
			cveIDs:         []string{"CVE-2022-12345", "cve-2021-44228", "CVE-2021-44228", "CVE-2021-0001"},
			expectedUnique: []string{"CVE-2021-0001", "CVE-2021-44228", "CVE-2022-12345"},
			expectedSorted: []string{"CVE-2021-0001", "CVE-2021-44228", "CVE-2022-12345"},
		},
		{
			name:           "空列表",
			cveIDs:         []string{},
			expectedUnique: []string{},
			expectedSorted: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 测试去重
			uniqueResult := RemoveDuplicateCVEs(tt.cveIDs)
			if len(uniqueResult) != len(tt.expectedUnique) {
				t.Errorf("RemoveDuplicateCVEs() got %v items, want %v items", len(uniqueResult), len(tt.expectedUnique))
			}

			// 先去重再排序
			sortedResult := SortCVEs(RemoveDuplicateCVEs(tt.cveIDs))
			if len(sortedResult) != len(tt.expectedSorted) {
				t.Errorf("SortCVEs() got %v items, want %v items", len(sortedResult), len(tt.expectedSorted))
				return
			}

			// 检查排序顺序
			for i, expected := range tt.expectedSorted {
				if i < len(sortedResult) && sortedResult[i] != expected {
					t.Errorf("SortCVEs() at position %v got %v, want %v", i, sortedResult[i], expected)
				}
			}
		})
	}
}

// TestValidateCVE 测试CVE ID验证
func TestValidateCVE(t *testing.T) {
	tests := []struct {
		name     string
		cveID    string
		expected bool
	}{
		{
			name:     "有效CVE",
			cveID:    "CVE-2021-44228",
			expected: true,
		},
		{
			name:     "标准化后有效",
			cveID:    "cve-2021-44228",
			expected: true,
		},
		{
			name:     "格式错误",
			cveID:    "CVE2021-44228",
			expected: false,
		},
		{
			name:     "年份超前",
			cveID:    "CVE-2099-12345",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCVE(tt.cveID)
			if result != tt.expected {
				t.Errorf("ValidateCVE(%v) = %v, want %v", tt.cveID, result, tt.expected)
			}
		})
	}
}

// TestCVEReferenceWithScagogoLibrary 测试CVEReference与scagogogo/cve库集成
func TestCVEReferenceWithScagogoLibrary(t *testing.T) {
	// 创建CVE引用对象
	cveRef := NewCVEReference("cve-2021-44228") // 使用小写格式

	// 检查是否自动应用了格式化
	if cveRef.CVEID != "CVE-2021-44228" {
		t.Errorf("NewCVEReference() should format CVE ID, got %v, want %v",
			cveRef.CVEID, "CVE-2021-44228")
	}

	// 添加受影响的CPE
	cveRef.AddAffectedCPE("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")

	// 测试查询功能
	cves := []*CVEReference{cveRef}

	// 使用不同格式的CVE ID进行查询
	cpes := QueryByCVE(cves, "cve-2021-44228")
	if len(cpes) != 1 {
		t.Errorf("QueryByCVE() got %v results, want 1", len(cpes))
	} else if cpes[0].Vendor != "apache" || cpes[0].ProductName != "log4j" {
		t.Errorf("QueryByCVE() returned incorrect CPE, got vendor=%v product=%v, want vendor=apache product=log4j",
			cpes[0].Vendor, cpes[0].ProductName)
	}

	// 测试QueryByProduct
	results := QueryByProduct(cves, "apache", "log4j", "")
	if len(results) != 1 {
		t.Errorf("QueryByProduct() got %v results, want 1", len(results))
	}

	// 测试不存在的产品
	noResults := QueryByProduct(cves, "apache", "tomcat", "")
	if len(noResults) != 0 {
		t.Errorf("QueryByProduct() for non-existent product got %v results, want 0", len(noResults))
	}
}

// TestGetRecentCVEs 测试获取最近几年的CVE
func TestGetRecentCVEs(t *testing.T) {
	currentYear := time.Now().Year()
	lastYear := currentYear - 1

	// 构建测试CVE列表，包含当前年份、去年和更早的CVE
	currentYearStr := time.Now().Format("2006")
	lastYearStr := time.Date(lastYear, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006")

	cveIDs := []string{
		"CVE-" + currentYearStr + "-12345",
		"CVE-" + lastYearStr + "-67890",
		"CVE-2018-11111",
	}

	// 获取最近1年的CVE
	recentCVEs1Year := GetRecentCVEs(cveIDs, 1)
	if len(recentCVEs1Year) != 1 {
		t.Errorf("GetRecentCVEs() for 1 year got %v results, expected only current year's CVE",
			len(recentCVEs1Year))
	}

	// 获取最近2年的CVE
	recentCVEs2Years := GetRecentCVEs(cveIDs, 2)
	if len(recentCVEs2Years) != 2 {
		t.Errorf("GetRecentCVEs() for 2 years got %v results, expected current and last year's CVEs",
			len(recentCVEs2Years))
	}
}
