# CPE 匹配

本示例演示如何使用 CPE 库进行基本的 CPE 匹配操作，包括精确匹配、模式匹配和批量匹配。

## 概述

CPE 匹配是识别和比较软件组件的核心功能。本示例展示了各种匹配技术，从简单的字符串比较到复杂的模式匹配。

下图展示了两个 CPE 如何逐组件比较并得出它们之间的关系：

```mermaid
flowchart TD
    Start(["源 CPE + 目标 CPE"]) --> Loop["逐组件比较"]
    Loop --> Check{"组件取值"}
    Check -->|"通配符 * 或 -"| Wild["视为匹配 / 任意"]
    Check -->|"精确值"| Exact["要求取值完全相同"]
    Wild --> Agg["汇总比较结果"]
    Exact --> Agg
    Agg --> Rel{"整体关系"}
    Rel --> Equal["相等"]
    Rel --> Subset["子集"]
    Rel --> Superset["超集"]
    Rel --> Disjoint["不相交"]
```

下图总结了如何选择匹配模式：

```mermaid
flowchart LR
    Need(["你的需求是什么？"]) --> A["精确：所有字段完全相同"]
    Need --> B["子集：目标比条件更窄"]
    Need --> C["超集：目标比条件更宽"]
    Need --> D["距离：相似度分数高于阈值"]
```

## 完整示例

```go
package main

import (
    "fmt"
    "strings"
    "github.com/scagogogo/cpe-skills"
)

func main() {
    fmt.Println("=== CPE匹配示例 ===")
    
    // 示例1：基本匹配
    fmt.Println("\n1. 基本匹配:")
    
    // 创建测试CPE
    cpe1, _ := cpeskills.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
    cpe2, _ := cpeskills.ParseCpe23("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
    cpe3, _ := cpeskills.ParseCpe23("cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*")
    
    fmt.Printf("CPE1: %s\n", cpe1.GetURI())
    fmt.Printf("CPE2: %s\n", cpe2.GetURI())
    fmt.Printf("CPE3: %s\n", cpe3.GetURI())
    
    // 精确匹配
    fmt.Printf("CPE1 == CPE2: %t\n", cpe1.Match(cpe2))
    fmt.Printf("CPE1 == CPE3: %t\n", cpe1.Match(cpe3))
    
    // 示例2：通配符匹配
    fmt.Println("\n2. 通配符匹配:")
    
    // 创建通配符模式
    pattern, _ := cpeskills.ParseCpe23("cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*")
    
    testCPEs := []string{
        "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",
        "cpe:2.3:a:microsoft:office:2019:*:*:*:*:*:*:*",
        "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",
    }
    
    fmt.Printf("匹配模式: %s\n", pattern.GetURI())
    fmt.Println("匹配结果:")
    
    for i, cpeStr := range testCPEs {
        testCPE, _ := cpeskills.ParseCpe23(cpeStr)
        match := pattern.Match(testCPE)
        
        status := "❌"
        if match {
            status = "✅"
        }
        
        fmt.Printf("  %s %d. %s %s\n", status, i+1, testCPE.Vendor, testCPE.ProductName)
    }
    
    // 示例3：版本范围匹配
    fmt.Println("\n3. 版本范围匹配:")
    
    // 定义版本范围
    baseProduct := "cpe:2.3:a:apache:tomcat"
    versions := []string{"8.5.0", "9.0.0", "9.0.1", "9.1.0", "10.0.0"}
    
    // 目标版本范围：9.x系列
    targetPattern := "9."

    fmt.Printf("匹配Tomcat %s*版本:\n", targetPattern)

    for _, version := range versions {
        cpeStr := fmt.Sprintf("%s:%s:*:*:*:*:*:*:*", baseProduct, version)
        testCPE, _ := cpeskills.ParseCpe23(cpeStr)

        // 判断版本是否属于 9.x 系列
        match := strings.HasPrefix(string(testCPE.Version), targetPattern)

        status := "❌"
        if match {
            status = "✅"
        }

        fmt.Printf("  %s Tomcat %s\n", status, version)
    }
    
    // 示例4：组件类型匹配
    fmt.Println("\n4. 组件类型匹配:")
    
    mixedCPEs := []string{
        "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*",      // 应用程序
        "cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*",      // 操作系统
        "cpe:2.3:h:cisco:catalyst_2960:*:*:*:*:*:*:*:*",     // 硬件
        "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*",       // 应用程序
    }
    
    // 只匹配应用程序
    fmt.Println("应用程序组件:")
    for i, cpeStr := range mixedCPEs {
        testCPE, _ := cpeskills.ParseCpe23(cpeStr)
        
        if testCPE.Part.ShortName == "a" {
            fmt.Printf("  ✅ %d. %s %s\n", i+1, testCPE.Vendor, testCPE.ProductName)
        } else {
            fmt.Printf("  ❌ %d. %s %s (%s)\n", i+1, testCPE.Vendor, testCPE.ProductName, testCPE.Part.LongName)
        }
    }
    
    // 示例5：供应商匹配
    fmt.Println("\n5. 供应商匹配:")
    
    vendors := []string{"microsoft", "apache", "oracle", "cisco"}
    
    for _, vendor := range vendors {
        fmt.Printf("\n%s 产品:\n", vendor)
        
        for i, cpeStr := range mixedCPEs {
            testCPE, _ := cpeskills.ParseCpe23(cpeStr)
            
            if string(testCPE.Vendor) == vendor {
                fmt.Printf("  ✅ %d. %s (%s)\n", i+1, testCPE.ProductName, testCPE.Part.LongName)
            }
        }
    }
    
    // 示例6：批量匹配
    fmt.Println("\n6. 批量匹配:")
    
    // 创建CPE列表
    cpeList := []*cpeskills.CPE{}
    for _, cpeStr := range mixedCPEs {
        testCPE, _ := cpeskills.ParseCpe23(cpeStr)
        cpeList = append(cpeList, testCPE)
    }
    
    // 定义匹配条件
    matchConditions := []struct {
        name      string
        condition func(*cpeskills.CPE) bool
    }{
        {
            "Microsoft产品",
            func(c *cpeskills.CPE) bool { return c.Vendor == "microsoft" },
        },
        {
            "应用程序",
            func(c *cpeskills.CPE) bool { return c.Part.ShortName == "a" },
        },
        {
            "版本10",
            func(c *cpeskills.CPE) bool { return c.Version == "10" },
        },
        {
            "网络设备",
            func(c *cpeskills.CPE) bool { return c.Part.ShortName == "h" },
        },
    }
    
    for _, condition := range matchConditions {
        fmt.Printf("\n匹配条件: %s\n", condition.name)
        matchCount := 0
        
        for i, testCPE := range cpeList {
            if condition.condition(testCPE) {
                fmt.Printf("  ✅ %d. %s %s %s\n", i+1, testCPE.Vendor, testCPE.ProductName, testCPE.Version)
                matchCount++
            }
        }
        
        fmt.Printf("  匹配数量: %d/%d\n", matchCount, len(cpeList))
    }
    
    // 示例7：复合匹配条件
    fmt.Println("\n7. 复合匹配条件:")
    
    // 复合条件：Microsoft的应用程序
    fmt.Println("Microsoft应用程序:")
    for i, testCPE := range cpeList {
        if testCPE.Vendor == "microsoft" && testCPE.Part.ShortName == "a" {
            fmt.Printf("  ✅ %d. %s %s\n", i+1, testCPE.ProductName, testCPE.Version)
        }
    }
    
    // 示例8：模糊匹配
    fmt.Println("\n8. 模糊匹配:")
    
    // 模糊匹配示例（产品名称相似性）
    targetProduct := "windows"
    similarProducts := []string{"windows", "win", "microsoft_windows", "windows_server"}
    
    fmt.Printf("与'%s'相似的产品:\n", targetProduct)
    
    for _, product := range similarProducts {
        // 简单的相似度计算（包含关系）
        similarity := 0.0
        if product == targetProduct {
            similarity = 1.0
        } else if len(product) > 0 && len(targetProduct) > 0 {
            if product == "win" && targetProduct == "windows" {
                similarity = 0.7 // 缩写匹配
            } else if (product == "microsoft_windows" || product == "windows_server") && targetProduct == "windows" {
                similarity = 0.8 // 包含匹配
            }
        }
        
        status := "❌"
        if similarity >= 0.7 {
            status = "✅"
        }
        
        fmt.Printf("  %s %s (相似度: %.1f)\n", status, product, similarity)
    }
    
    // 示例9：匹配统计
    fmt.Println("\n9. 匹配统计:")
    
    stats := map[string]int{
        "总CPE数量":   len(cpeList),
        "应用程序":     0,
        "操作系统":     0,
        "硬件设备":     0,
        "Microsoft": 0,
        "Apache":    0,
        "其他供应商":    0,
    }
    
    for _, testCPE := range cpeList {
        switch testCPE.Part.ShortName {
        case "a":
            stats["应用程序"]++
        case "o":
            stats["操作系统"]++
        case "h":
            stats["硬件设备"]++
        }
        
        switch testCPE.Vendor {
        case "microsoft":
            stats["Microsoft"]++
        case "apache":
            stats["Apache"]++
        default:
            stats["其他供应商"]++
        }
    }
    
    fmt.Println("匹配统计结果:")
    for category, count := range stats {
        fmt.Printf("  %s: %d\n", category, count)
    }
}
```

## 预期输出

```text
=== CPE匹配示例 ===

1. 基本匹配:
CPE1: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
CPE2: cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*
CPE3: cpe:2.3:a:microsoft:windows:11:*:*:*:*:*:*:*
CPE1 == CPE2: true
CPE1 == CPE3: false

2. 通配符匹配:
匹配模式: cpe:2.3:a:microsoft:*:*:*:*:*:*:*:*:*
匹配结果:
  ✅ 1. microsoft windows
  ✅ 2. microsoft office
  ❌ 3. apache tomcat
  ❌ 4. microsoft windows

3. 版本范围匹配:
匹配Tomcat 9.*版本:
  ❌ Tomcat 8.5.0
  ✅ Tomcat 9.0.0
  ✅ Tomcat 9.0.1
  ✅ Tomcat 9.1.0
  ❌ Tomcat 10.0.0

4. 组件类型匹配:
应用程序组件:
  ✅ 1. microsoft windows
  ❌ 2. microsoft windows (Operating System)
  ❌ 3. cisco catalyst_2960 (Hardware)
  ✅ 4. apache tomcat

5. 供应商匹配:

microsoft 产品:
  ✅ 1. windows (Application)
  ✅ 2. windows (Operating System)

apache 产品:
  ✅ 4. tomcat (Application)

cisco 产品:
  ✅ 3. catalyst_2960 (Hardware)

6. 批量匹配:

匹配条件: Microsoft产品
  ✅ 1. microsoft windows 10
  ✅ 2. microsoft windows 10
  匹配数量: 2/4

匹配条件: 应用程序
  ✅ 1. microsoft windows 10
  ✅ 4. apache tomcat 9.0.0
  匹配数量: 2/4

匹配条件: 版本10
  ✅ 1. microsoft windows 10
  ✅ 2. microsoft windows 10
  匹配数量: 2/4

匹配条件: 网络设备
  ✅ 3. cisco catalyst_2960 *
  匹配数量: 1/4

7. 复合匹配条件:
Microsoft应用程序:
  ✅ 1. windows 10

8. 模糊匹配:
与'windows'相似的产品:
  ✅ windows (相似度: 1.0)
  ✅ win (相似度: 0.7)
  ✅ microsoft_windows (相似度: 0.8)
  ✅ windows_server (相似度: 0.8)

9. 匹配统计:
匹配统计结果:
  总CPE数量: 4
  应用程序: 2
  操作系统: 1
  硬件设备: 1
  Microsoft: 2
  Apache: 1
  其他供应商: 1
```

## 匹配判定状态机

匹配过程是一个状态机：每次属性比较都把关系推向六种结局之一。下图展示 `ANY` 与 `NA` 如何驱动状态转换：

```mermaid
stateDiagram-v2
    [*] --> compare_attr_1
    compare_attr_1 --> compare_attr_2: equal
    compare_attr_1 --> mark_superset: source ANY
    compare_attr_1 --> mark_subset: target ANY
    compare_attr_1 --> mark_disjoint: mismatch (neither ANY)

    compare_attr_2 --> compare_attr_3: equal
    compare_attr_2 --> update_superset: source ANY
    compare_attr_2 --> update_subset: target ANY
    compare_attr_2 --> mark_disjoint: mismatch

    compare_attr_3 --> ... : ... (11 fields)

    state aggregate {
        [*] --> tally
        tally --> RelationEqual: all equal
        tally --> RelationSuperset: source had more ANYs
        tally --> RelationSubset: target had more ANYs
        tally --> RelationDisjoint: any mismatch
        tally --> RelationOverlap: mixed ANY + mismatch
    }

    ... --> aggregate
```

## 关键概念

### 1. 匹配类型

- **精确匹配**: 所有字段完全相同
- **通配符匹配**: 使用`*`匹配任意值
- **模式匹配**: 使用正则表达式或模式
- **范围匹配**: 版本或数值范围匹配

### 2. 匹配策略

- **字段级匹配**: 逐个字段比较
- **语义匹配**: 理解同义词和缩写
- **模糊匹配**: 基于相似度的匹配
- **结构化匹配**: 考虑 CPE 层次结构

### 3. 性能考虑

- **索引优化**: 为频繁查询的字段建立索引
- **批量处理**: 一次处理多个匹配操作
- **缓存结果**: 缓存常用的匹配结果
- **早期终止**: 在确定不匹配时提前退出

### 4. 版本比较

- `exact`: 精确版本匹配
- `greater`: 目标版本 >= 条件版本
- `less`: 目标版本 <= 条件版本
- `range`: 版本在指定范围内

## 最佳实践

1. **选择合适的匹配类型**: 根据需求选择精确匹配或模糊匹配
2. **使用通配符**: 合理使用通配符提高匹配灵活性
3. **验证输入**: 在匹配前验证 CPE 格式的正确性
4. **处理边界情况**: 考虑空值、特殊字符等情况
5. **性能监控**: 监控匹配操作的性能表现

## 下一步

- 学习[高级匹配](./advanced-matching.md)技术
- 了解[版本比较](./version-comparison.md)的详细方法
- 探索[CPE 集合](./sets.md)的批量匹配操作
