---
title: 最佳实践
outline: deep
---

# ✅ 最佳实践

在生产环境安全、高效地使用 `cpeskills` SDK 的建议。

## 在边界处校验输入

不要信任来自 SBOM、清单文件或用户输入的 CPE 字符串。先经 `Parse` 与 `ValidateCPE` 处理，再存储或匹配。

```go
import "github.com/scagogogo/cpe-skills"

func ingest(raw string) (*cpeskills.CPE, error) {
    c, err := cpeskills.Parse(raw) // 自动识别 2.2 / 2.3
    if err != nil {
        return nil, err
    }
    if err := cpeskills.ValidateCPE(c); err != nil {
        return nil, err
    }
    return cpeskills.NormalizeCPE(c), nil
}
```

## 处理类型化错误，而非字符串

SDK 返回带 `ErrorType` 的 `*CPEError`。用 `IsXxxError` 谓词按原因分支，而不是字符串匹配消息。

```go
if err := cpeskills.ValidateCPE(c); err != nil {
    switch {
    case cpeskills.IsInvalidFormatError(err):
        log.Printf("拒绝格式错误的输入")
    case cpeskills.IsInvalidPartError(err):
        log.Printf("拒绝非法 part")
    case cpeskills.IsOperationFailedError(err):
        log.Printf("可重试的存储失败: %v", err)
    }
}
```

完整错误分类见 [/zh/api/modules/errors](/zh/api/modules/errors)。

## `MustParse` 仅限字面量

`MustParse` 失败会 panic。仅用于编译期已知的包级变量值。其余场景一律用 `Parse` 并传播错误。

```go
var baseline = cpeskills.MustParse("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
// 运行时输入: 用 Parse，绝不用 MustParse
```

## 规范化厂商与产品名

厂商拼写千差万别（`Microsoft`、`microsoft`、`Microsoft Corp.`）。`NormalizeCPEVendorProduct` 与 `VendorNormalizer` 把别名收敛为规范形式，避免匹配时漏掉重复项。

```go
n := cpeskills.NewVendorNormalizer()
c2 := n.NormalizeCPE(c)                  // 规范化
n.RegisterVendorAlias("msft", "microsoft")
```

## 并发批量处理，但要设上限

`BatchScanner` 以并发限制运行扫描。并发数应匹配你的 CPU 与数据源限速，而不是直接抄 `runtime.NumCPU()`。

```go
idx := cpeskills.NewCPEIndex(cpes)
bs := cpeskills.NewBatchScanner(idx, 8) // 8 个 worker
bs.SetDataSources([]*cpeskills.VulnDataSource{src})
results, err := bs.Scan(components)
```

## 本地缓存 NVD 数据

NVD 数据源大且有限速。`DefaultNVDFeedOptions()` 默认缓存 24 小时于临时目录；生产环境请把 `CacheDir` 指向持久卷并提高 `CacheMaxAge`，避免重启即重下。

```go
opts := cpeskills.DefaultNVDFeedOptions()
opts.CacheDir = "/var/cache/nvd"
opts.CacheMaxAge = 168
```

## 用 `CPEIndex` 查找而非线性扫描

对固定集合的重复匹配，构建一次 `CPEIndex` 后调用 `Lookup`。在热路径里对大切片做线性扫描是最常见的性能回归。

## 小结

在边界校验、按类型化错误分支、`MustParse` 只用于字面量、规范化名称、限制并发、缓存 NVD 数据。这些习惯能挡住绝大多数真实事故。
