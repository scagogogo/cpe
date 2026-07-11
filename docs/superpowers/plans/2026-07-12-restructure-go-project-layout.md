# 根目录代码目录化重组 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`
> Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将根目录下 122 个扁平散落的 `.go` 文件按经典 Go 库项目布局整理进 `pkg/` 子目录，使仓库根目录干净、结构清晰，同时不改变任何函数逻辑、不破坏测试、不引入循环依赖。

**Architecture:** 数据流不变（用户/CLI 调用 → cpeskills 包处理 → 输出）。当前根目录 122 个 `.go` 文件全部属于 `package cpeskills`，是一个单一大包，内部通过直接函数调用协作（无 import）。本重构采用"整体迁移、保持单包"策略：将根目录所有 `.go` 文件用 `git mv` 移入 `pkg/cpe/`，package 名保持 `cpeskills` 不变；`module github.com/scagogogo/cpe-skills` 不变；`pkg/parsers` 原位不动；`cmd/cpe` 与 `examples/*/main.go` 仅修改 import 路径（`"github.com/scagogogo/cpe-skills"` → `cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"`），别名沿用 `cpeskills`，所有调用点 `cpeskills.XXX` 零改动。这样既达成"经典 Go 项目目录组织"，又把机械改动收敛到"移动文件 + 改 import 路径"两类，规避分包子带来的循环依赖风险。

**Tech Stack:** Go 1.25.0（toolchain go1.25.3），module `github.com/scagogogo/cpe-skills`，cobra v1.8.1，MCP go-sdk v1.6.1，goreleaser（入口 `./cmd/cpe`），GitHub Actions CI（`go vet ./...` + `go test .` + `go test ./examples/... ./cmd/...`）

**Risks:**
- （高）根目录是单一 `package cpeskills`，存在双向依赖（`cpe.go:385` 调用 `wfn.go` 的 `FromCPE/CompareWFNs`；`wfn.go:91` `FromCPE` 接收 `cpe.go` 定义的 `*CPE`）。若激进拆成 `pkg/cpe`、`pkg/wfn` 等多子包，必然产生循环依赖，Go 编译器直接拒绝 → 缓解：**保持 `pkg/cpe/` 单包**，只移动文件不改 package 名、不改任何函数体。本 Plan 不做多子包拆分（那是独立的大重构）。
- （中）122 个文件移动会中断 `git blame` 历史追踪 → 缓解：全程使用 `git mv` 而非 `cp`+`rm`，Git 会记录 rename，`git log --follow` 可追溯。
- （中）CI 第 35 行 `go test ... .` 只测当前目录（根包），迁移后根目录不再有 `*.go`，该命令测不到东西 → 缓解：Task 5 将 `.` 改为 `./...`。
- （低）`cmd/cpe` 测试文件（3 个）也 import 根包别名 → 缓解：Task 3 用 `grep -rl` 覆盖所有非测试与测试文件统一替换。
- （低）`.goreleaser.yml` 入口 `./cmd/cpe` 不受影响 → 无需改动，仅在 Task 6 验证构建仍通过。

---

### Task 1: 预检当前构建与测试基线

**Depends on:** None
**Files:**
- Modify: 无（仅运行验证命令，建立"迁移前可用"基线）

- [ ] **Step 1: 确认 go vet 通过 — 确保迁移前代码无静态错误**

```bash
go vet ./...
```

Run: `go vet ./...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "error" 或 "vet:"

- [ ] **Step 2: 确认根包测试通过 — 建立迁移前测试基线**

Run: `go test -count=1 ./... 2>&1 | tail -20`
Expected:
  - Exit code: 0
  - Output contains: "ok" 与 "PASS"
  - Output does NOT contain: "FAIL" 或 "build failed"

- [ ] **Step 3: 确认 CLI 可构建 — 确保迁移前 cmd/cpe 编译通过**

Run: `go build -o /tmp/cpe-baseline ./cmd/cpe && /tmp/cpe-baseline --help | head -5`
Expected:
  - Exit code: 0
  - Output contains: "Available Commands" 或 "cpe"

- [ ] **Step 4: 提交基线快照（无变更则跳过）**

Run: `git status --porcelain | head`
Expected:
  - 无输出（工作区干净）；若有输出说明存在未提交改动，需先处理后再继续

---

### Task 2: 迁移根目录 .go 文件到 pkg/cpe/ — 整体保持单包

**Depends on:** Task 1
**Files:**
- Create: `pkg/cpe/`（目录）
- Move: 根目录 122 个 `.go` 文件 → `pkg/cpe/`（57 实现 + 65 测试）

**说明：** 这是本 Plan 的核心 Task。所有文件移入 `pkg/cpe/` 后仍属同一 `package cpeskills`，**不改任何 package 声明、不改任何函数体**。`manifest_bridge.go` 中的 `pkg/parsers` import 路径 `github.com/scagogogo/cpe-skills/pkg/parsers` 保持不变（module path 没变）。

- [ ] **Step 1: 创建目标目录 pkg/cpe/ — 承载迁移后的库代码**

Run: `mkdir -p pkg/cpe`
Expected:
  - Exit code: 0
  - `ls -d pkg/cpe` 输出 `pkg/cpe`

- [ ] **Step 2: 用 git mv 迁移全部 122 个 .go 文件 — 保留 Git rename 历史**

Run: `git mv *.go pkg/cpe/`
Expected:
  - Exit code: 0
  - `ls *.go 2>/dev/null | wc -l` 输出 `0`（根目录已无 .go 文件）
  - `ls pkg/cpe/*.go | wc -l` 输出 `122`

- [ ] **Step 3: 验证迁移后 package 声明一致 — 确认无 package 冲突**

Run: `grep -h "^package " pkg/cpe/*.go | sort | uniq -c`
Expected:
  - Exit code: 0
  - Output 只有一行：`122 package cpeskills`（全部一致，无冲突）

- [ ] **Step 4: 验证 pkg/cpe 内部编译通过 — 确认同包内调用未被破坏**

Run: `go build ./pkg/cpe/`
Expected:
  - Exit code: 0
  - Output 为空（编译成功）
  - Output does NOT contain: "undefined" 或 "imported and not used"

- [ ] **Step 5: 验证 pkg/cpe 测试通过 — 确认同包测试逻辑未受影响**

Run: `go test -count=1 ./pkg/cpe/ 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "ok" 与 "PASS"

- [ ] **Step 6: 提交迁移**

Run: `git add -A && git commit -m "refactor: move root package files to pkg/cpe (122 files, single package preserved)"`
Expected:
  - Exit code: 0
  - `git log -1 --oneline` 显示该 commit

---

### Task 3: 修正 cmd/cpe 的根包 import 路径 — 指向 pkg/cpe

**Depends on:** Task 2
**Files:**
- Modify: `cmd/cpe/*.go`（28 个非测试 + 3 个测试文件，共 31 处 import）

**说明：** `cmd/cpe` 通过别名 `cpeskills "github.com/scagogogo/cpe-skills"` import 根包。根包迁到 `pkg/cpe/` 后，路径变为 `github.com/scagogogo/cpe-skills/pkg/cpe`。**别名保持 `cpeskills` 不变**，因此所有 `cpeskills.XXX` 调用点零改动，只改 import 语句本身。

- [ ] **Step 1: 批量替换 cmd/cpe 中根包 import 路径 — 路径加 /pkg/cpe 后缀**

Run: `grep -rl '"github.com/scagogogo/cpe-skills"$\|cpeskills "github.com/scagogogo/cpe-skills"' cmd/cpe/*.go | xargs sed -i 's|"github.com/scagogogo/cpe-skills"|"github.com/scagogogo/cpe-skills/pkg/cpe"|g'`
Expected:
  - Exit code: 0
  - `grep -rn 'github.com/scagogogo/cpe-skills"' cmd/cpe/*.go | grep -v pkg/cpe | wc -l` 输出 `0`（无残留旧路径）

- [ ] **Step 2: 确认别名 cpeskills 仍保留 — 调用点无需改动**

Run: `grep -rn 'cpeskills "' cmd/cpe/*.go | head -5`
Expected:
  - Output 仍含 `cpeskills "github.com/scagogogo/cpe-skills/pkg/cpe"`（别名不变）

- [ ] **Step 3: 验证 cmd/cpe 编译通过 — 确认 import 路径修正成功**

Run: `go build ./cmd/cpe/`
Expected:
  - Exit code: 0
  - Output does NOT contain: "cannot find" 或 "no required module"

- [ ] **Step 4: 验证 cmd/cpe 测试通过**

Run: `go test -count=1 ./cmd/cpe/ 2>&1 | tail -5`
Expected:
  - Exit code: 0
  - Output contains: "ok"

- [ ] **Step 5: 提交**

Run: `git add -A && git commit -m "refactor(cmd/cpe): rebase root package import to pkg/cpe (alias cpeskills preserved)"`
Expected:
  - Exit code: 0

---

### Task 4: 修正 examples/*/main.go 的根包 import 路径

**Depends on:** Task 2
**Files:**
- Modify: `examples/01_basic_parsing/main.go` … `examples/10_cve_mapping/main.go`（10 个文件）

**说明：** 10 个示例 main.go 都用 `cpeskills "github.com/scagogogo/cpe-skills"` import 根包，同 Task 3 策略：路径加 `/pkg/cpe` 后缀，别名不变。

- [ ] **Step 1: 批量替换 examples 中根包 import 路径**

Run: `grep -rl 'cpeskills "github.com/scagogogo/cpe-skills"' examples/*/main.go | xargs sed -i 's|"github.com/scagogogo/cpe-skills"|"github.com/scagogogo/cpe-skills/pkg/cpe"|g'`
Expected:
  - Exit code: 0
  - `grep -rn 'github.com/scagogogo/cpe-skills"' examples/*/main.go | grep -v pkg/cpe | wc -l` 输出 `0`

- [ ] **Step 2: 验证 examples 全部编译通过**

Run: `go build ./examples/...`
Expected:
  - Exit code: 0
  - Output does NOT contain: "cannot find" 或 "undefined"

- [ ] **Step 3: 验证 examples 测试（CI 用 || true 容错）**

Run: `go test -count=1 ./examples/... 2>&1 | tail -10`
Expected:
  - 不出现编译错误（"cannot find"/"undefined"）
  - 各 example 编译型 main 包显示 "ok" 或 "no test files"

- [ ] **Step 4: 提交**

Run: `git add -A && git commit -m "refactor(examples): rebase root package import to pkg/cpe"`
Expected:
  - Exit code: 0

---

### Task 5: 修正 CI 测试命令以适配新目录结构

**Depends on:** Task 2
**Files:**
- Modify: `.github/workflows/ci.yml:35,38`

**说明：** CI 第 35 行 `go test -count=1 -race -coverprofile=coverage.out .` 中的 `.` 只测根目录包；根目录已无 `.go` 文件，必须改为 `./pkg/cpe/`（只测库包，保持覆盖率统计语义）或 `./...`（全量，但会把 examples/cmd 也算进覆盖率）。这里选 `./pkg/cpe/` 保持与原 `.` 同语义。第 38 行 `./examples/... ./cmd/...` 不变。

- [ ] **Step 1: 读取 CI 第 30-45 行 — 确认当前测试命令上下文**

Run: `sed -n '30,45p' .github/workflows/ci.yml`
Expected:
  - 输出包含 `go test -count=1 -race -coverprofile=coverage.out .`
  - 记录该行行号（约 35）

- [ ] **Step 2: 将第 35 行的 `.` 替换为 `./pkg/cpe/` — 保持"只测库包"语义**

文件: `.github/workflows/ci.yml:35`（"Run tests" 步骤，go test 命令行）

```yaml
      - name: Run tests
        run: go test -count=1 -race -coverprofile=coverage.out ./pkg/cpe/
```

Run: `sed -i 's|go test -count=1 -race -coverprofile=coverage.out \.|go test -count=1 -race -coverprofile=coverage.out ./pkg/cpe/|' .github/workflows/ci.yml`
Expected:
  - `grep -n 'coverprofile=coverage.out' .github/workflows/ci.yml` 输出含 `./pkg/cpe/` 而非 ` .`

- [ ] **Step 3: 补充 go vet 全量路径不变确认 — ./... 已覆盖全部子目录**

Run: `grep -n 'go vet' .github/workflows/ci.yml`
Expected:
  - 输出 `go vet ./...`（`./...` 自动覆盖 pkg/cpe、cmd、examples，无需改动）

- [ ] **Step 4: 本地模拟 CI 测试矩阵 — 确认命令在新结构下可用**

Run: `go vet ./... && go test -count=1 -race -coverprofile=/tmp/cov.out ./pkg/cpe/ && go test -count=1 -race ./examples/... ./cmd/... 2>&1 | tail -15`
Expected:
  - Exit code: 0
  - Output contains: "ok" 与 "PASS"
  - 覆盖率文件 `/tmp/cov.out` 生成

- [ ] **Step 5: 确认覆盖率数值未塌缩 — 迁移不应改变覆盖率**

Run: `go tool cover -func=/tmp/cov.out | tail -1`
Expected:
  - 输出类似 `total:	(statements)	9x.x%`
  - 覆盖率与迁移前（主包 99.5%）数量级一致

- [ ] **Step 6: 提交**

Run: `git add -A && git commit -m "ci: point test target at ./pkg/cpe/ after root package relocation"`
Expected:
  - Exit code: 0

---

### Task 6: 全量验证与收尾 — 构建产物、goreleaser dry-run、根目录整洁度

**Depends on:** Task 3, Task 4, Task 5
**Files:**
- Modify: 无（仅验证）

- [ ] **Step 1: 全量构建验证 — 确认所有包编译通过**

Run: `go build ./...`
Expected:
  - Exit code: 0
  - Output 为空

- [ ] **Step 2: 全量测试验证 — 确认所有测试通过**

Run: `go test -count=1 ./... 2>&1 | tail -15`
Expected:
  - Exit code: 0
  - Output contains: "ok"
  - Output does NOT contain: "FAIL"

- [ ] **Step 3: goreleaser dry-run 验证 — 确认发布构建配置未受影响**

Run: `goreleaser build --snapshot --clean --single-target 2>&1 | tail -15`
Expected:
  - Exit code: 0
  - Output contains: "build succeeded" 或 "done"（视版本，关键是无 error）
  - 入口仍为 `./cmd/cpe`，无需改动 `.goreleaser.yml`

- [ ] **Step 4: 验证根目录整洁度 — 确认根目录不再散落 .go 文件**

Run: `ls *.go 2>/dev/null | wc -l && echo "---" && ls -d */ | sort`
Expected:
  - 第一行输出 `0`（根目录无 .go 文件）
  - 目录列表包含 `cmd/ docs/ examples/ pkg/ scripts/ website/` 等，结构清晰

- [ ] **Step 5: 验证 pkg/ 目录结构符合经典 Go 库布局**

Run: `find pkg -maxdepth 2 -type d | sort && echo "---" && ls pkg/cpe/*.go | wc -l`
Expected:
  - 输出 `pkg/parsers`、`pkg/cpe` 两个子包
  - `pkg/cpe/` 含 122 个 .go 文件

- [ ] **Step 6: 最终提交（如有残留变更）**

Run: `git status --porcelain`
Expected:
  - 无输出（全部已提交）；若有残留，`git add -A && git commit -m "chore: finalize directory restructuring"`

---

## 迁移前后目录结构对照

**迁移前（根目录散落 122 .go）：**

```text
cpe-skills/
├── *.go              # 122 个文件，package cpeskills
├── cmd/cpe/          # 45 文件，package main
├── pkg/parsers/      # 2 文件，package parsers
├── examples/         # 10 个示例
├── website/ documents/ scripts/
├── go.mod  go.sum  .goreleaser.yml
└── .github/workflows/
```

**迁移后（经典 Go 库布局）：**

```text
cpe-skills/
├── pkg/
│   ├── cpe/          # 122 文件，package cpeskills（原根目录，整体迁入）
│   └── parsers/      # 2 文件，package parsers（原位不动）
├── cmd/cpe/          # 45 文件，package main（import 路径改 pkg/cpe）
├── examples/         # 10 个示例（import 路径改 pkg/cpe）
├── website/ documents/ scripts/
├── go.mod  go.sum  .goreleaser.yml   # module path 不变
├── docs/
└── .github/workflows/  # ci.yml 测试目标改 ./pkg/cpe/
```

## 为什么不拆成 pkg/cpe + pkg/wfn + pkg/storage 多子包？

调研发现根目录 `cpe.go:385` 与 `wfn.go:91` 存在**双向依赖**：`cpe.go` 调用 `wfn.go` 的 `FromCPE/CompareWFNs`，`wfn.go` 的 `FromCPE` 又接收 `cpe.go` 定义的 `*CPE` 类型。Go 不允许循环 import，强行拆包将无法编译。要拆多子包需先做"提取共享类型到底层包 + 重构函数签名"的前置大重构，不在本 Plan 范围。当前"整体迁入 `pkg/cpe/` 保持单包"是风险最低、收益明确（根目录干净、结构经典）的务实方案。
