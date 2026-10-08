# 上游同步流程指南

本文档记录从上游 OpenHarmony 仓库同步代码到本地 mock 仓库的完整流程。同步完成后，请参阅 [编译修复流程](./build_and_fix_workflow.md) 执行构建验证与修复。

---

## 同步概览

```
步骤 1: 执行 sync.ps1     → 增量 fetch + 冲突检测 + 智能复制 + 自动删除上游已删文件
步骤 2: 检查同步报告       → 查看冲突、删除、本地独有文件报告
步骤 3: 验证构建（可选）    → 参阅编译修复流程文档
```

---

## 步骤 1: 上游同步

### 命令

```powershell
cd D:\Projects\ClionProjects\mock\appdata_master_mock
.\bin\update\sync.ps1                        # 完整同步（并行 fetch + 冲突检测 + 智能复制 + 自动删除）
.\bin\update\sync.ps1 -Repos relational_store # 只同步指定仓库
.\bin\update\sync.ps1 -WhatIf                 # 预览模式（不修改文件）
.\bin\update\sync.ps1 -RemoveExtra            # 同步并删除本地独有文件
.\bin\update\sync.ps1 -Force                  # 跳过冲突确认，自动覆盖
.\bin\update\sync.ps1 -Build                  # 同步后自动构建（cmake + ninja）
.\bin\update\sync.ps1 -SkipVerification       # 跳过 Step 5 对比验证
.\bin\update\sync.ps1 -CheckLocal             # 预检查本地修改的文件
.\bin\update\sync.ps1 -ConflictFile keep.txt  # 从文件读取冲突保留列表
```

### 同步机制（v3.1 并行 fetch + 并行 deepen + 智能枚举 + 逐文件冲突解决）

sync.ps1 v3.1 在 v3 基础上增加了并行 deepen、fetch 超时、失败仓库报告、ls-tree 缓存复用、进度指示器、旧产物自动清理，并修复了 `-RemoveExtra` 空目录清理边界和 `-Build` 构建日志路径问题。

**v3.1 优化（8 项）**：

1. **并行 deepen + 变更日志**：`git fetch --deepen N` 和变更日志生成移入并行 fetch job（之前在 Phase B 串行执行）。8 个仓库的 deepen 现在与 fetch 并行完成
2. **fetch 超时保护**：并行 fetch 添加 300 秒超时，超时后停止 job 并标记仓库失败，防止网络挂起导致无限等待
3. **失败仓库报告**：fetch 失败或超时的仓库在最终摘要中显示 `Failed: N` 和具体错误，标注 `ACTION REQUIRED`
4. **ls-tree 缓存复用**：Step 3 的 `git ls-tree` 结果缓存在 repo state 中，Step 5 直接复用，避免重复调用
5. **进度指示器**：并行 fetch 显示 `[i/8] repos fetched`；Step 5 每 500 文件输出 `compared N files`
6. **旧产物自动清理**：`Cleanup-OldSyncOutput` 清理整个旧日期目录（之前只清理 `backup/` 子目录）
7. **修复 `-RemoveExtra` 空目录清理**：使用每个文件对应的仓库 `TargetPath`（之前错误使用最后一个仓库的路径）
8. **修复 `-Build` 构建日志路径**：写到项目根 `tmp/build_output.log`（之前写到 `bin/update/tmp/`）

**v3 基础优化（10 项，保留）**：

1. **并行 fetch**：当 `parallelSync` 为 `true` 时，所有仓库的 `git fetch` 通过 `Start-Job` 并行执行。fetch 是网络 I/O 密集型操作，并行化显著减少总等待时间。冲突检测和 reset 保持串行（需要交互式确认）
2. **冲突检测**：在 fetch 之后、reset 之前，比较旧上游版本与本地文件。先比文件大小（快速），大小相同再比 SHA256 哈希
3. **逐文件冲突解决**：交互模式下列出带编号的冲突文件，用户可输入保留的编号（如 `1,3,5`），或 `all`/`none`。支持 `-ConflictFile` 参数从文件读取保留列表，适用于非交互式场景
4. **变更检测**：比较 fetch 前后的 commit hash。未变则标记 `UP TO DATE` 跳过后续步骤
5. **智能复制**：直接遍历 `git diff` 返回的变更文件列表，不再全量枚举 clone 目录。仅首次同步回退到全量 `Get-ChildItem` 枚举
6. **自动删除上游已删文件 + 空目录清理**：通过 `git diff --diff-filter=D` 获取上游已删文件列表，在本地自动删除。删除后自动清理遗留的空目录
7. **变更日志深化**：通过 `git fetch --deepen N`（默认 100）临时扩展浅克隆深度，获取完整提交链用于 `git log`。v2 的浅克隆只有 1 个 commit 历史，变更日志几乎为空。v3.1 将 deepen 移入并行 fetch job
8. **备份机制**：被用户确认覆盖的冲突文件在覆盖前自动备份到 `sync_output/<date>/backup/`。超过 `backupRetentionDays`（默认 7 天）的备份自动清理。v3.1 扩展为清理整个旧日期目录
9. **部分同步**：`interface_sdk` 配置了 `partialSync: true` + `includePatterns`，只复制匹配的文件（约 25 个）
10. **智能枚举**：使用 `git ls-tree` 替代 `Get-ChildItem` 遍历上游文件（git 内部索引，无需文件系统 I/O）。本地独有文件检测使用 HashSet（O(1)）替代逐文件 `Test-Path`。v3.1 缓存 ls-tree 结果供 Step 5 复用

### 冲突检测详解

冲突检测的关键时机在 `git fetch` 之后、`git reset --hard` 之前。此时工作区还是旧版本，可以直接比较旧上游版本 vs 本地文件。检测时先比文件大小（快速），大小相同再比 SHA256 哈希。

**冲突判定逻辑**：

| 上游状态 | 本地状态 | 大小比较 | 哈希比较 | 结果 |
|----------|----------|----------|----------|------|
| 修改 | 未修改 | 相同 | 相同 | 正常覆盖（无冲突） |
| 修改 | 已修改 | 不同 | — | **冲突** |
| 修改 | 已修改 | 相同 | 不同 | **冲突** |
| 新增 | 不存在 | — | — | 正常复制 |
| 删除 | 存在 | — | — | 自动删除（走删除流程） |

**冲突解决方式**：

- **交互模式**：列出带编号的冲突文件。输入 `all` 或回车覆盖全部；输入 `none` 保留全部；输入编号如 `1,3,5` 保留指定文件、覆盖其余
- **`-Force`**：跳过确认，自动覆盖所有冲突文件
- **`-ConflictFile <path>`**：从文件读取保留列表（每行一个 repo 相对路径，`#` 注释），列出的文件不被覆盖

**首次同步**：当无 `oldCommit`（首次克隆或 `tmp/` 被删）时，冲突检测不可用，脚本会输出警告。所有上游文件直接复制。

### 同步范围

涉及 8 个上游仓库（master 分支）：
- datamgr_service, kv_store, relational_store, data_object
- data_share, preferences, udmf, interface_sdk（部分同步）

### 受保护内容（不会被覆盖）

- **目录**: `mock/`, `test/`, `utils_native/`, `googletest/`, `bin/`, `.git/`, `.idea/`, `cmake-build-debug/`, `build/`
- **文件**（按文件名匹配，保护所有目录下的同名文件）: `CMakeLists.txt`, `dllmain.cpp/h`, `appdatamgr.gni`, `OAT.xml`, `README.md`, `README_zh.md`, `LICENSE`, `.clang-format`, `.gitignore`, `CLAUDE.md`, `account_delegate_mock.cpp/h`, `cloud_server_mock.cpp/h`

### 生成物

所有同步产物统一输出到 `sync_output/<date>/`（按日期组织）：

- `sync_output/<date>/backup/<repo>/<path>` — 被覆盖冲突文件的备份（超 7 天自动清理）
- `sync_output/<date>/extra_files_*.md` — 本地独有文件报告（本地有但上游从未有过的文件；上游已删文件已自动删除）
- `sync_output/<date>/diff_report_*.md` — 差异报告（源 vs 本地对比结果）
- `sync_output/<date>/change_log_*.md` — 变更日志（通过 `--deepen` 获取完整提交链）
- `sync_output/<date>/sync_*.log` — 同步日志
- `bin/update/.sync_state.json` — 同步状态（每个仓库的 commit hash + 时间戳）

### 同步后的影响

上游同步只更新 `mock/` 和 `test/` 之外的头文件和源文件，但：
1. 上游头文件可能新增/修改了接口，导致 mock 实现不匹配
2. 上游源文件可能新增了 `#include`，导致缺少头文件路径
3. 上游 `.cpp` 可能新增了符号调用，导致链接失败
4. 上游测试文件已更新，但本地 CMake 还是旧的（test/ 受保护）

遇到编译问题时，请参阅 [编译修复流程](./build_and_fix_workflow.md)。
