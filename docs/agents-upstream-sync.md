# 上游同步

代码同步工具将本地 mock 仓库与 OpenHarmony 上游仓库保持同步。工具位于 `bin/update/`，支持并行 fetch（`Start-Job`）、冲突检测（逐文件解决）、智能枚举（`git ls-tree` 替代全量遍历）、自动删除上游已删文件、变更日志深化、备份机制和同步后自动构建。

## 核心原则

这些原则是**强制性的**，违反会破坏项目的基本设计：

1. **代码仓 = 上游副本**：同步后各代码仓目录（`datamgr_service/`、`data_share/` 等）必须与上游完全一致，**唯一例外**是本地编译用的 `CMakeLists.txt`。
2. **不修改上游代码**：不能修改代码仓内的上游源码或文件来修复编译问题。如果上游代码编译失败，**只能通过修改 `mock/` 目录下的代码**来适配（添加 mock 实现、头文件覆盖等）。
3. **保留 GN 文件**：`BUILD.gn` 文件虽然本地构建不使用，但必须保留——它们是编写和维护 `CMakeLists.txt` 的参考来源。
4. **保护本地修改**：同步时内置冲突检测——在 fetch 之后、reset 之前比较旧上游版本与本地文件，检测到冲突时逐文件提示用户选择保留或覆盖。不会静默丢弃本地修改。

## 基本命令

```powershell
# 完整同步（并行 fetch + 冲突检测 + 智能复制 + 自动删除）
.\bin\update\sync.ps1

# 只同步指定仓库
.\bin\update\sync.ps1 -Repos relational_store,datamgr_service

# 预览模式（不实际修改文件）
.\bin\update\sync.ps1 -WhatIf

# 同步并删除本地独有文件（受保护文件不会被删除）
.\bin\update\sync.ps1 -RemoveExtra

# 跳过冲突确认，自动覆盖（非交互式）
.\bin\update\sync.ps1 -Force

# 同步后自动构建（cmake + ninja）
.\bin\update\sync.ps1 -Build

# 跳过 Step 5 对比验证（加速同步）
.\bin\update\sync.ps1 -SkipVerification

# 预检查本地修改的文件（同步前安全检查）
.\bin\update\sync.ps1 -CheckLocal

# 从文件读取冲突保留列表（非交互式，每行一个 repo 相对路径，# 注释）
.\bin\update\sync.ps1 -ConflictFile keep.txt

# 全量对齐（复制所有上游文件，修复累积差异，建议每月执行）
.\bin\update\sync.ps1 -FullSync -Force
```

## 冲突检测与解决

sync.ps1 v3.1 在 fetch 之后、reset 之前检测冲突——比较旧上游版本与本地文件（先比大小，相同再比 SHA256）。当上游和本地都修改了同一文件时判定为冲突，被确认覆盖的冲突文件会自动备份到 `sync_output/<date>/backup/`。

**三种解决方式：**

| 方式 | 参数 | 适用场景 |
|---|---|---|
| 交互模式 | （默认） | 列出带编号的冲突文件，输入 `1,3,5` 保留指定文件、覆盖其余；`all` 覆盖全部，`none` 保留全部 |
| 全部覆盖 | `-Force` | 非交互式，跳过确认直接覆盖所有冲突文件 |
| 文件保留列表 | `-ConflictFile keep.txt` | 非交互式，文件中列出的路径不被覆盖（每行一个 repo 相对路径，`#` 注释），适用于 Agent 自动化场景 |

> **首次同步**：无 `oldCommit`（首次克隆或 `tmp/` 被删）时冲突检测不可用，脚本会输出警告，所有上游文件直接复制。

## 同步范围

涉及 8 个上游仓库（master 分支）：datamgr_service、kv_store、relational_store、data_object、data_share、preferences、udmf、interface_sdk（部分同步，只复制 `api/@ohos.data*` 等匹配文件）。配置见 `bin/update/update_config.json`。

## 受保护内容

同步时以下内容**不会被覆盖**：

- **目录**：`mock/`、`test/`、`utils_native/`、`googletest/`、`bin/`、`.git/`、`.idea/`、`cmake-build-debug/`、`build/`
- **文件**（按文件名匹配，保护所有目录下的同名文件）：`CMakeLists.txt`、`dllmain.cpp/h`、`appdatamgr.gni`、`OAT.xml`、`README.md`、`README_zh.md`、`LICENSE`、`.clang-format`、`.gitignore`、`CLAUDE.md`、`account_delegate_mock.cpp/h`、`cloud_server_mock.cpp/h`

`CMakeLists.txt` 受保护是因为本地用 CMake 构建系统，与 OpenHarmony 的 GN 构建系统不同，必须保留以支持本地编译。

## 同步后验证

同步后必须验证构建是否通过：

1. 全量构建收集失败：`./ninja.exe -C cmake-build-debug -k0 -j4 2>&1 | tee tmp/build_output.log`
2. 提取失败列表：`grep "FAILED:" tmp/build_output.log | sort -u`
3. 编译修复流程见 [本地编译及编译修复](./agents-build-and-fix.md)

同步流程详见 [上游同步流程](./upstream_sync_workflow.md)，编译修复流程见 [编译修复流程](./build_and_fix_workflow.md)。

## 同步工具生成的报告

| 产物 | 路径 | 说明 |
|---|---|---|
| 冲突文件备份 | `sync_output/<date>/backup/<repo>/<path>` | 被覆盖冲突文件的备份（超 7 天自动清理） |
| 本地独有文件报告 | `sync_output/<date>/extra_files_*.md` | 本地有但上游没有的文件 |
| 差异报告 | `sync_output/<date>/diff_report_*.md` | 源 vs 本地对比结果 |
| 变更日志 | `sync_output/<date>/change_log_*.md` | 通过 `--deepen` 获取完整提交链 |
| 同步状态 | `bin/update/.sync_state.json` | 每个仓库的 commit hash + 时间戳 |
| 同步日志 | `sync_output/<date>/sync_*.log` | 同步过程日志 |

完整同步工作流和 AI Agent 规则见 [`.skills/openharmony-sync/SKILL.md`](../.skills/openharmony-sync/SKILL.md)。同步工具详细文档见 [bin/update/README.md](../bin/update/README.md)，快速参考见 [bin/update/QUICKSTART.md](../bin/update/QUICKSTART.md)。
