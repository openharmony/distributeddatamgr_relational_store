# AGENTS.md

本文件为此代码仓库的 AGENTS 指南，为 AI 辅助开发工具（OpenCode / ZCode / Claude Code 等）在此仓库中工作时提供项目约定和指导。

基于**渐进式披露原则**，本文件仅包含任务路由和核心约束。具体操作指南见 `docs/` 下的独立文档。

## 任务路由表

| 要做什么 | 去哪份文档 | 关键命令 |
|---|---|---|
| 从上游同步最新代码 | [docs/agents-upstream-sync.md](./docs/agents-upstream-sync.md) | `.\bin\update\sync.ps1` |
| 本地编译 / 编译修复 | [docs/agents-build-and-fix.md](./docs/agents-build-and-fix.md) | `./ninja.exe -C cmake-build-debug -j16` |
| 同步后全量构建收集失败 | [docs/agents-build-and-fix.md](./docs/agents-build-and-fix.md#全量构建与失败收集) | `./ninja.exe -C cmake-build-debug -k0 -j16` |
| GN 到 CMake 转换 | [docs/agents-build-and-fix.md](./docs/agents-build-and-fix.md#gn-到-cmake-转换原则) | 参考 `.skills/gn-to-cmake-test-converter/SKILL.md` |
| 对比 GN/CMake 产物 | [docs/gn-vs-cmake-targets.md](./docs/gn-vs-cmake-targets.md) | 同步后重生成：`bash bin/update/gen-target-comparison.sh` |
| 运行测试 / 测试修复 | [docs/agents-test-guide.md](./docs/agents-test-guide.md) | `ctest --output-on-failure -j1` |
| 构建并运行单个测试 | [docs/agents-test-guide.md](./docs/agents-test-guide.md#构建并运行单个测试) | `./ninja.exe -C cmake-build-debug -j16 NativeRdbTest && ./cmake-build-debug/bin/NativeRdbTest.exe` |
| 提交本地变更到 mock 仓库 | [docs/agents-git-workflow.md](./docs/agents-git-workflow.md) | `git commit -m "feat: ..."` |
| 了解模块架构 | [docs/agents-architecture.md](./docs/agents-architecture.md) | 查看对应模块的 `AGENTS.md` |

## 路径路由

当修改以下目录下的文件时，先阅读对应文档：

| 修改哪个目录 | 必读文档 | 关键约束 |
|---|---|---|
| `mock/` | [.skills/openharmony-sync/SKILL.md](./.skills/openharmony-sync/SKILL.md) § Principle 5 | mock/ 是唯一适配层，系统 API mock 只能加在此处，用 `include BEFORE` 覆盖上游头文件 |
| `test/<module>/` | [docs/agents-build-and-fix.md](./docs/agents-build-and-fix.md#gn-到-cmake-转换原则) | 测试 CMake 配置必须放在 `test/` 下，不在模块内联 |
| `CMakeLists.txt`（任意目录） | [.skills/gn-to-cmake-test-converter/SKILL.md](./.skills/gn-to-cmake-test-converter/SKILL.md) | 必须对照同目录 `BUILD.gn` 编写，保留 GN 文件 |
| 上游仓库目录（见约束 1） | — | **禁止修改**，编译问题通过 `mock/` 适配 |

## 术语路由

遇到以下术语时，参阅对应文档：

| 术语 | 含义 | 去哪了解 |
|---|---|---|
| `BUILD.gn` | 上游 GN 构建文件，CMakeLists.txt 的参考来源 | [docs/agents-build-and-fix.md](./docs/agents-build-and-fix.md#gn-到-cmake-转换原则) |
| `sync.ps1` | 上游代码同步脚本 v3.1（10 参数） | [bin/update/README.md](./bin/update/README.md) |
| `dlopen` mock | 动态库加载 mock，用于模拟系统服务 | [docs/agents-test-guide.md](./docs/agents-test-guide.md#动态库加载dlopenmock) |
| `include BEFORE` | CMake 头文件覆盖技巧，mock 头文件优先于上游 | [.skills/openharmony-sync/SKILL.md](./.skills/openharmony-sync/SKILL.md) § Principle 2 |
| `appdatamgr.gni` | GN 包含文件（受保护，不覆盖） | [docs/agents-upstream-sync.md](./docs/agents-upstream-sync.md#受保护内容) |
| `sync_output/` | 同步产物输出目录（按日期组织） | [docs/upstream_sync_workflow.md](./docs/upstream_sync_workflow.md) |
| `--allow-multiple-definition` | 链接器标志，允许重复符号（OBJECT 库与共享库/mock 共存时） | [docs/build_and_fix_workflow.md](./docs/build_and_fix_workflow.md) § 符号重定义 |

> **编辑前声明**：修改任何文件前，先声明 (1) 本任务类别（见任务路由表），(2) 已阅读的路由文档，(3) 发现的适用约束。未声明前不得修改文件。

## 项目概述

这是 OpenHarmony 分布式数据管理子系统 (`appdatamgr`) 的 mock 仓库。本地环境使用 Cygwin 在 Windows 上模拟 Unix 环境，使用 CMake 作为构建系统。该仓库实现了完整的数据管理组件，包括关系型数据库、首选项、数据共享、KV 存储、分布式数据对象和 UDMF（用户数据管理框架）。

## 核心约束（必须遵守）

1. **不修改上游代码**：不能修改 `datamgr_service/`、`data_share/`、`relational_store/`、`kv_store/`、`data_object/`、`preferences/`、`udmf/`、`interface_sdk/`、`utils_native/` 中的上游源码（非受保护文件）。编译问题**只能通过修改 `mock/`、`test/`、`CMakeLists.txt`** 来适配。
2. **保留 GN 文件**：`BUILD.gn` 文件必须保留——它们是编写和维护 `CMakeLists.txt` 的参考来源。
3. **构建目录**：始终使用 `cmake-build-debug` 作为构建目录名，使用项目根目录的 `ninja.exe`。
4. **测试配置统一**：所有测试 CMake 配置放在 `test/<module_name>/` 下，不在模块 `CMakeLists.txt` 中内联定义。
5. **`master` 分支只做同步**：不在 `master` 上直接修改代码，所有本地修改在 `feature/*` 分支上进行。
6. **删除前确认**：删除 `mock/` 或 `test/` 下的文件前需用户确认；执行 `sync.ps1 -RemoveExtra` 前需用户确认。

### 常见 Agent 失败模式

| 错误行为 | 正确做法 |
|---|---|
| 直接修改上游源码修复编译错误 | 通过 `mock/` 添加 mock 实现或头文件覆盖 |
| 编写 CMakeLists.txt 时未对照同目录 BUILD.gn | 先读 BUILD.gn，按 `.skills/gn-to-cmake-test-converter/SKILL.md` 转换 |
| 在模块 CMakeLists.txt 中内联测试配置 | 测试配置放 `test/<module_name>/` 下 |
| 在 `master` 分支直接提交代码 | 切 `feature/*` 分支后再修改 |
| 删除 mock 文件未确认 | 先报告待删文件列表，经用户确认后删除 |
| Mock 覆盖文件与 OBJECT 库符号冲突时盲目加 `--allow-multiple-definition` | 先用 `list(REMOVE_ITEM)` 排除被覆盖的真实源文件；确需共存时按 [docs/build_and_fix_workflow.md](./docs/build_and_fix_workflow.md) 加 `--allow-multiple-definition` 并注释原因 |

## 任务完成标准

| 任务 | Done 定义 | 必须报告 |
|---|---|---|
| 本地编译 | `ninja -j16` 零错误退出 | 构建结果（成功/失败数） |
| 全量构建收集 | `ninja -k0 -j16` 执行完毕，收集所有失败 | 失败文件列表、失败模式分类 |
| 运行测试 | `ctest --output-on-failure -j1` 全部通过 | 通过/失败/跳过数 |
| 上游同步 | sync.ps1 完成且无未解决冲突 | 同步的仓库、冲突文件数、备份目录 |
| 编译修复 | 修复后 `ninja -k0` 零错误 | 修改的文件列表、修复模式 |
| 上游同步+编译修复 | sync.ps1 完成 + ninja 零错误 + 重生成 [对比文档](./docs/gn-vs-cmake-targets.md#重新生成步骤) | 同步仓库数、修复文件列表、对比文档路径 |

> **验证不可用时**：若 `ninja`/`ctest` 无法执行（Cygwin 未配置、环境异常），Agent 须 (1) 报告环境状态，(2) 尝试 `cmake --version` 和 `ninja --version` 诊断，(3) 不得声称任务完成。

## 运维文档索引

| 何时查阅 | 文档 | 说明 |
|---|---|---|
| 执行同步前 | [docs/agents-upstream-sync.md](./docs/agents-upstream-sync.md) | sync.ps1 命令、冲突检测、受保护内容 |
| 编译失败时 | [docs/agents-build-and-fix.md](./docs/agents-build-and-fix.md) | 构建命令、失败收集、GN→CMake 转换 |
| 运行测试前 | [docs/agents-test-guide.md](./docs/agents-test-guide.md) | 测试环境、运行命令、Mock 系统 |
| 了解架构时 | [docs/agents-architecture.md](./docs/agents-architecture.md) | 组件结构、架构模式、关键约束、目录约定 |
| 提交变更前 | [docs/agents-git-workflow.md](./docs/agents-git-workflow.md) | 提交规范、分支策略 |
| 需要同步细节时 | [docs/upstream_sync_workflow.md](./docs/upstream_sync_workflow.md) | 上游同步流程详解 |
| 需要编译修复细节时 | [docs/build_and_fix_workflow.md](./docs/build_and_fix_workflow.md) | 编译修复流程详解 |
| 查找历史编译失败 | [docs/build_failures.md](./docs/build_failures.md) | 编译失败历史记录 |
| 需要了解编译单元 | [docs/build_structure.md](./docs/build_structure.md) | 编译单元结构总览 |
| 同步后对比 GN/CMake | [docs/gn-vs-cmake-targets.md](./docs/gn-vs-cmake-targets.md) | 编译产物映射、差异模式、重新生成步骤 |
| 查询 sync.ps1 参数 | [bin/update/README.md](./bin/update/README.md) | sync.ps1 完整文档 |
| 快速查找同步命令 | [bin/update/QUICKSTART.md](./bin/update/QUICKSTART.md) | 同步工具常用命令速查 |
