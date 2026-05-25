# OpenHarmony RDB Store — Agent Instructions

基于 SQLite 的 OpenHarmony 系统级数据库服务，为内部服务和第三方应用提供数据存储。

## Core Principles <!-- [S1,E4] -->

1. 修改存量接口 MUST 评估性能影响 — RDB 对接口性能有强要求
2. 新增外部依赖 MUST 优先动态加载方式 — native_rdb 支持动态卸载（详见 `docs/dynamic_loading.md`）
3. 用户说"调研一下" MUST NOT 直接实现 — 先调研再决定 `[S1]`
4. Claim "done" MUST 有测试验证 — 未验证不算完成 `[E1]`
5. 接口层 API NEVER 破坏向后兼容 — NDK/JS/ETS 接口绝对不能破坏兼容

## Repository Guide <!-- [C1,E5] -->

### 技术栈

| 项目 | 说明 |
|------|------|
| 语言 | C++（原生核心）、ArkTS/JS（NAPI绑定）、ETS（Taihe）、Cangjie（FFI） |
| 构建系统 | GN + OpenHarmony 构建系统 |
| 存储引擎 | SQLite（third_party_sqlite） |
| 测试框架 | googletest（C++）、JS测试框架（ArkTS） |

### 核心依赖

| 依赖 | 用途 |
|------|------|
| HUKS | 数据库加密密钥管理 |
| HiLog / HiTrace / HiSysEvent | 日志、追踪、事件上报 |
| IPC | 进程间通信（SA服务代理） |
| kv_store | 跨仓工具类复用 |
| data_share | Data Share 适配器 |
| ability_runtime | Ability 生命周期集成 |

### 构建与测试命令

| 命令 | 用途 | 产物路径 |
|------|------|----------|
| `./build.sh --product-name rk3568 --build-target relational_store` | 构建整个组件 | `out/rk3568/innerkits/ohos-arm/relational_store/` |
| `./build.sh --product-name rk3568 --build-target relational_store_test` | 构建全部测试 | `out/rk3568/exe.unstripped/tests/` |
| `./build.sh --product-name rk3568 --build-target //foundation/distributeddatamgr/relational_store/interfaces/inner_api/rdb:native_rdb` | 构建原生核心库 | `out/rk3568/innerkits/ohos-arm/relational_store/native_rdb/` |
| `prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang-format -i <file>` | 格式化单个文件（依赖仓库根目录 `.clang-format` 配置） | 提交前 **MUST** 格式化 |

模块名 `relational_store` / `relational_store_test` 为 `ohos_part` / `ohos_part_test` 组，可直接用作 `--build-target`；子目标（如 `native_rdb`）需绝对 GN 路径。测试用例完整列表见 `bundle.json` 的 `test` 字段。设备端测试运行路径：`/data/test/relational_store/relational_store/native_rdb/`

### Mock 与 TDD

- **测试框架**: googletest
- **测试文件命名**: `*_test.cpp`（如 `rdb_store_impl_test.cpp`）
- **Mock 模板目录**: `test/native/rdb/unittest/mockservice/`、`test/native/rdb/unittest/mock_obs_manage_test/`
- **Mock 文件命名**: `mock_*.cpp` / `mock_*.h`
- **TDD**: 1) RED 先写测试 **MUST** 看到失败 → 2) GREEN 最小实现 → 3) IMPROVE 重构

## CI Requirements <!-- [E1] -->

| CI 任务 | 本地等价命令 |
|---------|-------------|
| 单元测试 | `./build.sh --product-name rk3568 --build-target relational_store_test` |
| 格式化检查 | `clang-format -i <file>` |
| 编译检查 | `./build.sh --product-name rk3568 --build-target relational_store` |

提交前必跑：格式化 + 编译构建 + 单元测试

## Environment Variables <!-- [E5,C4] -->

| 变量名 | 必需 | 用途 | 来源 |
|--------|------|------|------|
| `relational_store_rdb_support_icu` | 是 | 控制是否启用 ICU 国际化支持 | `relational_store.gni` |
| `arkdata_db_core_is_exists` | 条件 | 控制是否启用 GRD 内核动态加载 | `relational_store.gni`（依赖 `global_parts_info`） |
| `relational_store_config` | 是 | 通用配置开关 | `relational_store.gni` |
| `relational_store_dm_part_is_enabled` | 条件 | 控制 Device Manager 依赖 | `relational_store.gni`（依赖 `global_parts_info`） |
| `relational_store_api_metrics_enabled` | 条件 | 控制 API Metrics 上报 | `relational_store.gni`（依赖 `global_parts_info`） |

来源均为 `relational_store.gni` declare_args()，**NEVER** 手写不一致的值。

## Exploration Notes <!-- [C1] -->

尚无满足条件的探索总结。当同一探索性问题在不同会话中被反复执行 **3 次及以上**并得到相同结论时，按 4 要素格式补入（问题/结论/关键路径/失效条件），单条 ≤10 行。

## Known Pitfalls <!-- [E1,E5,S4] -->

### Pitfall 1：文件操作未考虑进程中断

- **现象**: 文件操作在中断后数据损坏或丢失
- **根因**: 未处理进程中断场景，缺少恢复机制
- **反模式**: **NEVER** 写文件操作时不考虑进程中断恢复
- **正确写法**: 文件操作 **MUST** 考虑进程中断场景，中断后可恢复（使用 WAL 模式、事务保护）
- **引入时机**: 第 2 次出现文件损坏问题后补入

### Pitfall 2：共享资源多进程并发

- **现象**: 共享资源在多进程并发访问时数据不一致
- **根因**: 未考虑多进程并发，缺少锁或 IPC 隔离
- **反模式**: **NEVER** 忽略共享资源的多进程并发访问场景
- **正确写法**: 共享资源 **MUST** 考虑多进程并发访问场景，跨进程访问通过 IPC
- **引入时机**: 第 2 次出现并发问题后补入

### Pitfall 3：过度依赖 SA 进程

- **现象**: 功能失效因为 SA 进程未启动或不存在
- **根因**: 代码硬依赖 SA 进程存在，未做降级处理
- **反模式**: **NEVER** 过度依赖服务端 SA 进程
- **正确写法**: **MUST** 考虑 SA 进程未启动或不存在场景，做降级/容错处理
- **引入时机**: 第 2 欠出现 SA 依赖失效后补入

## Coding Conventions <!-- [C2] -->

| 维度 | 约定 |
|------|------|
| 不可变性 | 接口层 API（NDK/JS/ETS）**NEVER** 破坏向后兼容；Inner APIs 不建议修改 |
| 文件规模 | 单文件建议 ≤2000 行；超过 **MUST** 拆分 |
| 错误处理 | **MUST** 使用 `rdb_errno.h` 标准错误码；**NEVER** 让接口层存量接口返回新错误码或变更同场景错误码；错误码分层详见 `docs/error_code_layers.md` |
| 日志 | 错误日志 **MUST** 提供充足上下文信息；高频分支 **NEVER** 打正常日志 |
| 文件命名 | 测试文件 `*_test.cpp`；Mock 文件 `mock_*.cpp/.h`；构建配置 `BUILD.gn` |
| 导出约定 | inner_api 仅导出 `include/` 下头文件；新增导出 **MUST** 同步更新 `bundle.json` |

Commit 信息 **MUST** 包含 `Co-Authored-By: Agent`，**NEVER** 把 Agent 修改为其它单词。

## Anti-Patterns <!-- [C2,E5,S4] -->

### 语法级

- **NEVER** commit unless asked
- **NEVER** leave empty `catch(e){}`
- **NEVER** 破坏接口层 API 向后兼容
- **NEVER** 直推 main 分支
- **NEVER** 把 Agent 修改为其它单词（Co-Authored-By 声明）

### 认知级

- **NEVER** claim "done" without running tests `[E1]`
- **NEVER** fabricate API signatures `[E5]`
- **NEVER** implement when user said "调研一下" `[S1]`
- **NEVER** agree if you see problems — say it `[S4]`
- **NEVER** skip the failing-test step in TDD `[E1]`

### 合理化对照表

| Agent 会说的借口 | 现实 |
|------------------|------|
| "太简单不需要测试" | 简单代码也会坏。写测试只要 30 秒。 |
| "我先写完再补测试" | 事后补的测试什么也证明不了。 |
| "手动测过了" | 没有记录、不可重复的测试不算测试。 |
| "这个依赖直接加上就行" | native_rdb 支持动态卸载，直接加依赖会破坏卸载能力。 |

## Internal Module Dependencies <!-- [C1] -->

| 模块 | 能力 | 依赖 | 被谁依赖 |
|------|------|------|----------|
| native_rdb | 核心关系型数据库（SQLite封装） | rdb_crypt, obs_mgr_adapter, dfx | NDK/JS/ETS接口层, cloud_data, data_share |
| rdb_crypt | 数据库加密（HUKS动态加载） | HUKS（动态加载） | native_rdb |
| obs_mgr_adapter | 观察者管理器（动态加载） | 无 | native_rdb |
| cloud_data | 云同步服务 | IPC, native_rdb | JS/ETS接口层 |
| dfx | 故障/雷达/统计报告 | HiLog, HiTrace, HiSysEvent | native_rdb |
| icu | ICU 国际化支持（动态加载） | ICU（动态加载） | native_rdb |

禁止循环依赖。如有 **MUST** 单列并给出整改 Issue。

## External Dependencies <!-- 库/存储/服务+降级策略 -->

| 组件 | 类型 | 用途 | 关键路径 | 降级策略 |
|------|------|------|----------|----------|
| SQLite | 外部库 | 存储引擎 | 是 | 无降级（核心依赖） |
| HUKS | 外部服务 | 加密密钥管理 | 是（加密场景） | 动态加载，不可用时加密功能不可用 |
| IPC / samgr | 外部服务 | 进程间通信 | 是（跨进程场景） | SA未启动时功能降级 |
| kv_store | 跨仓依赖 | 工具类复用 | 是 | 无降级 |
| data_share | 跨仓依赖 | Data Share 适配 | 否 | 功能降级 |
| ability_runtime | 外部服务 | Ability生命周期 | 是 | SA未启动时功能降级 |
| HiLog/HiTrace/HiSysEvent | 外部服务 | 日志追踪 | 是 | 无降级（系统基础服务） |
| ICU | 外部库 | 国际化locale配置 | 否（动态加载） | 不可用时locale功能降级 |
| openssl | 外部库 | 加密辅助 | 否 | 动态加载 |

**NEVER** 写入访问凭据或真实 Endpoint，仅允许环境变量名引用 `[C4]`。

## Docs Index <!-- 按命中频率排序 -->

| 路径 | 标题 | 加载场景 | 稳定性 |
|------|------|----------|--------|
| `docs/dynamic_loading.md` | 动态加载和卸载机制 | 新增外部依赖时 | 稳定 |
| `docs/rdb_native.md` | RDB Native 层详细实现 | 跨模块改动或新服务接入 | 稳定 |
| `docs/error_code_layers.md` | 错误码分层体系 | 修改错误码或新增接口时 | 稳定 |