# OpenHarmony RDB Store — Agent Instructions

基于 SQLite 的 OpenHarmony 系统级数据库服务，为内部服务和第三方应用提供数据存储。

## Core Principles <!-- [S1,E4] -->

1. 修改存量接口 MUST 评估性能影响 — 运行性能基线测试（`test/js/relationalstore/performance/src/`），对照 BASE_LINE 阈值（tablet/phone 分列），改动后所有性能 case MUST 全 pass；涉及无现成基线的接口 MUST 先补基准测试再改代码
2. 新增外部依赖 MUST 优先动态加载方式 — native_rdb 支持动态卸载（详见 `docs/dynamic_loading.md`）
3. 用户说"调研一下" MUST NOT 直接实现 — 先调研再决定 `[S1]`
4. Claim "done" MUST 有测试验证 — 所改模块对应 UT 跑通且断言全过才算 done；无现成 UT 则 MUST 先补 `[E1]`
5. 接口层 API NEVER 破坏向后兼容 — NDK/JS/ETS 接口绝对不能破坏兼容；仅修改 C++ 侧功能时也 MUST 评估对上层接口的影响 — 逐层检查 JS/NAPI（`frameworks/js/napi/`）、ETS（`frameworks/ets/taihe/`）、NDK（`interfaces/ndk/include/`）的接口声明和测试断言是否受影响；仅内部重构不影响接口签名时 MUST 在 commit 说明"不影响上层接口"

## Repository Guide <!-- [C1,E5] -->

### 代码目录分层

```
relational_store/
├── frameworks/              # 实现代码
│   ├── native/             # C++ 原生实现
│   │   ├── rdb/            # RDB 核心实现（SQLite 封装、连接池、事务等）
│   │   ├── rd/             # RD（GRD 内核相关）
│   │   ├── rdb_crypt/      # 数据库加密（HUKS）
│   │   ├── obs_mgr_adapter/# 观察者管理器
│   │   ├── icu/            # ICU 国际化支持
│   │   ├── cloud_data/     # 云同步服务
│   │   ├── dfx/            # DFX（故障/雷达/统计报告）
│   │   ├── rdb_data_ability_adapter/ # DataAbility 适配器
│   │   ├── rdb_data_share_adapter/  # DataShare 适配器
│   │   ├── appdatafwk/              # AppData Framework 适配器
│   ├── js/napi/            # JS/TS NAPI 绑定
│   ├── ets/taihe/          # ETS（Taihe）实现
│   ├── cj/                 # Cangjie FFI 实现
│   └── common/             # 公共工具
│
└── interfaces/              # 接口定义
    ├── inner_api/          # 内部 API（供其他 OpenHarmony 模块使用）
    │   ├── rdb/            # RDB 内部接口
    │   ├── rdb_data_ability_adapter/ # DataAbility 适配器内部接口
    │   ├── rdb_data_share_adapter/  # DataShare 适配器内部接口
    │   └── appdatafwk/              # AppData Framework 内部接口
    └── ndk/                # NDK 接口（暴露给应用开发者）
        └── include/        # NDK 头文件（oh_rdb_*.h）
```

**分层原则**：
- `interfaces/inner_api/`：模块间接口，内部使用，**NEVER** 破坏兼容
- `interfaces/ndk/include/`：应用层接口，公开 API，**NEVER** 破坏兼容
- `frameworks/native/`：C++ 实现，不影响原有功能，可重构
- 修改 `frameworks` 层代码 **MUST** 评估对 `interfaces` 层的影响 — 参见 Core Principles 第 5 条的逐层检查方法

### 任务路由表

| 任务类型 | 主要改动路径 | MUST 检查的上层路径 | 对应测试路径 |
|----------|-------------|---------------------|-------------|
| RDB 核心逻辑 | `frameworks/native/rdb/src/` | `frameworks/js/napi/`、`frameworks/ets/taihe/`、`interfaces/ndk/include/` | `test/native/rdb/unittest/`、`test/js/rdb/` |
| 加密功能 | `frameworks/native/rdb_crypt/` | `frameworks/native/rdb/`（rdb_crypt 被依赖） | `test/native/rdb/unittest/` |
| JS/NAPI 接口 | `frameworks/js/napi/` | `interfaces/ndk/include/`（同一接口的不同绑定） | `test/js/rdb/` |
| ETS 接口 | `frameworks/ets/taihe/` | 无上层 | `test/ets/relational_store/` |
| NDK 接口 | `interfaces/ndk/include/` | 无上层（公开 API） | `test/ndk/unittest/` |
| 云同步 | `frameworks/native/cloud_data/` | `frameworks/js/napi/`、`frameworks/ets/taihe/` | `test/native/clouddata/`、`test/ets/cloud_data/` |
| DataShare 适配 | `frameworks/native/rdb_data_share_adapter/` | `interfaces/inner_api/rdb_data_share_adapter/` | `test/native/rdb_data_share_adapter/` |
| DataAbility 适配 | `frameworks/native/rdb_data_ability_adapter/` | `interfaces/inner_api/rdb_data_ability_adapter/` | `test/native/rdb_data_ability_adapter/` |
| DFX | `frameworks/native/dfx/` | `frameworks/native/rdb/`（dfx 被依赖） | `test/native/rdb/unittest/` |
| ICU | `frameworks/native/icu/` | `frameworks/native/rdb/`（icu 被依赖） | `test/native/rdb/unittest/` |

### 构建与测试命令

| 命令 | 用途 | 产物路径 |
|------|------|----------|
| `./build.sh --product-name rk3568 --build-target relational_store` | 构建整个组件 | `out/rk3568/distributeddatamgr/relational_store/` |
| `./build.sh --product-name rk3568 --build-target relational_store_test` | 构建全部测试 | `out/rk3568/tests/unittest/relational_store/` |
| `./build.sh --product-name rk3568 --build-target //foundation/distributeddatamgr/relational_store/interfaces/inner_api/rdb:native_rdb` | 构建原生核心库 | `out/rk3568/innerkits/ohos-arm/relational_store/native_rdb/` |
| `${OHOS_ROOT}/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang-format --style=file -i <file>` | 格式化单个文件（使用仓库 `.clang-format` 配置） | `${OHOS_ROOT}` 为 OpenHarmony 源码根目录；提交前 **MUST** 格式化 |

模块名 `relational_store` / `relational_store_test` 为 `ohos_part` / `ohos_part_test` 组，可直接用作 `--build-target`；子目标（如 `native_rdb`）需绝对 GN 路径。测试用例完整列表见 `bundle.json` 的 `test` 字段。设备端测试运行路径：`/data/test/relational_store/relational_store/native_rdb/`

### Mock 与 TDD

- **测试框架**: googletest
- **测试文件命名**: `*_test.cpp`（如 `rdb_store_impl_test.cpp`）
- **Mock 模板目录**: `test/native/rdb/unittest/mockservice/`、`test/native/rdb/unittest/mock_obs_manage_test/`
- **Mock 文件命名**: `mock_*.cpp` / `mock_*.h`
- **TDD**: 1) RED 先写测试 **MUST** 看到失败 → 2) GREEN 最小实现 → 3) IMPROVE 重构

## CI Requirements <!-- [E1] -->

提交前必跑：格式化 + 编译构建 + 单元测试（命令见 Repository Guide）

## Configuration <!-- [C4] -->

所有构建配置开关定义在 `relational_store.gni` 的 `declare_args()` 中，包括 ICU 国际化支持、GRD 内核动态加载、Device Manager 依赖、API Metrics 上报等。**NEVER** 手写与 `relational_store.gni` 不一致的值。

## Exploration Notes <!-- [C1] -->

尚无满足条件的探索总结。当同一探索性问题在不同会话中被反复执行 **3 次及以上**并得到相同结论时，按 4 要素格式补入（问题/结论/关键路径/失效条件），单条 ≤10 行。

## Known Pitfalls <!-- [E1,E5,S4] -->

### Pitfall 1：文件操作未考虑进程中断

- **现象**: 文件操作过程中进程中断，重启后无法恢复或数据损坏
- **根因**: 未考虑进程中断场景，缺少恢复机制，导致不可逆的严重后果
- **反模式**: **NEVER** 写文件操作时不考虑进程中断后的可恢复性
- **正确写法**: 文件操作 **MUST** 保证进程中断后重启可恢复 — 使用原子写（write-to-temp + rename）或 WAL/日志机制；验证方法：模拟 kill -9 后重启检查数据完整性

### Pitfall 2：共享资源多进程并发

- **现象**: 共享资源在多进程并发访问时数据不一致
- **根因**: 未考虑多进程并发，缺少锁或 IPC 隔离
- **反模式**: **NEVER** 忽略共享资源的多进程并发访问场景
- **正确写法**: 共享资源 **MUST** 考虑多进程并发访问场景，跨进程访问通过 IPC — DataShare 使用 `rdb_data_share_adapter` 做 IPC 隔离；验证方法：多进程并发写入后检查数据一致性

### Pitfall 3：过度依赖 SA 进程

- **现象**: 功能失效因为 SA 进程未启动或不存在
- **根因**: 代码硬依赖 SA 进程存在，未做降级处理
- **反模式**: **NEVER** 过度依赖服务端 SA 进程
- **正确写法**: **MUST** 考虑 SA 进程未启动或不存在场景，做降级/容错处理 — 检查 SA 可用性后再调用，不可用时返回本地缓存或默认值；验证方法：kill SA 进程后功能不崩溃且返回降级结果

## Coding Conventions <!-- [C2] -->

| 维度 | 约定 |
|------|------|
| 不可变性 | 接口层 API（NDK/JS/ETS）**NEVER** 破坏向后兼容；Inner APIs 不建议修改 |
| 文件规模 | 单文件建议 ≤2000 行；超过 **MUST** 拆分 |
| 错误处理 | **MUST** 使用 `rdb_errno.h` 标准错误码；**NEVER** 让接口层存量接口返回新错误码或变更同场景错误码；错误码分层详见 `docs/error_code_layers.md` |
| 日志 | 错误日志 **MUST** 提供充足上下文信息（函数名 + 文件路径 + 操作类型 + 错误码）；高频分支 **NEVER** 打正常日志 |
| 文件命名 | 测试文件 `*_test.cpp`；Mock 文件 `mock_*.cpp/.h`；构建配置 `BUILD.gn` |
| 导出约定 | inner_api 仅导出 `include/` 下头文件；新增导出 **MUST** 同步更新 `bundle.json` |
| 工具类复用 | **MUST** 优先使用 `kv_store:datamgr_common` 提供的工具类（ConcurrentMap、ITypesUtil、Traits、JSProxy、BlockData、LRUBucket 等），**NEVER** 自行实现已有同等能力

Commit 信息 **MUST** 包含 `Co-Authored-By: Agent`，**NEVER** 把 Agent 修改为其它单词。

## Anti-Patterns <!-- [C2,E5,S4] -->

### 语法级

- **NEVER** commit unless asked

### 认知级

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
| rdb_crypt | 数据库加密 | HUKS | native_rdb |
| obs_mgr_adapter | 观察者管理器 | 无 | native_rdb |
| cloud_data | 云同步服务 | IPC, native_rdb | JS/ETS接口层 |
| dfx | 故障/雷达/统计报告 | HiLog, HiTrace, HiSysEvent | native_rdb |
| relational_store_icu | ICU 国际化支持 | ICU | native_rdb |

禁止循环依赖。如有 **MUST** 单列并给出整改 Issue。


## Knowledge Routes <!-- 触发式文档加载 -->

| 触发词/路径模式 | 加载文档 | 加载后 MUST 检查 |
|-----------------|----------|------------------|
| `错误码` / `errno` / `E_OK` / `rdb_errno.h` / 修改接口返回值 | `docs/error_code_layers.md` | 存量接口返回码不变；新增错误码仅用于新增接口 |
| `动态加载` / `dlopen` / `新增依赖` / `dlsym` | `docs/dynamic_loading.md` | 新依赖 MUST 使用动态加载方式；禁止静态链接 |
| `跨模块` / `新服务接入` / `rdb_native` / `connection_pool` | `docs/rdb_native.md` | 跨模块改动 MUST 不破坏 inner_api 兼容 |
| `加密` / `crypt` / `HUKS` / `rdb_crypt` | `docs/error_code_layers.md` + `docs/rdb_native.md` | 加密相关改动 MUST 通过 rdb_crypt 适配层 |
| `云同步` / `cloud` / `cloud_data` | `docs/rdb_native.md` | 云同步 MUST 通过 IPC 与 native_rdb 交互 |