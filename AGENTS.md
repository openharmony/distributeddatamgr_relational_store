# AGENTS.md

本文件是 AI Agent 处理本仓库任务时的轻量入口。先读本文件，再按任务类型只加载匹配的详细文档页。

## 阅读策略

不要一开始就读取 `docs/` 下的所有文件。

默认只读本文件。涉及需求设计或代码开发时，最多按需加载：

1. 如果影响范围不清楚，读取 `docs/rdb_native.md` 了解核心类关系和目录结构。
2. 读取一个与任务领域匹配的专题页（`docs/error_code_layers.md` 或 `docs/dynamic_loading.md`）。
3. 规划验证时，见本文件"编译和测试方法"章节。

## 仓库定位

`relational_store` 是 OpenHarmony 关系型数据库组件。在 OpenHarmony 源码树中的位置是：

```text
//foundation/distributeddatamgr/relational_store
```

组件元信息：

- 子系统：`distributeddatamgr`
- 部件：`relational_store`
- 主要能力面：关系型数据库 CRUD、事务、连接池、加密、云同步、观察者通知、DataShare/DataAbility 适配、ICU 国际化排序。

基于 SQLite 的 OpenHarmony 系统级数据库服务，为内部服务和第三方应用提供数据存储。主要实现语言是 C++，通过 NAPI 暴露到 ArkTS/JavaScript，同时包含 ETS/Taihe 实现、Cangjie FFI、NDK C API、native inner kit 和测试代码。

# 代码地图

## 代码分层

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

**破坏兼容 = 存量接口的功能行为发生变化或错误码发生变化**（包括：删减接口/参数、修改返回值含义、同场景返回不同错误码、改变接口行为语义）。

**分层原则**：

- `interfaces/inner_api/`：模块间接口，内部使用，**NEVER** 破坏兼容。
- `interfaces/ndk/include/`：应用层接口，公开 API，**NEVER** 破坏兼容。
- `frameworks/native/`：C++ 实现，不影响原有功能，可重构。
- 修改 `frameworks` 层代码 **MUST** 评估对 `interfaces` 层的影响 — 逐层检查 JS/NAPI、ETS、NDK 的接口声明和测试断言是否受影响；仅内部重构不影响接口签名时 MUST 在 commit 说明"不影响上层接口"。

## 任务路由表

| 任务类型         | 主要改动路径                                  | MUST 检查的上层路径                                          | 对应测试路径                                     |
| ---------------- | --------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------ |
| RDB 核心逻辑     | `frameworks/native/rdb/src/`                  | `frameworks/js/napi/`、`frameworks/ets/taihe/`、`interfaces/ndk/include/` | `test/native/rdb/unittest/`、`test/js/rdb/`      |
| 加密功能         | `frameworks/native/rdb_crypt/`                | `frameworks/native/rdb/`（rdb_crypt 被依赖）                 | `test/native/rdb/unittest/`                      |
| JS/NAPI 接口     | `frameworks/js/napi/`                         | `interfaces/ndk/include/`（同一接口的不同绑定）              | `test/js/rdb/`                                   |
| ETS 接口         | `frameworks/ets/taihe/`                       | 无上层                                                       | `test/ets/relational_store/`                     |
| NDK 接口         | `interfaces/ndk/include/`                     | 无上层（公开 API）                                           | `test/ndk/unittest/`                             |
| 云同步           | `frameworks/native/cloud_data/`               | `frameworks/js/napi/`、`frameworks/ets/taihe/`               | `test/native/clouddata/`、`test/ets/cloud_data/` |
| DataShare 适配   | `frameworks/native/rdb_data_share_adapter/`   | `interfaces/inner_api/rdb_data_share_adapter/`               | `test/native/rdb_data_share_adapter/`            |
| DataAbility 适配 | `frameworks/native/rdb_data_ability_adapter/` | `interfaces/inner_api/rdb_data_ability_adapter/`             | `test/native/rdb_data_ability_adapter/`          |
| DFX              | `frameworks/native/dfx/`                      | `frameworks/native/rdb/`（dfx 被依赖）                       | `test/native/rdb/unittest/`                      |
| ICU              | `frameworks/native/icu/`                      | `frameworks/native/rdb/`（icu 被依赖）                       | `test/native/rdb/unittest/`                      |

禁止循环依赖。如有 **MUST** 单列并给出整改 Issue。

# 知识路由

## 触发式文档加载

| 触发词/路径模式                                              | 加载文档                                           | 加载后 MUST 检查                             |
| ------------------------------------------------------------ | -------------------------------------------------- | -------------------------------------------- |
| `错误码` / `errno` / `E_OK` / `rdb_errno.h` / 修改接口返回值 | `docs/error_code_layers.md`                        | 存量接口返回码不变；新增错误码仅用于新增接口 |
| `动态加载` / `dlopen` / `新增依赖` / `dlsym`                 | `docs/dynamic_loading.md`                          | 新依赖 MUST 使用动态加载方式；禁止静态链接   |
| `跨模块` / `新服务接入` / `rdb_native` / `connection_pool`   | `docs/rdb_native.md`                               | 跨模块改动 MUST 不破坏 inner_api 兼容        |
| `加密` / `crypt` / `HUKS` / `rdb_crypt`                      | `docs/error_code_layers.md` + `docs/rdb_native.md` | 加密相关改动 MUST 通过 rdb_crypt 适配层      |
| `云同步` / `cloud` / `cloud_data`                            | `docs/rdb_native.md`                               | 云同步 MUST 通过 IPC 与 native_rdb 交互      |

# 专家经验

## 核心原则

1. 修改存量接口 MUST 评估性能影响 — 运行性能基线测试（test/js/relationalstore/performance），对照 BASE_LINE 阈值，改动后所有性能 case MUST 全 pass；涉及无现成基线的接口 MUST 先补基准测试再改代码。
2. 新增外部依赖 MUST 优先动态加载方式 — native_rdb 支持动态卸载（详见 `docs/dynamic_loading.md`）。
3. 用户说"调研一下" MUST NOT 直接实现 — 先调研再决定。
4. Claim "done" MUST 有测试验证 — 所改模块对应 UT 跑通且断言全过才算 done；无现成 UT 则 MUST 先补。
5. 接口层 API NEVER 破坏向后兼容 — 破坏兼容指存量接口的功能行为或错误码发生变化（删减接口/参数、修改返回值含义、同场景返回不同错误码、改变行为语义）；仅修改 C++ 侧功能时也 MUST 评估对上层接口的影响；仅内部重构不影响接口签名时 MUST 在 commit 说明"不影响上层接口"。

## 编码规范

| 维度       | 约定                                                         |
| ---------- | ------------------------------------------------------------ |
| 不可变性   | 接口层 API（NDK/JS/ETS）**NEVER** 破坏向后兼容（破坏兼容 = 功能行为或错误码发生变化）；Inner APIs 不建议修改 |
| 文件规模   | 单文件建议 ≤2000 行；超过 **MUST** 拆分                      |
| 错误处理   | **MUST** 使用 `rdb_errno.h` 标准错误码；**NEVER** 让接口层存量接口返回新错误码或变更同场景错误码；分层详见 `docs/error_code_layers.md` |
| 日志       | 错误日志 **MUST** 提供充足上下文信息（函数名 + 文件路径 + 操作类型 + 错误码）；高频分支 **NEVER** info 级别日志 |
| 文件命名   | 测试文件 `*_test.cpp`；Mock 文件 `mock_*.cpp/.h`；构建配置 `BUILD.gn` |
| 导出约定   | inner_api 仅导出 `include/` 下头文件；新增导出 **MUST** 同步更新 `bundle.json` |
| 工具类复用 | **MUST** 优先使用 `kv_store:datamgr_common` 提供的工具类（ConcurrentMap、ITypesUtil、Traits、JSProxy、BlockData、LRUBucket 等），**NEVER** 自行实现已有同等能力 |
| 定义复用   | 新增映射表、函数、接口前 **MUST** 先检查同文件/同模块内是否存在可复用的同类定义，优先扩展而非新增，合并而非并行 |

Commit 信息 **MUST** 包含 `Co-Authored-By: Agent`，**NEVER** 把 Agent 修改为其他单词。

## 已知陷阱

- 共享资源 **MUST** 考虑多进程并发访问场景，跨进程访问通过 IPC（DataShare 用 `rdb_data_share_adapter` 做 IPC 隔离）；**NEVER** 忽略共享资源的多进程并发访问场景。
- **MUST** 考虑 SA 进程未启动或不存在场景，做降级/容错处理（检查 SA 可用性后再调用，不可用时返回本地缓存或默认值）；**NEVER** 硬依赖 SA 进程。

| Agent 会说的借口       | 现实                                                |
| ---------------------- | --------------------------------------------------- |
| "太简单不需要测试"     | 简单代码也会坏。写测试只要 30 秒。                  |
| "我先写完再补测试"     | 事后补的测试什么也证明不了。                        |
| "手动测过了"           | 没有记录、不可重复的测试不算测试。                  |
| "这个依赖直接加上就行" | native_rdb 支持动态卸载，直接加依赖会破坏卸载能力。 |

# 编译和测试方法

> **MUST**：修改类任务完成后 MUST 执行以下验证步骤，NEVER 跳过任何一步。

## 修改类任务验证步骤模板（MUST 执行）

1. **格式化**（MUST，提交前必跑）：
   ```bash
   ${OHOS_ROOT}/prebuilts/clang/ohos/linux-x86_64/llvm/bin/clang-format --style=file -i <修改的文件>
   ```

2. **编译构建**（MUST，确认修改不引入编译错误）：
   ```bash
   ./build.sh --product-name rk3568 --build-target relational_store
   ```

3. **单元测试**（MUST，确认修改不破坏现有功能）：
   ```bash
   ./build.sh --product-name rk3568 --build-target relational_store_test
   ```

> Claim "done" MUST 有以上 3 步验证结果。缺少任何一步 = 任务未完成。