# OpenHarmony RDB Store 开发指南

本文档提供 OpenHarmony 关系型数据库（RDB）存储组件的开发指导。

## Project Context

本项目是 **OpenHarmony 关系型数据库（RDB）存储**组件 - 一个基于 SQLite 构建的系统级数据库服务，为 OpenHarmony 内部服务和第三方应用提供数据存储服务。

**开发协作重点**:
- **动态卸载**: native_rdb 库支持动态卸载，新增外部依赖必须充分评估并尽量使用动态加载方式（详见 [动态加载和卸载机制](docs/dynamic_loading.md)）
- **跨仓依赖**: 依赖 `kv_store` 工具类、IPC 服务调用
- **性能要求**: RDB 对接口性能有强要求，修改存量接口时必须评估性能影响

## 项目概述

### 技术栈
- **编程语言**: C++（原生核心）、JavaScript/ArkTS（NAPI 绑定）、ETS（Taihe）
- **构建系统**: GN（Generate Ninja）配合 OpenHarmony 构建系统
- **存储引擎**: SQLite（third_party_sqlite）
- **测试框架**: googletest 用于 C++，JS 测试框架用于 JavaScript/ArkTS
- **关键依赖**: HUKS（加密）、HiLog（日志）、IPC（进程间通信）、Ability Runtime

### 架构
两层架构：

**接口层**（同层级，供应用开发者使用）:
- **NDK 接口** (`interfaces/ndk/`) - 稳定的 C API
- **JS 接口** (`frameworks/js/napi/`) - JavaScript/ArkTS NAPI 绑定
- **ETS (Taihe) 接口** (`frameworks/ets/taihe/`) - 基于 Taihe 的新一代 ArkTS API
- **Cangjie 接口** (`frameworks/cj/`) - Cangjie 语言 FFI 接口

**Native 层**:
- **接口定义** (`interfaces/inner_api/`): 内部 C++ API
  - `rdb` - 核心关系型数据库接口
  - `cloud_data` - 云同步服务接口
  - `dataability` - Data Ability 集成接口
  - `rdb_data_share_adapter` - Data Share 适配器
  - `rdb_data_ability_adapter` - Data Ability 适配器
  - `appdatafwk` - 应用数据框架工具

- **实现** (`frameworks/native/`): 核心功能实现
  - `rdb/` - 基于 SQLite 的核心实现
  - `rdb_crypt/` - 加密模块（内部使用 HUKS）
  - `dfx/` - DFX（故障/雷达/统计报告）
  - `cloud_data/` - 云同步服务实现
  - `obs_mgr_adapter/` - 观察者管理器适配器

## 关键目录

### 目录结构
```
relational_store/
├── interfaces/              # 接口层
│   ├── inner_api/           # Native 层接口定义（C++）
│   └── ndk/                 # NDK C 接口
├── frameworks/              # Native 层实现 + 接口层实现
│   ├── native/              # Native 层实现
│   │   ├── rdb/             # 核心 C++ 实现
│   │   ├── rdb_crypt/       # 加密模块
│   │   ├── dfx/             # DFX
│   │   ├── cloud_data/      # 云同步服务
│   │   └── obs_mgr_adapter/ # 观察者管理器
│   ├── js/napi/             # JS 接口实现
│   ├── ets/taihe/           # ETS 接口实现
│   └── cj/                  # Cangjie 接口实现
└── test/                    # 测试代码
```

> **RDB Native 层详细实现**请参考：[docs/rdb_native.md](docs/rdb_native.md)

### 核心类关系
```
RdbStoreImpl → ConnectionPool (最多4个) → Connection → Statement → AbsResultSet
```

### 关键源码文件
- `frameworks/native/rdb/src/connection_pool.cpp` - 连接池
- `frameworks/native/rdb/src/rdb_store_impl.cpp` - RdbStore 核心实现
- `frameworks/native/rdb/src/transaction.cpp` - 事务管理
- `frameworks/native/rdb/src/rdb_service_proxy.cpp` - IPC 服务代理
- `frameworks/native/rdb/src/global_resource.cpp` - 动态库卸载管理
- `relational_store.gni` - 跨仓路径定义
- `interfaces/inner_api/rdb/include/rdb_errno.h` - 错误码定义

## 命令

### 构建命令
```bash
# 构建整个组件
./build.sh --product-name <产品名> --build-target relational_store

# 构建特定原生库
./build.sh --product-name <产品名> --build-target //foundation/distributeddatamgr/relational_store/interfaces/inner_api/rdb:native_rdb
```

### 测试命令
```bash
# 构建原生测试
./build.sh --product-name <产品名> --build-target //foundation/distributeddatamgr/relational_store/test/native/rdb:unittest

# 运行测试套件（可执行文件位于 /data/test/relational_store/relational_store/native_rdb/）
# - NativeRdbTest: 主要单元测试
# - NativeRdbMultiThreadTest: 多线程测试
# - NativeRdbMultiProcessTest: 多进程测试
```

### 代码格式化
```bash
clang-format -i <文件>
```

## 规范

### 代码风格
- **列限制**: 119 字符
- **缩进宽度**: 4 个空格
- **指针对齐**: 右对齐（`int* ptr`）
- 代码完成后必须使用 `clang-format -i <file>` 格式化

### API 兼容性
- **接口层 API**（NDK/JS/ETS）：绝对不能破坏向后兼容
- **Inner APIs** (`interfaces/inner_api/`): 不建议修改，如必须修改需与依赖组件协调

### 错误处理
- **错误码分层**: 三层架构（SQLite/RD内核 → Native层 → 接口层），详见 [错误码分层体系](docs/error_code_layers.md)
- **绝对禁止**让接口层存量接口返回新的错误码，或同场景错误码发生变更。
- 使用 `rdb_errno.h` 中定义的标准化错误码

### 代码提交
- Commit 信息必须包含 `Co-Authored-By: Agent`
- 不允许把 Agent 修改为其它单词

## 工作流程

### 添加新功能
1. **实现接口层**：NDK/JS/ETS 接口在相应目录添加，内部接口在 `interfaces/inner_api/rdb/include/`
2. **实现 Native 层**：在 `frameworks/native/rdb/src/` 中实现
3. **编写测试**：在 `test/native/rdb/unittest/`、`test/js/` 或 `test/ets/` 中添加
4. **检查依赖**：新增外部依赖优先用动态加载（详见 [动态加载和卸载机制](docs/dynamic_loading.md)）
5. **构建测试**：运行 `NativeRdbTest`、`NativeRdbMultiThreadTest`、`NativeRdbMultiProcessTest`

## 注意事项

### 开发技巧
- **接口性能**: 修改存量接口时评估性能影响，使用连接后及时释放
- **日志打印**: 错误日志提供充足信息，减少高频分支的正常打印
- **多线程/多进程**: 一个连接只允许一个线程使用，跨进程访问通过 IPC
- **跨平台**: 优先使用 GN 构建系统控制跨平台差异，避免在代码中使用编译宏

### 关键文件路径
- `relational_store.gni` - 跨仓路径定义
- `frameworks/native/rdb/src/rdb_service_proxy.cpp` - IPC 服务代理
- `frameworks/native/rdb/src/global_resource.cpp` - 动态库卸载管理
- `interfaces/inner_api/rdb/include/rdb_errno.h` - 错误码定义

### 常见陷阱
- 文件操作要考虑进程中断场景，中断后要可恢复
- 共享资源需要考虑多进程并发访问场景
- 不能过度依赖服务端SA进程，因为SA进程可能未启动或者不存在
