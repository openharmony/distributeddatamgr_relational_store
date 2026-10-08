# 架构概述

## 项目定位

这是 OpenHarmony 分布式数据管理子系统 (`appdatamgr`) 的 mock 仓库。本地环境使用 Cygwin 在 Windows 上模拟 Unix 环境，使用 CMake 作为构建系统。该仓库实现了完整的数据管理组件，包括关系型数据库、首选项、数据共享、KV 存储、分布式数据对象和 UDMF（用户数据管理框架）。

### AGENTS.md 说明

项目各目录下存在 `AGENTS.md` 文件，记录了对应 OpenHarmony 上游仓库的说明和上下文信息。在开发或修改某个模块时，参考该模块目录下的 `AGENTS.md` 以了解上游仓库的架构和设计意图。

## 组件结构

仓库组织为几个主要组件：

1. **relational_store/** - 关系型数据库（RDB）组件
   - 基于 SQLite 作为持久化引擎，支持 ACID 特性：事务、索引、视图、触发器、外键
   - 最多 4 个连接池，同时只能有一个写操作
   - 详见 [relational_store/AGENTS.md](../relational_store/AGENTS.md)

2. **data_object/** - 分布式数据对象管理
   - 具有分布式能力的内存对象管理，基于会话的对象同步
   - 内存约束：每个对象 100-150KB
   - 详见 [data_object/AGENTS.md](../data_object/AGENTS.md)

3. **preferences/** - 首选项数据库
   - 本地应用的轻量级键值存储，数据加载到内存以快速访问
   - 约束：键最多 80 字符，字符串值最多 8192 字符，建议最多 10,000 条记录
   - 详见 [preferences/AGENTS.md](../preferences/AGENTS.md)

4. **kv_store/** - 轻量型 KV 数据库
   - 轻量型设备的键值对数据管理，仅单进程访问
   - 详见 [kv_store/AGENTS.md](../kv_store/AGENTS.md)

5. **data_share/** - 数据共享组件
   - 管理应用数据并支持同一设备上应用间的共享，使用数据共享适配器进行跨应用通信
   - 详见 [data_share/AGENTS.md](../data_share/AGENTS.md)

6. **datamgr_service/** - 分布式数据管理服务
   - 分布式数据协调的核心服务，管理备份、引导、配置、加密、目录和矩阵服务
   - 详见 [datamgr_service/AGENTS.md](../datamgr_service/AGENTS.md)

7. **udmf/** - 用户数据管理框架
   - 管理用户数据生命周期和权限，支持数据预处理、存储和生命周期管理
   - 详见 [udmf/AGENTS.md](../udmf/AGENTS.md)

8. **mock/** - Mock 基础设施
   - OpenHarmony 子系统的广泛 mock 库，包括 IPC、能力运行时、包框架、安全服务
   - 对于在没有完整 OpenHarmony 环境的情况下进行测试至关重要

9. **data_mining/** - Data Mining 客户端 SDK
   - 结构化数据类型定义（Schema、Record、RecordBatch）
   - ETL Pipeline 算子接口（Source、Operator、Sink）
   - ETL 客户端门面类（EtlClient），通过 IPC 触发远程 Pipeline
   - 插件动态加载系统（PluginModule、PluginRegistry）

10. **data_mining_service/** - Data Mining SA 服务
    - 独立 System Ability 服务（SAID=1311）
    - Pipeline 运行时引擎，管理 Pipeline DAG 构建与执行
    - 客户端库（DataMiningClient），通过 IPC Dispatch 到 SA
    - 插件生命周期管理和远程连接

## 架构模式

**分层架构：**
- 接口层 (`interfaces/`) - 公共 API 和接口
- 框架层 (`frameworks/`) - 内部实现
- 实现层 (`src/`) - 核心功能

**分布式架构：**
- SoftBus 用于设备通信
- 基于会话的对象同步
- 云同步能力

**面向服务：**
- 微服务风格的组件
- 使用 mock IPC 实现的基于 IPC 的通信
- 基于能力的安全性，使用基于令牌的身份验证

### 关键设计模式

- 观察者模式：用于数据更改通知
- 工厂模式：用于对象创建
- 适配器模式：用于组件兼容
- 单例模式：用于服务管理器
- 策略模式：用于不同的存储后端

## 关键约束

### RDB 约束
- 最多 4 个连接池
- 同时只能有一个写操作
- 基于 SQLite 的持久化

### 分布式数据对象约束
- 每个对象：100-150KB 内存
- 基于会话的标识
- 最大对象大小：500KB

### 首选项约束
- 键字符串：最多 80 个字符
- 字符串值：最多 8192 个字符
- 建议最多：10,000 条记录

### 其他组件约束

各模块的详细约束见对应模块的 AGENTS.md：
- [kv_store/AGENTS.md](../kv_store/AGENTS.md) — KV 存储约束
- [data_share/AGENTS.md](../data_share/AGENTS.md) — 数据共享约束
- [datamgr_service/AGENTS.md](../datamgr_service/AGENTS.md) — 分布式数据管理服务约束
- [udmf/AGENTS.md](../udmf/AGENTS.md) — UDMF 约束

## 代码规范

### 编码标准

项目使用 Google 风格格式化（在 `.clang-format` 中配置）：
- 缩进：4 个空格（无制表符）
- 行长度：119 个字符
- 指针对齐：右对齐
- Include 排序：启用
- 基于：Google 风格

### 命名约定

| 类型 | 约定 | 示例 |
|------|------|------|
| 类 | PascalCase | `DistributedObject` |
| 函数 | camelCase | `createDistributedObject` |
| 变量 | camelCase | `sessionId` |
| 常量 | SCREAMING_SNAKE_CASE | `MAX_OBJECT_SIZE` |

### 文件组织

- 头文件：单独的 include 目录
- 源文件：按组件组织
- 测试：在 `test/` 目录中镜像源结构
- 构建：按类型组织输出（bin、lib）

## 目录组织约定

项目根目录下除了代码仓、构建目录和工具目录外，还有以下组织约定：

### 设计文档 (`design_doc/`)

单次需求的设计文件（设计文档、分析报告、PPT、生成脚本等）统一放到 `design_doc/` 下，按主题分子目录组织：

```
design_doc/
├── api_misuse_audit/     # API 误用排查
│   ├── report.md
│   └── workspace/
├── db_layout/            # 数据库布局设计
│   ├── layout.pptx
│   └── gen_script.js
└── rdb_dfx_analysis/     # RDB DFX 分析
    ├── analysis.pptx
    └── gen_script.js
```

**规则**：
- 每个单次需求完成后，其设计文件移入 `design_doc/<topic>/`
- 主题命名用小写下划线（如 `api_misuse_audit`）
- 不要将设计文件留在项目根目录

### 同步产物 (`sync_output/`)

代码同步工具（`bin/update/sync.ps1`）产生的报告和日志统一放到 `sync_output/` 下，按日期区分：

```
sync_output/
├── 20260913/             # 按日期组织（YYYYMMDD）
│   ├── backup/          # 被覆盖冲突文件的备份
│   ├── extra_files.md    # 本地独有文件报告
│   ├── diff_report.md   # 差异报告
│   ├── change_log.md    # 变更日志
│   └── sync.log         # 同步日志
├── 20260822/
│   └── ...
└── (无日期文件)          # 早期/手动产生的报告放根级
```

**规则**：
- 同步工具的输出路径应在 `sync_output/<date>/` 下
- 运行时状态文件（`.sync_state.json`、`tmp/`）保留在 `bin/update/` 下
- 构建日志放在 `tmp/` 目录下（`tmp/build_output.log`），不放在项目根目录

### 构建日志

构建和测试产生的日志文件（如 `tmp/build_output.log`、`ctest_output.log`、`native_rdb_*.log`）放在 `tmp/` 目录下，不长期保留在项目根目录。需要时重新生成即可。

## 重要说明

- 这是一个 mock/test 仓库，不是生产 OpenHarmony 代码
- 使用 Cygwin 在 Windows 上模拟 Unix 环境
- 所有 OpenHarmony 子系统依赖都是 mock
- SQLite 用作底层存储引擎
- 测试可以在没有完整 OpenHarmony 环境的情况下独立运行
- 配置文件使用 JSON 格式
- 具有特定错误代码的全面错误处理
