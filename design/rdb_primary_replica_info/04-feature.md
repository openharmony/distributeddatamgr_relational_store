---
feature_id: "FEAT-20261008-001"
rr_id: ""
title: "relational_store 主备库信息查询"
date: "2026-10-08"
status: Draft
---
# Feature

> 阶段 0.4 草案。feature_id 为本地草案追踪号；01 未提供 RR 单号，正式归档信息仍按用户要求暂缓。

## 1. 概述与价值

为 relational_store 增加 Native C++ 内部接口，按调用者请求获取主备库 DB/WAL 大小、文件修改时间和可选普通表的精确行数，并报告回放、checkpoint、采集失败及缺句柄时的跳过状态，支持调用者比较主备差异。

| 字段 | 内容 |
|------|------|
| RR单号 | 未提供；01-requirement.md frontmatter 的 rr_id 为空，正式归档暂缓 |
| 特性优先级 | 未提供，待正式评审确定 |
| 目标版本 | 未提供，按用户要求暂缓归档 |
| 初步影响范围 | OpenHarmony distributeddatamgr / relational_store |
| Owner / SIG | relational_store 模块 Owner 与 SIG 评审角色待指派/确认 |

## 2. 范围

### 目标

- 增加 Native C++ 内部入口和结果类型；不增加 JS、ETS、NDK 或 IPC 接口。
- 对主库和备库分别提供 DB/WAL 字节大小及归纳文件修改时间。Connection 原始提供 DB、WAL、binlog 的 Unix 毫秒修改时间；RdbStore 主库取 DB/WAL 较大值，备库存在关联 binlog 时取最新 binlog 时间，否则取 DB/WAL 较大值。
- 所有原始修改时间先采集；存在 binlog 时尝试回放，随后分别尝试主库、备库 checkpoint，再采集文件大小和可选的单个普通表精确行数。
- 只复用主连接已有的备库连接；无连接时不尝试打开，跳过依赖句柄的回放、checkpoint 和表计数，返回主库可用信息。
- 各步骤保留独立状态，失败时返回已取得的部分结果；支持 MAIN_REPLICA、MANUAL_TRIGGER、已有加密能力和并发写入采样。

### 非目标

- 不提供跨主备的原子快照或数据一致性证明；不同指标可对应不同采样时点。
- 不主动恢复、重建、删除或创建备库；不因诊断接口触发额外复制。
- 不返回表内容、不对比行内容、不支持多表/视图/系统表计数。
- 不更改存量 API 的行为、返回码或既有 JS/ETS/NDK 接口；不设性能或耗时验收目标。
- 不在本 Feature 中确定未提供的 RR、优先级、目标版本或人员任命。

## 3. 成功标准（AC）

| AC# | 标准 | 可观察指标 | 验证方式 |
|-----|------|-----------|---------|
| AC-01 | Native C++ 内部调用者可调用主备信息入口；没有新增 JS/ETS/NDK/IPC 绑定 | inner_api 有新增入口与结果类型；相关绑定及 IPC 定义无新增 | API/构建清单检查；Native 单测编译调用 |
| AC-02 | Connection 在回放和 checkpoint 前分别采集主备 DB、WAL、关联 binlog 修改时间，统一为 Unix 毫秒 | 原始时间字段可分别判断成功、缺失和失败；固定秒/纳秒输入折算为 `sec*1000+nsec/1000000` | 文件时间控制单测；校验采样顺序和单位 |
| AC-03 | RdbStore 按各库规则返回归纳时间 | 主库只取 DB/WAL 较大值；备库有关联 binlog 时取其最大时间，否则取 DB/WAL 较大值 | 构造 DB/WAL/binlog 时间组合，断言边界值及回放前时间 |
| AC-04 | 存在可回放 binlog 时先尝试回放并记录结果；没有日志或内核不支持时结果能区分对应状态 | 回放状态和错误独立于其余指标；辅助索引不被当作数据日志 | 单日志、多日志、辅助文件、无日志及错误注入单测 |
| AC-05 | 回放后主库与备库 checkpoint 分别尝试并分别记录结果 | 两个目标有各自状态；主库失败不隐藏备库尝试结果，反之亦然 | 对主/备 checkpoint 分别注入 BUSY/CORRUPT 并检查结果 |
| AC-06 | 返回主、备 DB 文件和 WAL 文件各自大小，单位字节 | 四个大小字段分别可用，缺失与 stat 错误不会伪装成有效的零值 | 临时数据库/WAL 文件大小单测及文件访问错误注入 |
| AC-07 | 指定一个普通表时分别返回对应库的精确 64 位行数；未指定时不执行计数 | 主备插入不同已知行数后各自返回正确标量；非普通表和非法标识符不会误计数 | 表存在、零行、缺失、引号标识符及非法标识符用例 |
| AC-08 | 备库已有连接时直接使用；无连接时不尝试打开备库，并跳过依赖备库句柄的回放、checkpoint 和计数 | 不发生诊断打开调用；依赖句柄的操作不执行，主库可用结果仍返回 | 已有连接、无连接但文件存在、无连接且文件缺失用例；检查不打开、不创建或主动恢复/重建备库 |
| AC-09 | 任一步失败仍返回其它已取得的信息和逐项失败原因 | 对失败字段有状态/错误，对成功字段保留有效值 | 分别注入时间采集、回放、checkpoint、stat、计数和备库句柄不可用 |
| AC-10 | 两种主备模式、既有加密配置及并发写入下接口按约定工作 | 不主动恢复/重建；并发写入不要求所有字段同一逻辑时点；非 SQLite 后端按约定返回不支持 | MAIN_REPLICA/MANUAL_TRIGGER、加密库、并发写入 UT；目标设备与 ABI 验证 |

## 4. 受影响模块（跨仓）

| 领域 | 仓库 | 模块/路径 | 影响类型 | 兼容性策略 | Owner / SIG |
|------|------|-----------|---------|-----------|-------------|
| distributeddatamgr | relational_store | interfaces/inner_api/rdb；RdbStoreImpl | 新增内部查询入口和返回结构；存量行为保持 | opt-in 新增 API；保留所有存量签名及语义 | Owner、SIG 待指派/确认 |
| distributeddatamgr | relational_store | frameworks/native/rdb/src/rdb_store_impl.cpp | 新增编排路径；避免复用恢复分支 | 新增调用路径；不改变旧方法行为 | Owner、SIG 待指派/确认 |
| distributeddatamgr | relational_store | frameworks/native/rdb/include/connection.h、statement.h | 新增连接级诊断能力，不改变存量方法含义 | 新增虚接口保持旧方法签名与行为；非 SQLite 后端默认不支持 | Owner、SIG 待指派/确认 |
| distributeddatamgr | relational_store | frameworks/native/rdb/src/sqlite_connection.cpp | 可复用内核调用；诊断路径补充严格来源与状态返回 | 新增 SQLite 诊断路径；连接归还沿用存量 checkpoint 错误处理 | Owner、SIG 待指派/确认 |
| distributeddatamgr | relational_store | frameworks/native/rdb/src/sqlite_utils.cpp、rdb_db_info_manager.cpp | 路径和文件采集复用；增加最新数据日志时间与逐项失败表达 | 不改变存量 Stat/Collect；新路径单独返回采集状态 | Owner、SIG 待指派/确认 |
| distributeddatamgr | relational_store | frameworks/native/rdb/src/connection_pool.cpp | 管理连接生命周期；候选 B 涉及受管临时连接 | 方案 A 复用受管主连接并由其持有新开的备库连接；不新增临时连接 | Owner、SIG 待指派/确认 |
| distributeddatamgr | relational_store | frameworks/native/rd/src/rd_connection.cpp | 新接口默认不支持；不引入 SQLite 行为 | 默认不支持新增诊断能力；存量 RD 行为保持 | Owner、SIG 待指派/确认 |
| distributeddatamgr | appdata_master_mock | mock/sqlite/include/sqlite3sym.h、mock/sqlite/src/sqlite3.c | 既有依赖；验证扩展可用性，不新增第三方依赖 | 本方案不计划改动 SQLite 内核；以现有扩展进行验证 | Mock 仓维护者待确认 |

模块覆盖检查结论：**pass**。已逐项覆盖 02 §2.1 全部 8 行；mock/sqlite 为现有依赖，方案不新增或修改该内核依赖。

术语一致性检查结论：**pass**。relational_store 各模块的影响类型标签与 02 §2.1 一致；mock/sqlite 行说明为对该表“本地 SQLite 配套内核”事实的范围澄清，不扩大代码改动范围。

目标仓 Owner 和 SIG 角色尚未提供；以上影响行已明确标注待指派/确认，不能据此视作正式责任任命。

### 需求变更影响性分析

| 影响方 | 影响类型 | 分析 |
|--------|----------|------|
| 北向应用开发者 | 无影响 | 不新增 NDK、JS、ETS API，不改变应用现有调用方式。 |
| 南向开发者 | 正向优化 | Native 模块内部可获得主备库状态、文件信息和可选表计数，具体 API 需按本 Feature AC 实现。 |
| 分布式设备 | 无影响 | 不改变跨设备复制协议、传输内容或一致性语义；允许的本地采样不构成同步保证。 |
| 系统开发者（跨子系统） | 无影响 | 不新增跨子系统接口、服务或 IPC 依赖。 |
| 设备使用者 | 无影响 | 不增加直接可见的设置、界面或操作；接口作为 Native 诊断能力供内部调用。 |

## 5. 拆解指引

选定方案：A（见 [03-arch-decision-record.md](03-arch-decision-record.md)）。按 R1→R2→R3 检查，当前资料只表明一个 `relational_store` 子系统，无证据显示需由不同 Owner/SIG 独立交付，也未超过 5 人月简单特性上限；因此建议按 R4 默认不拆，提交 **1 个 proposal**。这是待用户确认的拆分草案，尚未进入 Step 0.5。

| Proposal | 文件 | 边界/职责 | 估算工作量(人月) | Owner | 依赖 | GA 状态 |
|----------|------|----------|-----------------|-------|------|---------|
| PROP-01 relational_store 主备库信息接口 | 待拆分确认后生成 | relational_store Native inner_api、RdbStore 编排、Connection/SqliteConnection 诊断操作、结果与错误状态、对应测试和构建验证；覆盖 AC-01～AC-10 | 1.68～2.52（端到端估算） | relational_store 模块 Owner 待指派 | 复用现有 SQLite/binlog 能力；无跨 proposal 依赖 | 待 SIG 评审 |

| 汇总项 | 结果 |
|--------|------|
| Proposal 数量 | 1（草案，待用户确认） |
| 端到端总工作量 | 1.68～2.52 人月，沿用 02 的方案 A 区间，不是排期承诺 |
| 复杂度 | 简单（总工作量 <5 人月；单 proposal 上限 5 人月） |
| 拆分依据 | R1：已识别代码范围都属于同一 relational_store 目标仓；mock/sqlite 是既有验证依赖，无独立改动 proposal。R2：无已证据支持的跨 Owner 子系统拆分。R3：估算低于简单特性 5 人月上限。故按 R4 单 proposal 草案。 |
| 初步交付里程碑 | M1 Native 类型和连接级诊断操作；M2 RdbStore 编排和逐项结果；M3 定向构建、UT 与 ABI/目标环境核验。日期待目标版本和模块排期确定。 |
| 条件项与依赖 | 02 §5 的 binlog 文件筛选、既有加密/VFS、并发及 ABI 验证项需在相应设计/实现/验证节点关闭；03 §6 正式责任人与关闭时间仍待用户评审记录。 |

**拆分确认门禁：** 请用户确认上述单 proposal 草案，或提出调整。在收到确认前，04 保持 Draft，不进入 Review Ready Gate。

## Phase 2 验证项（来自 02）

实现阶段至少核验：回放前时间顺序及毫秒折算；主备计数来源；回放和两库 checkpoint 独立失败；无备库连接时不打开并跳过依赖句柄的操作；不主动创建或恢复/重建备库；精确 COUNT(*) 与普通表标识符处理；binlog 数据文件筛选；两种 HA 模式、加密、自定义目录、并发资源寿命；新增虚接口 ABI 与正式目标构建。连接归还沿用存量 checkpoint 错误处理。详细验证边界见 02 §2.5 和 §5。
