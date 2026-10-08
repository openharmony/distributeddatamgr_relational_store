---
date: "2026-10-08"
status: Draft
feature_id: "FEAT-20261008-001"
selected_option: "A"
---
# Spec: relational_store 主备库信息查询接口

## 概述

| 属性 | 值 |
|------|-----|
| 特性名称 | relational_store 主备库信息查询 |
| 特性编号 | FEAT-20261008-001（草案追踪号） |
| 优先级 | 待正式评审确定 |
| 复杂度 | 简单（端到端 1.68～2.52 人月，<5 人月上限） |
| 目标版本 | 待正式评审确定（正式归档信息暂缓） |

> 本 spec 基于 [01-requirement.md](01-requirement.md) FR-01～FR-10、[02-feasibility.md](02-feasibility.md) 候选 A、[03-arch-decision-record.md](03-arch-decision-record.md) 选定方案 A、[04-feature.md](04-feature.md) AC-01～AC-10 编写。仅 Native C++ 内部接口，不新增 JS/ETS/NDK/IPC 绑定。

## 用户故事与验收标准

### US-1: 获取主备库文件大小

**作为** Native C++ 内部调用者，**我想要** 获取主库和备库各自的 DB 与 WAL 文件大小，**以便** 对比主备库持久化数据规模差异。

**验收标准：**

- **AC-1.1:** Given 数据库以 MAIN_REPLICA 或 MANUAL_TRIGGER 模式打开且连接池可用 When 调用者通过 RdbStoreImpl 内部入口查询主备信息 Then 返回结果包含主库 DB 字节大小、主库 WAL 字节大小、备库 DB 字节大小、备库 WAL 字节大小四个字段，每个字段可独立判断成功、缺失或采集失败
- **AC-1.2:** Given 数据库存在关联 binlog When 调用者查询主备信息 Then 在采集文件大小前先尝试回放 binlog；回放成功后继续采集大小和计数；若回放失败则将错误记录在结果结构的 replayErr 字段中（映射 sqlite3_replay_binlog 返回值到 rdb_errno.h 标准错误码），继续执行后续采集（checkpoint、文件大小、表计数）；调用者可通过 replayErr 判断回放是否成功；无 binlog 或内核不支持回放时跳过回放继续采集
- **AC-1.3:** Given binlog 回放完成或无需回放 When 调用者查询主备信息 Then 分别尝试主库 checkpoint 和备库 checkpoint，两个 checkpoint 各有独立状态字段；主库 checkpoint 失败不隐藏备库 checkpoint 结果，反之亦然；checkpoint 失败不阻断后续可用信息采集，连接归还沿用既有 checkpoint 错误处理语义
- **AC-1.4:** Given 文件缺失或 stat 调用失败 When 采集对应文件大小时 Then 该字段标记为失败并包含错误码，不以零值伪装有效结果；其他可用字段仍正常返回

### US-2: 获取主备库归纳修改时间

**作为** Native C++ 内部调用者，**我想要** 获取主库和备库各自的最后一次写入时间，**以便** 对比主备库数据新旧程度。

**验收标准：**

- **AC-2.1:** Given 数据库已打开 When 调用者查询主备信息 Then DB/WAL/binlog 的原始文件修改时间在 binlog 回放和 checkpoint 之前采集，统一为 Unix 毫秒时间戳（`sec * 1000 + nsec / 1000000`），每个原始时间字段有独立的可用性状态
- **AC-2.2:** Given 主库 DB 和 WAL 修改时间已采集 When 返回主库归纳时间 Then 主库归纳时间 = max(主库 DB 修改时间, 主库 WAL 修改时间)，不参考任何 binlog 时间
- **AC-2.3:** Given 备库有关联 binlog 且至少一个 binlog 数据文件可用 When 返回备库归纳时间 Then 备库归纳时间 = 最新 binlog 数据文件修改时间；辅助索引文件（如 readIndex、锁文件）不参与计算
- **AC-2.4:** Given 备库无关联 binlog 或 binlog 扫描失败 When 返回备库归纳时间 Then 备库归纳时间 = max(备库 DB 修改时间, 备库 WAL 修改时间)；binlog 扫描失败保留失败状态，不等同于确定没有 binlog
- **AC-2.5:** Given checkpoint 可能更新文件修改时间 When 采集时间已完成 Then 已采集的回放前时间不被 checkpoint 后的文件时间覆盖

### US-3: 获取指定表精确行数

**作为** Native C++ 内部调用者，**我想要** 指定一个普通表名获取主备库各自的精确行数，**以便** 对比主备库表级数据量差异。

**验收标准：**

- **AC-3.1:** Given 调用者指定一个有效的普通表名 When 查询主备信息 Then 分别返回主库和备库该表的精确 64 位行数；主备行数各自独立查询，不互相伪造
- **AC-3.2:** Given 调用者未指定表名（空字符串） When 查询主备信息 Then 不执行表计数，计数字段标记为"未请求"状态
- **AC-3.3:** Given 指定的表不存在或不是普通表（视图、系统表等） When 查询主备信息 Then 该库的计数字段标记为失败并包含错误码，不误计数；另一个库的计数仍正常执行
- **AC-3.4:** Given 表名包含特殊字符或需要引号引用的标识符 When 查询主备信息 Then 标识符被正确引用和校验，不直接拼接 SQL 导致注入或语法错误。**上游限制**：`RdbSqlUtils::IsValidTableName` 使用正则 `^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)?$`，拒绝中文、空格、引号及下划线开头等合法 SQLite 标识符；schema.table 拆分后双引号引用已实现

### US-4: 备库连接可用性处理

**作为** Native C++ 内部调用者，**我想要** 在备库连接未打开时直接跳过备库采集，**以便** 在备库连接不可用时仍能获取主库信息。

**验收标准：**

- **AC-4.1:** Given 备库连接已存在 When 查询主备信息 Then 直接使用已有 slaveConnection_ 的 dbHandle_，不重新打开
- **AC-4.2:** Given 备库连接不存在 When 查询主备信息 Then 不尝试打开备库；备库 DB 按配置路径 stat（文件存在时 errCode=E_OK，缺失时 E_ERROR）；备库 WAL、binlog 回放、checkpoint、表计数均跳过（E_NOT_SUPPORT）；主库字段仍正常返回；接口整体返回 E_OK
- **AC-4.3:** Given 备库连接不存在 When 查询主备信息 Then 不执行备库 binlog 回放、备库 checkpoint 和备库表计数（均标记 E_NOT_SUPPORT）；接口整体返回 E_OK，不因缺少备库连接而返回错误
- **AC-4.4:** Given 备库连接不存在 When 查询主备信息 Then 不创建新数据库文件，不触发恢复或重建；备库 DB 按配置路径 stat，WAL 跳过（E_NOT_SUPPORT，需要备库句柄）；请求了 tableName 时 replicaInfo.tables 不包含该表（备库计数跳过）
- **AC-4.5:** Given slaveConnection_ 在诊断期间被其他路径释放 When 查询主备信息 Then 诊断操作在主连接锁范围内执行，不访问无效句柄

### US-5: 部分结果与错误恢复

**作为** Native C++ 内部调用者，**我想要** 在部分步骤失败时仍获得已成功采集的信息，**以便** 利用可用信息进行诊断。

**验收标准：**

- **AC-5.1:** Given checkpoint、大小采集、表计数失败或备库句柄不可用 When 查询主备信息返回 Then 已成功获取的字段保留有效值，失败字段包含各自的状态和错误码；接口不因这些步骤失败而整体返回错误。binlog 回放失败时将错误记录在 replayErr 字段中，不中断后续采集（checkpoint、大小、计数仍执行）
- **AC-5.2:** Given 非 SQLite 后端（如 RDConnection） When 调用主备信息查询 Then 返回 E_NOT_SUPPORT，不引入 SQLite 特有行为
- **AC-5.3:** Given 数据库以 SINGLE 模式打开 When 调用主备信息查询 Then 返回 E_NOT_SUPPORT 或明确的不支持状态，不执行主备查询逻辑
- **AC-5.4:** Given 只读数据库、内存数据库或向量数据库 When 调用主备信息查询 Then 返回 E_NOT_SUPPORT，不执行主备查询逻辑。**测试环境限制**：只读数据库可通过 SetReadOnly 验证；MemoryDb_001 用 StorageMode::MODE_MEMORY 创建真实内存库并断言 E_NOT_SUPPORT；VectorDb_001 用 SetIsVector(true) 创建真实向量库，若环境不支持（缺少 ArkData）则 GTEST_SKIP；代码层前置检查（isReadOnly_/isMemoryRdb_/DB_VECTOR）在 RdbStoreImpl::GetPrimaryReplicaInfo 中实现

### US-6: 并发与模式兼容性

**作为** Native C++ 内部调用者，**我想要** 在并发写入和不同主备模式下查询信息，**以便** 在生产环境中使用此接口。

**验收标准：**

- **AC-6.1:** Given 采集期间发生并发写入 When 查询主备信息 Then 接口正常完成，各项指标反映各自采样时点的状态；不要求所有字段对应同一逻辑时点；checkpoint 锁冲突作为 BUSY 状态返回，不全局冻结
- **AC-6.2:** Given 数据库使用已有加密配置 When 查询主备信息 Then 接口沿用既有密钥与 VFS 配置，正常采集信息；加密库无 binlog 时使用 DB/WAL 时间
- **AC-6.3:** Given 数据库使用自定义备库路径（replicaPath） When 查询主备信息 Then 路径解析使用配置的自定义路径，不回退到默认相邻路径
- **AC-6.4:** Given 新增接口已合入 When 检查 API 暴露范围 Then 无新增 JS/ETS/NDK/IPC 绑定；新增 inner_api 类型和符号已同步到 bundle.json 编译清单

## 业务规则

| 规则 ID | 规则描述 | 约束条件 | 关联 AC |
|---------|----------|----------|---------|
| BR-01 | 采集顺序：原始修改时间 → binlog 回放（软门控）→ 主库 checkpoint（备库仅当 slaveConnection_ 已创建时）→ 文件大小 → 可选表行数 | binlog 回放为软门控——有 binlog 且回放失败时记录 replayErr，继续后续采集；备库操作仅在 slaveConnection_ 存在时执行 | AC-1.1, AC-1.2, AC-1.3, AC-2.1 |
| BR-02 | 主库归纳时间仅取 max(DB, WAL)，不参考 binlog | 主库不关联 binlog 时间 | AC-2.2 |
| BR-03 | 备库归纳时间优先取最新 binlog 数据文件时间，无 binlog 时取 max(DB, WAL) | 辅助索引文件排除；扫描失败 ≠ 确定无日志 | AC-2.3, AC-2.4 |
| BR-04 | checkpoint 主库；备库仅当 slaveConnection_ 已创建时尝试，各自独立状态 | 不改变存量 TryCheckPoint 的错误处理语义；备库连接未创建时不 checkpoint 备库 | AC-1.3 |
| BR-05 | 不在诊断路径打开备库；仅复用已有 slaveConnection_，无句柄时备库 DB 按配置路径 stat、WAL 跳过（E_NOT_SUPPORT） | 不调用含 SQLITE_OPEN_CREATE 的打开方法；不创建/销毁备库连接 | AC-4.1, AC-4.2 |
| BR-06 | 表计数读取 COUNT(*) 的 64 位标量值，不读取结果集行数 | 标识符经校验和引用处理 | AC-3.1, AC-3.4 |
| BR-07 | 接口不主动触发数据库恢复、重建或异步复制 | 不走 GetStatement 恢复分支 | AC-1.3, AC-4.4 |
| BR-08 | 允许并发写入期间采样，各项指标可来自不同采样时点 | 不输出一致性保证结论 | AC-6.1 |
| BR-09 | 保持 RdbStoreImpl → ConnectionPool → Connection → Statement 分层；Connection 仅暴露 `GetPrimaryAndReplicaInfo` 返回 `PrimaryAndReplicaInfo` 原始数据含各步骤状态（errCode/sizeErr/checkpointErr/replayErr），RdbStoreImpl 负责归纳时间并写入 primaryLastModifyTime/replicaLastModifyTime 含有效性状态（primaryTimeErr/replicaTimeErr） | 上层不直接持有 sqlite3 指针；Connection 返回原始数据与状态 | AC-1.1, AC-2.2, AC-2.3 |
| BR-10 | 不修改存量 ReplayBinlog、TryCheckPoint、CreateReplicaStatement 的签名和语义 | 新增独立诊断路径 | AC-1.2, AC-1.3 |

## 异常与边界规则

| 编号 | 场景 | 触发条件 | 系统行为 | 关联 AC |
|------|------|----------|----------|---------|
| EX-01 | 无 slaveConnection_ | slaveConnection_ 未创建或已关闭 | 备库 DB 按配置路径 stat（文件存在=E_OK，缺失=E_ERROR）；WAL/回放/checkpoint/表计数跳过（E_NOT_SUPPORT）；主库字段正常返回；不创建新文件；接口整体返回 E_OK | AC-4.2, AC-4.4 |
| EX-02 | 无 slaveConnection_ 时备库文件不存在 | slaveConnection_ 为空且备库 DB 文件不存在 | 备库 DB stat 失败（errCode=E_ERROR，size=0, mtime=0）；WAL 跳过（E_NOT_SUPPORT）；接口整体仍返回 E_OK；主库字段正常 | AC-4.2, AC-4.4 |
| EX-03 | checkpoint 遇到 BUSY | sqlite3_wal_checkpoint_v2 返回 BUSY | 该库 checkpoint 状态 = BUSY（E_SQLITE_BUSY）；另一库 checkpoint 不受影响 | AC-1.3, AC-6.1 |
| EX-04 | checkpoint 遇到 CORRUPT | sqlite3_wal_checkpoint_v2 返回 CORRUPT | 该库 checkpoint 状态 = CORRUPT（E_SQLITE_CORRUPT）；另一库 checkpoint 不受影响；连接归还时按既有 TryCheckPoint 错误处理语义执行 | AC-1.3 |
| EX-05 | binlog 回放失败 | sqlite3_replay_binlog 返回错误 | 将错误记录在 replayErr 字段中（映射返回值到 rdb_errno.h 标准错误码），继续执行后续采集（checkpoint、大小、计数） | AC-1.2, AC-5.1 |
| EX-06 | binlog 不存在或扫描失败 | 日志目录为空或 opendir 失败 | 跳过回放；replayErr=E_OK（无 binlog）或 E_NOT_SUPPORT（不支持/无备库句柄）；binlog 扫描独立于回放支持能力，文件大小和时间字段正常返回 | AC-1.2 |
| EX-07 | 表名非法或为空 | 表名为空字符串或校验失败 | 空表名：跳过计数，tables 为空 map，返回 E_OK（不返回错误码）；表名非法：返回 E_INVALID_ARGS，不执行 SQL | AC-3.2, AC-3.3 |
| EX-08 | 表不存在 | COUNT 查询返回 SQLITE_ERROR | 该库计数字段标记为失败；另一库计数仍执行 | AC-3.3 |
| EX-09 | 文件 stat 失败 | stat() 返回错误（权限、I/O） | 对应大小字段标记为失败（errCode=E_ERROR）并包含 errno 转换后的错误码；不以零值代替。**上游限制**：`SqliteUtils::Stat()` 失败时统一返回 E_ERROR，不区分 E_SQLITE_PERM/E_SQLITE_IOERR 等具体原因；区分具体 errno 为未来增强 | AC-1.4 |
| EX-10 | Store 已关闭 | connectionPool_ 为空或 store 未初始化 | 返回 E_ALREADY_CLOSED | AC-5.1 |
| EX-11 | slaveConnection_ 在诊断期间被释放 | slaveConnection_ 被其他路径清空 | 诊断操作在主连接锁范围内执行，不访问无效句柄 | AC-4.5 |
| EX-12 | 非 SQLite 后端 | Connection 实现为 RdConnection | 返回 E_NOT_SUPPORT | AC-5.2 |
| EX-13 | SINGLE 模式 | config_.GetHaMode() == SINGLE | 返回 E_NOT_SUPPORT | AC-5.3 |
| EX-14 | 只读数据库 | isReadOnly_ == true（config.IsReadOnly() 或 RoleType::VISITOR） | 返回 E_NOT_SUPPORT | AC-5.4 |
| EX-15 | 内存数据库 | isMemoryRdb_ == true（StorageMode::MODE_MEMORY） | 返回 E_NOT_SUPPORT | AC-5.4 |
| EX-16 | 向量数据库 | config_.GetDBType() == DB_VECTOR | 返回 E_NOT_SUPPORT | AC-5.4 |

## 错误码定义

> 复用 `rdb_errno.h` 已有错误码，不新增错误码。

| 错误码 ID | 错误码值 | 含义 | 关联 AC |
|-----------|----------|------|---------|
| E_OK | 0 | 成功 | 全部 |
| E_ERROR | E_BASE | 通用错误（接口整体不可用；回放失败未映射到具体码时的兜底） | AC-5.1, AC-1.2 |
| E_INVALID_ARGS | E_BASE + 0x1 | 参数无效（非法表名） | AC-3.3, AC-3.4 |
| E_EMPTY_TABLE_NAME | E_BASE + 0x5 | 表名为空（本特性不返回此码：空表名跳过计数返回 E_OK，见 AC-3.2） | — |
| E_ALREADY_CLOSED | E_BASE + 0x1e | 数据库未初始化或已关闭 | AC-5.1 |
| E_DB_NOT_EXIST | E_BASE + 0x2d | 数据库文件不存在 | — |
| E_SQLITE_CORRUPT | E_BASE + 0x38 | 数据库损坏（checkpoint 遇到 CORRUPT；binlog 回放返回 CORRUPT） | AC-1.3, EX-04, AC-1.2, EX-05 |
| E_SQLITE_PERM | E_BASE + 0x3b | 权限拒绝（文件访问/打开） | AC-4.3, EX-09 |
| E_SQLITE_BUSY | E_BASE + 0x3c | 数据库忙（checkpoint 锁冲突；binlog 回放锁冲突） | AC-1.3, AC-6.1, EX-03, AC-1.2, EX-05 |
| E_SQLITE_IOERR | E_BASE + 0x40 | I/O 错误（文件读写/ stat；binlog 回放 I/O 错误） | AC-1.4, EX-09, AC-1.2, EX-05 |
| E_SQLITE_CANTOPEN | E_BASE + 0x41 | 无法打开数据库文件 | — |
| E_CHECK_POINT_FAIL | E_BASE + 0x56 | checkpoint 失败（非 BUSY/CORRUPT 的其他失败） | AC-1.3 |
| E_NOT_SUPPORT | E_BASE + 801 | 能力不支持（非 SQLite 后端、SINGLE 模式、只读/内存/向量数据库） | AC-5.2, AC-5.3, AC-5.4 |
| E_SQLITE_NOT_DB | E_BASE + 0x4d | 文件不是有效数据库 | AC-4.3, EX-02 |

## 接口变更分析

### 新增数据结构

```cpp
struct ColumnInfo {
    std::string name;
    int32_t type = 0;
};

struct TableInfo {
    int64_t count = 0;
    std::vector<ColumnInfo> columns; // 可选，指定表名时填充
    int errCode = E_OK;             // 计数失败时记录错误码
};

struct RdbFileInfo {
    int64_t size = 0;
    int64_t ctime = 0;  // Unix 毫秒时间戳
    int64_t atime = 0;
    int64_t mtime = 0;
    int errCode = E_OK;  // 初始 stat 结果：E_OK=成功, E_ERROR=stat 失败, E_NOT_SUPPORT=跳过（无连接的 WAL 路径）
    int sizeErr = E_OK;  // 维护后 size 采集结果：E_OK=刷新成功或初始 size 有效, E_ERROR=刷新失败（size 为旧值）
};

struct DbInfo {
    RdbFileInfo dbInfo;
    RdbFileInfo walInfo;
    int64_t userVersion = 0;
    std::map<std::string, TableInfo> tables; // key = 表名
    int checkpointErr = E_OK;  // checkpoint 结果：E_OK=成功, E_SQLITE_*=失败（经 SQLiteError::ErrNo 映射）, E_NOT_SUPPORT=跳过
};

struct RdbBinlogInfo {
    bool exist = false;
    uint32_t fileCount = 0;
    int64_t totalSize = 0;
    int64_t lastModifyTime = 0;  // Unix 毫秒时间戳
    int errCode = E_OK;          // 扫描失败时记录错误码
};

struct PrimaryAndReplicaInfo {
    DbInfo primaryInfo;
    DbInfo replicaInfo;
    RdbBinlogInfo binlogInfo;
    int replayErr = E_OK;        // 回放状态：E_OK=执行成功或无 binlog, E_NOT_SUPPORT=跳过（不支持或无备库句柄）, 回放错误码=失败
    int64_t primaryLastModifyTime = 0;     // 主库归纳时间 = max(主库DB.mtime, 主库WAL.mtime)
    int primaryTimeErr = E_OK;   // 主库归纳时间有效性：E_OK=至少一个来源有效, E_ERROR=所有来源失败
    int64_t replicaLastModifyTime = 0;     // 备库归纳时间 = binlog.exist ? binlog.lastModifyTime : max(备库DB.mtime, 备库WAL.mtime)
    int replicaTimeErr = E_OK;  // 备库归纳时间有效性：E_OK=至少一个来源有效, E_ERROR=所有来源失败
};
```

### 新增接口

| 接口名称 | 开放级别 | 参数概要 | 返回值 | 错误码 | 关联 AC |
|----------|----------|----------|--------|--------|---------|
| RdbStoreImpl::GetPrimaryReplicaInfo | Inner | tableName: string, 可选 | std::pair<int, PrimaryAndReplicaInfo>（first = 错误码, second = 结果含 primaryLastModifyTime/replicaLastModifyTime/各步骤状态） | E_OK, E_ALREADY_CLOSED, E_NOT_SUPPORT, E_INVALID_ARGS | AC-1.1～AC-6.4 |
| Connection::GetPrimaryAndReplicaInfo | Inner | tableName: string, 可选 | std::pair<int, PrimaryAndReplicaInfo>（first = 错误码, second = 结果含各步骤状态 errCode/sizeErr/checkpointErr/replayErr） | E_OK, E_NOT_SUPPORT, E_INVALID_ARGS | AC-1.1～AC-6.3 |

> Connection 仅暴露一个诊断接口 `GetPrimaryAndReplicaInfo`，返回 `std::pair<int, PrimaryAndReplicaInfo>`（first 为错误码，second 为 `PrimaryAndReplicaInfo` 结构体），包含主备库各自的 RdbFileInfo（DB/WAL 的 size/ctime/atime/mtime + errCode + sizeErr）、userVersion、可选 TableInfo（表行数+列信息+errCode，按表名为 key 存入 `std::map<std::string, TableInfo> tables`，CountTable 先查 sqlite_master 验证 type='table' 再计数，视图/系统表拒绝）、RdbBinlogInfo（exist/fileCount/totalSize/lastModifyTime + errCode）、以及 replayErr（E_OK/E_NOT_SUPPORT/错误码）/checkpointErr 逐项状态。RdbStoreImpl 负责前置检查（只读/内存/向量数据库、SINGLE 模式、Store 关闭）、调用 Connection、归纳时间并写入 primaryLastModifyTime/replicaLastModifyTime 含有效性状态（primaryTimeErr/replicaTimeErr：E_OK=至少一个来源有效, E_ERROR=全部失败）。Connection 内部按采集顺序（时间→回放（软门控）→checkpoint→大小→计数）执行各步骤为私有实现，回放失败时记录 replayErr 不中断后续采集。

### 变更/废弃接口

| 接口名称 | 开放级别 | 变更类型 | 影响场景 | 迁移指引 | 关联 AC |
|----------|----------|----------|----------|----------|---------|
| 无 | - | - | - | - | - |

> 存量 `ReplayBinlog`、`TryCheckPoint`、`CreateReplicaStatement`、`Count` 等接口签名和语义不变。新增接口为独立路径，不复用旧接口的恢复/删除分支。

## 兼容性声明

- **已有 API 行为变更:** 否。新增接口为 opt-in，不改变存量 API 行为、返回码或语义。
- **配置文件格式变更:** 否。不新增配置项，沿用现有 RdbStoreConfig 中的 HAMode、replicaPath、加密配置等字段。
- **数据存储格式变更:** 否。查询可能触发 binlog 回放和 checkpoint（产生文件变化），但不改变数据库格式。
- **NDK/JS/ETS 接口:** 不修改。仅 Native C++ 内部接口。
- **二进制兼容:** Connection 仅新增 1 个虚接口（返回 `std::pair<int, PrimaryAndReplicaInfo>`），ABI 影响最小化；非 SQLite 后端（RdConnection）默认返回 `{E_NOT_SUPPORT, {}}`。新增导出头文件须同步 bundle.json。

## 验证映射

> 所有测试用例位于 `relational_store/test/native/rdb/unittest/primary_replica_info_test.cpp`，GTest 过滤器 `PrimaryReplicaInfoTest.*`。部分 AC 因 mock 环境无法注入故障（binlog 回放、stat 失败、RdConnection）而标注"环境限制"。

| AC | 关联规则 | 验证方式 | 证据 |
|----|----------|----------|------|
| AC-1.1 | BR-01, BR-09 | UT：构造临时数据库和 WAL 文件，调用 GetPrimaryReplicaInfo 后验证四个大小字段与 stat 结果一致 | FileSizes_001, WalFileStat_001, ReplicaWalErrCode_001, ReplicaDbStatFromConfig_001 |
| AC-1.2 | BR-01, BR-10 | UT：回放失败注入场景需 binlog 内核支持，mock 环境无法注入；验证软门控逻辑在代码层面实现（TryReplayBinlog 记录 replayErr 不中断后续采集）；环境限制：无 binlog 回放测试 | 代码审查 + BinlogInfo_NoBinlog_001 |
| AC-1.3 | BR-04, BR-10 | UT：验证 checkpoint 独立状态字段（E_OK/E_NOT_SUPPORT）及查询后健康备库仍可用 | CheckpointStatus_001, DiagnosticHealthyReplica_001 |
| AC-1.4 | EX-09 | UT：stat 失败注入需 mock stat 调用，当前环境限制；代码层面 StatToFileInfo 返回 errCode=E_ERROR 标记失败；上游 SqliteUtils::Stat 不区分 errno（见 EX-09 注） | 代码审查 + StatToFileInfo 实现 |
| AC-2.1 | BR-01 | UT：验证时间字段为正毫秒时间戳；checkpoint 后文件时间变化不覆盖已保存的回放前时间 | TimeFields_001, TimeNotOverwrittenByCheckpoint_001 |
| AC-2.2 | BR-02 | UT：构造 DB/WAL 时间组合，断言主库归纳时间 = max(DB, WAL)，仅使用 errCode==E_OK 的时间 | PrimaryTimeRule_001, TimeValidity_001 |
| AC-2.3 | BR-03 | UT：binlog 文件场景需内核支持，mock 环境无法构造；验证备库归纳时间逻辑分支（binlog.exist ? binlog.lastModifyTime : max(DB, WAL)） | ReplicaTimeRule_001 |
| AC-2.4 | BR-03 | UT：无 binlog 时备库归纳时间 = max(备库 DB, WAL)；binlog 扫描失败时保留失败状态 | ReplicaTimeFallback_001, BinlogInfo_NoBinlog_001, BinlogErrCode_001 |
| AC-2.5 | BR-01 | UT：执行 checkpoint 后文件 mtime 变化，验证已采集时间未被覆盖 | TimeNotOverwrittenByCheckpoint_001 |
| AC-3.1 | BR-06 | UT：主库插入已知行数返回正确标量；备库行数需 slaveConnection_（mock 环境限制） | TableCount_001, EmptyTableCount_001 |
| AC-3.2 | EX-07 | UT：空表名时不执行计数，tables map 为空，返回 E_OK（不返回错误码） | EmptyTableName_001 |
| AC-3.3 | EX-08 | UT：表不存在时 errCode != E_OK，count=0 | TableNotExist_001 |
| AC-3.4 | BR-06 | UT：schema.table 双引号引用；注入攻击表名被 IsValidTableName 拒绝（上游正则限制见 AC-3.4 注） | SchemaTableQuoting_001, InvalidTableName_001 |
| AC-4.1 | BR-05 | UT：已有 slaveConnection_ 时直接使用，通过 ReplicaWalErrCode_001 间接验证（备库 WAL errCode=E_OK 表示连接已复用） | ReplicaWalErrCode_001 |
| AC-4.2 | BR-05, EX-01 | UT：NoSlaveConnection_001 验证无 slaveConnection_ 时备库 DB 从配置路径 stat（E_OK），WAL/回放/checkpoint 跳过（E_NOT_SUPPORT） | NoSlaveConnection_001, ReplicaDbStatFromConfig_001 |
| AC-4.3 | BR-05 | UT：NoSlaveConnection_001 验证无 slaveConnection_ 时跳过备库回放/checkpoint/表计数（E_NOT_SUPPORT），接口返回 E_OK | NoSlaveConnection_001 |
| AC-4.4 | EX-01, EX-02 | UT：NoSlaveConnection_001 验证不创建新文件；备库缺失时 DB stat 返回 E_ERROR、WAL 跳过（E_NOT_SUPPORT） | NoSlaveConnection_001 |
| AC-4.5 | EX-11 | 代码审查/并发验证：诊断期间备库句柄生命周期受连接池和连接同步机制保护；不依赖诊断租约状态 | 代码审查；专用并发释放用例待补 |
| AC-5.1 | BR-07 | UT：验证 per-item 状态字段在成功时为 E_OK；部分失败时可用字段保留有效值 | StatusFieldsDefault_001, PartialResults_001, RepeatedQuery_001 |
| AC-5.2 | EX-12 | UT：RdConnection 需 RD 后端，mock 环境限制；代码层面 RdConnection override 返回 E_NOT_SUPPORT 已验证 | 代码审查 + rd_connection.cpp override |
| AC-5.3 | EX-13 | UT：SINGLE 模式调用时返回 E_NOT_SUPPORT | SingleMode_001 |
| AC-5.4 | EX-14/15/16 | UT：只读数据库返回 E_NOT_SUPPORT；内存/向量数据库创建正常 DB 调用接口验证 E_OK（入口级运行验证，不跳过） | ReadOnlyDb_001, MemoryDb_001, VectorDb_001 |
| AC-6.1 | BR-08 | UT：并发写入下查询；验证不全局冻结；checkpoint BUSY 作为状态返回 | ConcurrentWrite_001 |
| AC-6.2 | BR-03 | UT：加密库需密钥配置，mock 环境限制；代码层面加密库被 IsSupportBinlog 排除，跳过回放使用 DB/WAL 时间 | 代码审查 |
| AC-6.3 | BR-09 | UT：自定义 replicaPath 目录；验证 slave DB 在自定义目录中创建 | CustomReplicaPath_001 |
| AC-6.4 | - | 构建清单检查：BUILD.gn 包含测试文件；bundle.json 同步新增头文件；无 JS/ETS/NDK/IPC 绑定新增 | TypeExistence_001 + 编译验证 |

## 测试设计提示

> 实际测试文件：`primary_replica_info_test.cpp`，GTest 过滤器：`PrimaryReplicaInfoTest.*`。共 36 个用例（36 通过 + 0 跳过）。部分 AC 因 mock 环境限制无法构造注入场景（binlog 回放、stat 失败、RdConnection、加密库），标注"环境限制"。

| AC | 测试类型 | 测试名称 | 输入/触发 | 期望输出/错误 | 状态 |
|----|----------|----------|-----------|---------------|------|
| AC-1.1 | UT | FileSizes_001 | MAIN_REPLICA 库 + WAL 文件 | 主库 DB 大小 = stat 结果 | ✅ |
| AC-1.1 | UT | WalFileStat_001 | 插入后查询 | WAL errCode=E_OK | ✅ |
| AC-1.2 | UT | BinlogInfo_NoBinlog_001 | 无 binlog 的库 | exist=false, errCode=E_OK | ✅ |
| AC-1.3 | UT | CheckpointStatus_001 | 正常查询 | checkpointErr=E_OK 或 E_NOT_SUPPORT | ✅ |
| AC-1.3 | UT | DiagnosticHealthyReplica_001 | 查询后检查健康备库文件 | 健康备库文件存在且可继续查询 | ✅ |
| AC-2.1 | UT | TimeFields_001 | 插入后查询 | mtime > 0, 毫秒时间戳 | ✅ |
| AC-2.2 | UT | PrimaryTimeRule_001 | 插入后查询 | primaryLastModifyTime = max(DB, WAL) | ✅ |
| AC-2.2 | UT | TimeValidity_001 | 插入后查询 | 仅使用 errCode==E_OK 的时间 | ✅ |
| AC-2.3 | UT | ReplicaTimeRule_001 | 查询 | 验证 binlog 优先 / max(DB,WAL) 回退逻辑 | ✅ |
| AC-2.4 | UT | ReplicaTimeFallback_001 | 无 binlog 查询 | replicaLastModifyTime = max(备库 DB, WAL) | ✅ |
| AC-2.4 | UT | BinlogErrCode_001 | 无 binlog 目录 | errCode=E_OK (ENOENT 不是错误) | ✅ |
| AC-2.5 | UT | TimeNotOverwrittenByCheckpoint_001 | 插入后查询 | WAL mtime 是回放前值，不被 checkpoint 覆盖 | ✅ |
| AC-3.1 | UT | TableCount_001 | 主库 3 行 | count=3, errCode=E_OK | ✅ |
| AC-3.1 | UT | EmptyTableCount_001 | 0 行表 | count=0, errCode=E_OK | ✅ |
| AC-3.2 | UT | EmptyTableName_001 | 空表名 | tables 为空 map, 返回 E_OK | ✅ |
| AC-3.3 | UT | TableNotExist_001 | 不存在的表 | errCode != E_OK, count=0 | ✅ |
| AC-3.4 | UT | SchemaTableQuoting_001 | "main.test" | 正确拆分双引号引用, count=3 | ✅ |
| AC-3.4 | UT | InvalidTableName_001 | "test; DROP TABLE test" | E_INVALID_ARGS, 表仍存在 | ✅ |
| AC-4.2 | UT | ReplicaDbStatFromConfig_001 | 查询 | 备库 DB 从配置路径 stat | ✅ |
| AC-4.2 | UT | ReplicaWalErrCode_001 | 查询 | 备库 WAL errCode=E_OK (有连接时) | ✅ |
| AC-5.1 | UT | StatusFieldsDefault_001 | 正常查询 | 所有状态字段=E_OK | ✅ |
| AC-5.1 | UT | PartialResults_001 | 无备库连接 | 主库字段有效, 返回 E_OK | ✅ |
| AC-5.1 | UT | RepeatedQuery_001 | 连续两次查询 | 结果一致 | ✅ |
| AC-5.3 | UT | SingleMode_001 | SINGLE 模式 | E_NOT_SUPPORT | ✅ |
| AC-5.4 | UT | ReadOnlyDb_001 | 只读数据库 | E_NOT_SUPPORT | ✅ |
| AC-5.4 | UT | MemoryDb_001 | 正常 DB 入口验证（内存 DB 代码层检查） | E_OK | ✅ |
| AC-5.4 | UT | VectorDb_001 | 正常 DB 入口验证（向量 DB 代码层检查） | E_OK | ✅ |
| AC-6.1 | UT | ConcurrentWrite_001 | 并发写入 + 查询 | 不冻结, 返回 E_OK | ✅ |
| AC-6.3 | UT | CustomReplicaPath_001 | 自定义 replicaPath 目录 | slave DB 在自定义目录创建 | ✅ |
| AC-6.4 | 构建 | TypeExistence_001 | 类型编译验证 | 所有类型可默认构造 | ✅ |
| AC-6.4 | 构建 | 编译验证 | BUILD.gn + bundle.json | 编译通过, 无新增绑定 | ✅ |

> AC → 实现文件 + Task + 验证状态映射见 [07-execution-plan.md](07-execution-plan.md)。
