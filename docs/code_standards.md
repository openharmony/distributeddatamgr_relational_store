# 代码规范

本文档是 relational_store 的**强制编码规范**，由 [`AGENTS.md`](../AGENTS.md) 的"知识路由"在涉及代码开发/修改任务时按需加载。

包含：
- R1～R10 强制规则（正反示例 + 计数方法 + 豁免流程）
- 反馈闭环（规则演进机制）
- 演进记录

> **本文件是规则的唯一权威来源**。AGENTS.md 不再内联规则表，避免双处维护产生分歧。

---

## R1 函数行数 ≤ 50

### 规则

单个函数（含成员函数 / 静态函数 / lambda）有效代码行数 **MUST ≤ 50** 行。超过 **MUST** 拆分为多个私有方法或匿名命名空间内的辅助函数。

### 计数方法

- 以编辑器 / `git diff` 显示的"非空非注释行"为准
- 不计：空行、纯注释行、函数签名行、纯括号行
- 计入：所有可执行语句、`if/for/while` 条件、`return` 语句

### 反例（违反 R1）

```cpp
// 反例：函数 60+ 行，职责混杂
int RdbStoreImpl::DoBackup(const std::string &path, const Key &key, bool verify, ...) {
    // ... 60 行混合：参数校验、连接获取、SQL 构造、执行、结果处理、日志、GID 设置 ...
}
```

### 正例（遵守 R1）

```cpp
// 正例：编排函数只做路由，每个分支提取为独立方法
int RdbStoreImpl::InnerBackup(const std::string &databasePath,
    const std::vector<uint8_t> &destEncryptKey, bool verifyDb)
{
    if (isReadOnly_) {
        return E_NOT_SUPPORT;
    }
    if (config_.GetDBType() == DB_VECTOR) {
        return BackupVectorDb(databasePath, destEncryptKey);
    }
    if (config_.GetHaMode() != HAMode::SINGLE && SqliteUtils::IsSlaveDbName(databasePath)) {
        return BackupSlaveDb(databasePath, verifyDb);
    }
    return BackupMainDb(databasePath, destEncryptKey);
}
```

### 豁免条件

仅当同时满足以下 3 项才允许豁免，**MUST** 在 commit 说明写明：

1. 拆分会破坏接口兼容性（如虚函数签名、NDK 导出符号）
2. 拆分后函数语义支离破碎，可读性反而下降
3. 行数未超出太多（建议 ≤ 60 行）

---

## R2 入参数量 ≤ 5

### 规则

函数参数数量 **MUST ≤ 5**。超过 **MUST** 用结构体封装入参或拆分函数。**NEVER** 借此规则修改存量接口签名。

### 计数方法

- 函数声明 / 定义中出现的具名形参个数
- `this` 隐式参数不计（成员函数同样不计）
- 模板参数不计
- `const Type &` 算 1 个

### 反例（违反 R2）

```cpp
// 反例：7 个参数
int InsertRow(const std::string &table, int id, const std::string &name,
    int age, double salary, const std::vector<uint8_t> &blob, bool replace);
```

### 正例（遵守 R2）

```cpp
// 正例：用结构体封装
struct RowParam {
    std::string table;
    int32_t id;
    std::string name;
    int32_t age;
    double salary;
    std::vector<uint8_t> blob;
    bool replace;
};
int InsertRow(const RowParam &param);  // 1 个参数
```

### 豁免条件

- 存量接口签名 **NEVER** 改（兼容性优先）
- 新增函数若参数确实不可合并（如 SQLite C API 回调），允许豁免，**MUST** 在 commit 说明

---

## R3 不可变性（接口层）

接口层 API（NDK / JS / ETS）**NEVER** 破坏向后兼容。完整定义、判定、示例见
`AGENTS.md > 专家经验 > 核心原则 #5`（"接口层 API NEVER 破坏向后兼容"）。

Inner APIs 不建议修改；如需修改 **MUST** 在 commit 中说明影响面。错误码相关的兼容
边界详见 `docs/error_code_layers.md`（对应本规范 R5）。

---

## R4 文件规模 ≤ 2000 行

单文件建议 ≤ 2000 行。超过 **MUST** 拆分（按职责、按功能模块）。

---

## R5 错误处理

- **MUST** 使用 `rdb_errno.h` 标准错误码
- **NEVER** 让接口层存量接口返回新错误码或变更同场景错误码
- 错误码分层详见 `docs/error_code_layers.md`

---

## R6 日志

- 错误日志 **MUST** 提供充足上下文：函数名 + 文件路径 + 操作类型 + 错误码
- 高频分支（如每次 SQL 执行、每次连接获取）**NEVER** info 级别日志
- 使用 `LOG_ERROR` / `LOG_WARN` / `LOG_INFO` / `LOG_DEBUG` 宏，按严重级别选择

---

## R7 文件命名

| 类型         | 命名                                          |
| ------------ | --------------------------------------------- |
| 测试文件     | `*_test.cpp`                                  |
| Mock 文件    | `mock_*.cpp` / `mock_*.h`                     |
| 构建配置     | `BUILD.gn`                                    |
| 头文件       | 与实现同名 `.h`，放 `include/` 目录           |

---

## R8 导出约定

- `inner_api` 仅导出 `include/` 下头文件
- 新增导出 **MUST** 同步更新 `bundle.json`
- 实现细节（`src/` 内的头文件）**NEVER** 被外部模块直接 include

---

## R9 工具类复用

**MUST** 优先使用 `kv_store:datamgr_common` 提供的工具类：

- `ConcurrentMap` — 线程安全 map
- `ITypesUtil` — Parcel 序列化
- `Traits` — 类型萃取
- `JSProxy` — NAPI 调用代理
- `BlockData` — 阻塞等待数据
- `LRUBucket` — LRU 缓存

**NEVER** 自行实现已有同等能力。

---

## R10 定义复用

新增映射表、函数、接口前 **MUST** 先检查：

1. 同文件内是否已有同类定义
2. 同模块内是否已有同类定义
3. `kv_store:datamgr_common` 是否已提供

优先扩展而非新增，合并而非并行。

---

## 反馈闭环（规则演进）

本规范的规则集合不是固定的。两种触发场景 **MUST** 走"询问用户"流程：

### 触发 1：Agent 编码过程中发现可推广的模式

编码过程中若对正在修改的代码产生新的改进建议（例如发现可推广的模式、反模式、可固化的写法），**MUST 先询问用户**是否将该建议加入本规范，**NEVER** 擅自扩充。

### 触发 2：用户在同一会话中提及同一规范 2 次以上

当**用户**在同一个会话中针对同一项编码要求 / 代码规范提及 2 次或以上时（例如先说"函数别太长"，过几轮又说"这个函数太长了拆一下"），Agent **MUST** 主动询问用户是否将该项加入本规范文档，**NEVER** 让用户重复要求第 3 次。

判定"同一规范"的依据：
- 涉及同一维度（如行数、参数数、命名、错误处理等）
- 即使措辞不同但语义指向同一规则

询问时的模板：

```
检测到您在本次会话中多次提到「<规范描述>」。是否将这条加入
docs/code_standards.md 作为正式规则（R11+）？
```

### 加入流程

1. 询问用户 → 用户同意
2. 在本文件追加新规则（编号 R11、R12……）
3. 在本文件 `## 演进记录` 追加一条变更记录

> AGENTS.md 不再内联规则表，因此**不需要**同步修改 AGENTS.md；它的知识路由表已
> 指向本文件，新规则自动对 Agent 生效。

---

## 演进记录

| 日期       | 变更                                                                                           |
| ---------- | ---------------------------------------------------------------------------------------------- |
| 2026-08-08 | 去重：从 AGENTS.md 移除内联 R1～R10 表与反馈闭环章节，本文件成为规则唯一权威来源；R3 改为引用 `AGENTS.md > 核心原则 #5`；修正 R2 计数内重复条目 |
| 2026-08-08 | 初始版本，建立 R1～R10；新增"用户同一会话提及 2 次以上"反馈触发条件                             |
