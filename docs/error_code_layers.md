# 错误码分层体系

本文档说明 relational_store 组件的错误码分层体系和转换机制。

## 错误码分层架构

relational_store 组件采用三层错误码架构：

```
┌─────────────────────────────────────────────────────────────┐
│         SQLite / RD 内核错误码                              │
│  - 文件: sqlite3.h (SQLITE_*)                             │
│  - 最底层错误，数据库引擎返回                                │
└────────────────────────┬────────────────────────────────────┘
                         │ 转换
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               Native 层错误码                                │
│  - 文件: rdb_errno.h                                        │
│  - 基于 E_BASE (14800000)                                   │
│  - 可以修改，但需要协调                                      │
└────────────────────────┬────────────────────────────────────┘
                         │ 直接传递 (通过IPC)
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              接口层错误码 (NDK/JS)                           │
│  - NDK: relational_store_error_code.h (RDB_E_*)            │
│  - JS: napi_rdb_error.cpp (错误码映射表)                    │
│  - 绝对不能破坏向后兼容                                      │
└─────────────────────────────────────────────────────────────┘
```

### 关键要点

1. **没有独立的 IPC 错误码层**: IPC 只是传输机制，错误码在跨进程通信中保持不变
2. **错误码值保持一致**: Native 层和 NDK 层使用相同的错误码值（都是基于 E_BASE = 14800000）
3. **JS 层映射**: JS 层通过映射表将 Native 错误码转换为 JS 错误码和错误消息

## 各层错误码说明

### 1. SQLite 和 RD 内核错误码

**文件**: `third_party/sqlite/sqlite3.h`

**常见错误码**:
- `SQLITE_OK` (0): 成功
- `SQLITE_BUSY` (5): 数据库文件锁定
- `SQLITE_LOCKED` (6): 表锁定
- `SQLITE_CORRUPT` (11): 数据库损坏
- `SQLITE_CONSTRAINT` (19): 约束冲突

### 2. Native 层错误码

**文件**: `interfaces/inner_api/rdb/include/rdb_errno.h`

**基础定义**:
```c
constexpr int E_BASE = 14800000;           // 基础错误码
constexpr int E_OK = 0;                     // 成功
constexpr int E_ERROR = E_BASE;             // 通用错误
constexpr int E_INVALID_ARGS = (E_BASE + 1); // 14800001
```

**SQLite 映射错误码**:
```c
constexpr int E_SQLITE_ERROR = (E_BASE + 0x37);      // 14800055
constexpr int E_SQLITE_CORRUPT = (E_BASE + 0x38);    // 14800052
constexpr int E_SQLITE_BUSY = (E_BASE + 0x3c);       // 14800054
constexpr int E_SQLITE_LOCKED = (E_BASE + 0x3d);     // 14800055
constexpr int E_SQLITE_IOERR = (E_BASE + 0x40);      // 14800058
```

### 3. 接口层错误码 (NDK/JS)

**文件**:
- NDK: `interfaces/ndk/include/relational_store_error_code.h`
- JS: `frameworks/js/napi/relationalstore/src/napi_rdb_error.cpp`

**特点**:
- **NDK**: 与 Native 层使用相同的错误码值（基于 E_BASE）
- **JS**: 通过映射表转换为 JS 错误码和错误消息
- **绝对不能破坏向后兼容**

## 错误码转换流程

### 转换链路

```
SQLite/RD 内核错误 → Native 层错误码 → [通过IPC直接传递] → 接口层错误码
```

### 转换示例

**场景 1: 数据库损坏**
```
SQLite: SQLITE_CORRUPT (11)
  ↓
Native: E_SQLITE_CORRUPT (14800052)
  ↓
NDK: RDB_E_SQLITE_CORRUPT (14800052)
  ↓
JS: 14800052 + "Failed to open the database because it is corrupted"
```

**场景 2: 数据库忙**
```
SQLite: SQLITE_BUSY (5)
  ↓
Native: E_SQLITE_BUSY (14800054)
  ↓
NDK: RDB_E_SQLITE_BUSY (14800054)
  ↓
JS: 14800054 + "SQLite: The database file is locked"
```

## 新增错误码的指导原则

### 评估流程

1. **确定错误码所属层级**: SQLite/RD 内核、Native 层、接口层
2. **检查是否需要新增接口层错误码**:
   - **新增功能暴露给应用开发者**: 需要新增 NDK/JS 错误码（谨慎评估，破坏兼容性）
   - **内部优化**: 只在 Native 层新增，映射到现有接口层错误码
3. **评估对存量接口的影响**: **绝对禁止**让存量接口返回新的错误码

### 允许的场景

✅ **内部新增错误码，映射到现有接口错误码**:
```cpp
// Native 层新增
constexpr int E_NEW_FEATURE_ERROR = (E_BASE + 0x100); // 14800100

// 映射到现有接口错误码，保持兼容性
// NDK/JS 层使用 RDB_E_NOT_SUPPORT 或其他现有错误码
```

### 禁止的场景

❌ **让存量接口返回新的错误码**:
```cpp
// 破坏向后兼容，绝对禁止
int32_t RdbStore_Insert(...) {
    if (new_condition) {
        return RDB_ERR_NEW_ERROR; // ❌ 破坏兼容性！
    }
}
```

❌ **修改现有错误码的含义**:
```cpp
// 改变错误码语义，破坏依赖该错误码的应用
// RDB_ERR_BUSY 原来表示数据库忙，改为表示连接池满
```

## 新增错误码模板

### Native 层新增错误码

```cpp
// 1. interfaces/inner_api/rdb/include/rdb_errno.h
constexpr int E_MY_NEW_ERROR = (E_BASE + 0x100);

// 2. 实现文件使用
int32_t MyFunction() {
    if (error_condition) {
        return E_MY_NEW_ERROR;
    }
    return E_OK;
}

// 3. 如果需要暴露给应用开发者，同步更新 NDK/JS 层
// NDK: interfaces/ndk/include/relational_store_error_code.h
// JS: frameworks/js/napi/relationalstore/src/napi_rdb_error.cpp
```

## 测试要点

### 单元测试
- 验证 SQLite 错误码到 Native 层错误码的转换
- 验证 Native 层错误码到 NDK/JS 层的传递

### 兼容性测试
- 确保存量接口在相同场景下返回相同的错误码
- 验证新增错误码不会影响存量接口的错误返回

## 调试技巧

### 常见问题
1. **错误码不一致**: 某层返回了未定义的错误码
2. **转换错误**: SQLite 错误码到 Native 层错误码的映射错误
3. **兼容性破坏**: 存量接口返回了新错误码
4. **JS 层映射缺失**: Native 层新增错误码后 JS 层没有对应的映射

### 调试方法
- 在错误码转换的关键节点添加日志
- 记录 SQLite 错误码、Native 层错误码、接口层错误码的传递过程
- 使用 HiLog 记录错误的层级、错误码值、函数名称

## 总结

错误码分层是 relational_store 组件错误处理的核心机制。

**关键原则**:
1. **三层架构**: SQLite/RD 内核 → Native 层 → 接口层（NDK/JS）
2. **错误码一致性**: Native 层和 NDK 层使用相同的错误码值（基于 E_BASE）
3. **IPC 传输**: 错误码通过 IPC 直接传递，值保持不变
4. **向后兼容**: 接口层存量接口不能返回新的错误码
5. **JS 映射**: Native 层新增错误码后，JS 层必须同步添加映射表

**新增错误码时**:
- Native 层可以自由新增错误码（基于 E_BASE + 偏移）
- 如果需要暴露给应用开发者，必须同步更新 NDK/JS 层
- 绝对禁止让存量接口返回新的错误码，以保持向后兼容性
