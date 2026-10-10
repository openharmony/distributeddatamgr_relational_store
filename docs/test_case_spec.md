# 测试用例规范

本文件是 relational_store 仓库测试用例的编写规范。**新增或修改任何测试用例前 MUST 完整阅读本文件。**

---

## 1. 用例目录

### 1.1 目录划分原则

测试目录按**测试层**和**功能域**两级划分：

```
relational_store/test/
├── interface/                    # 接口层测试：公共 API 端到端验证
├── native/
│   ├── rdb/
│   │   ├── unittest/            # Native 核心单元测试
│   │   ├── mock/                # 测试 Mock 文件
│   │   ├── fuzztest/            # Fuzz 测试
│   │   └── distributedtest/     # 分布式测试
│   ├── clouddata/unittest/       # 云数据测试
│   ├── dataability/unittest/     # DataAbility 谓词测试
│   ├── appdatafwk/unittest/      # AppData 框架测试
│   ├── rdb_service_adapter/unittest/  # 服务适配器测试
│   ├── rdb_data_share_adapter/unittest/  # DataShare 适配器
│   └── rdb_data_ability_adapter/unittest/  # DataAbility 适配器
├── ndk/
│   ├── unittest/                # NDK C API 测试
│   └── fuzztest/                # NDK Fuzz 测试
└── interface/                   # (与根 interface/ 同义，上游结构)
```

### 1.2 测试层选择规则

| 被测代码位置 | 测试层 | 用例目录 | 说明 |
|---|---|---|---|
| `interfaces/ndk/include/` | NDK | `ndk/unittest/` | 验证 C API 公开接口 |
| `interfaces/inner_api/` | Interface | `interface/` | 验证模块间接口契约 |
| `frameworks/native/rdb/src/` | Native | `native/rdb/unittest/` | 验证核心实现逻辑 |
| `frameworks/native/rdb_crypt/` | Native | `native/rdb/unittest/` | 加密相关 |
| `frameworks/native/cloud_data/` | CloudData | `native/clouddata/unittest/` | 云同步 |
| `frameworks/native/rdb_service_adapter/` | ServiceAdapter | `native/rdb_service_adapter/unittest/` | IPC 代理 |
| `frameworks/native/rdb_data_share_adapter/` | DataShareAdapter | `native/rdb_data_share_adapter/unittest/` | DataShare |
| `frameworks/native/rdb_data_ability_adapter/` | DataAbilityAdapter | `native/rdb_data_ability_adapter/unittest/` | DataAbility |
| `frameworks/native/appdatafwk/` | AppDataFwk | `native/appdatafwk/unittest/` | AppData 框架 |

> **原则**：用例与被测代码就近放置。接口层改动写 Interface 测试，实现层改动写 Native 测试。禁止在 Native 测试中验证接口契约（职责越界）。

### 1.3 Mock 文件目录

| Mock 类型 | 存放位置 | 命名规则 |
|---|---|---|
| 模块级 Mock | `native/<module>/mock/` | `mock_<name>.cpp/h` |
| 测试内 Mock | `native/<module>/unittest/<subdir>/` | `mock_<name>.cpp/h` |
| Mock 仓库级 | `mock/src/`、`mock/include/` | 见 AGENTS.md 路径路由 |

> Mock 文件与测试源文件分开存放，不可混放。Mock 头文件在 `mock/include/` 子目录，Mock 源文件在 `mock/src/` 子目录。

### 1.4 公共测试文件

每个测试层维护一组公共工具文件，跨用例复用：

| 测试层 | 公共文件 | 内容 |
|---|---|---|
| Native | `native/rdb/unittest/common.cpp/h` | 路径管理、数据库清理、测试常量 |
| Interface | `interface/rdb_test_common.cpp/h` | 回调基类、测试数据生成 |
| NDK | `ndk/unittest/common.h` | NDK 初始化辅助 |

> 新增公共工具函数优先加入对应层的公共文件，禁止在单个用例文件中定义跨文件复用的工具函数。

---

## 2. 用例文件命名

### 2.1 测试源文件

```
<功能域>_<功能点>_test.cpp
```

| 组成 | 规则 | 示例 |
|---|---|---|
| 功能域 | 被测模块的小写名称 | `rdb_store`、`rdb_predicates`、`rdb_encrypt` |
| 功能点 | 被测功能描述，下划线分隔 | `impl`、`backup_restore`、`decrypt` |
| 后缀 | 固定 `_test` | — |

示例：

```
rdb_store_impl_test.cpp          # RDB Store 实现测试
rdb_predicates_test.cpp          # 谓词测试
rdb_encrypt_decrypt_test.cpp     # 加密解密测试
rdb_store_backup_restore_test.cpp  # 备份恢复测试
rdb_store_rekey_test.cpp         # Rekey 测试
transaction_test.cpp             # 事务测试（功能域省略时为通用模块）
```

### 2.2 Mock/辅助文件

```
mock_<name>.cpp / mock_<name>.h     # Mock 文件
security_manager_test_helper.cpp   # 测试辅助（非 Mock）
```

### 2.3 Fuzz 文件

```
<fuzzer_target>_fuzzer.cpp / <fuzzer_target>_fuzzer.h
```

Fuzz 文件放在 `fuzztest/<fuzzer_target>/` 子目录下，每个 fuzzer 独占一个目录。

---

## 3. 用例编写规范

### 3.1 用例宏与命名

使用 OpenHarmony 测试框架宏：

```cpp
HWTEST_F(FixtureName, Module_Function_Description_001, TestSize.Level1)
```

| 组成 | 规则 | 示例 |
|---|---|---|
| Fixture 名 | `PascalCase`，以 `Test` 结尾 | `RdbStoreImplTest`、`RdbPredicatesInterfaceTest` |
| 用例名 | `Module_Function_Description_序号` | `Rdb_BatchInsertTest_001` |
| Module | 模块缩写 | `Rdb`、`Rd`、`Sqlite` |
| Function | 功能名，`PascalCase` | `BatchInsert`、`Query`、`Encrypt` |
| Description | 场景描述（可选），`PascalCase` | `WithEmptyTable`、`AfterRekey` |
| 序号 | 三位数字，从 `001` 开始 | `001`、`002`、`003` |
| Level | 执行优先级 | `Level0`（核心）~ `Level4`（低频） |

**TestSize.Level 选择指南：**

| Level | 含义 | 适用场景 |
|---|---|---|
| `Level0` | 最高优先级 | 核心功能路径（CRUD 基本流程、事务提交/回滚） |
| `Level1` | 高优先级 | 重要功能路径（加密、备份恢复、连接池） |
| `Level2` | 常规 | 正常功能验证（谓词组合、结果集遍历） |
| `Level3` | 边界 | 边界值和异常输入（空表、超大数据、非法参数） |
| `Level4` | 低频 | 罕见场景、压力场景、长时间运行 |

### 3.2 用例描述要求

每个用例 MUST 在用例名中体现**被测功能 + 场景 + 预期结果**。禁止使用无意义的序号命名。

**反面示例（禁止）：**

```cpp
// 禁止：用例名无法体现测试内容
HWTEST_F(RdbStoreImplTest, Test001, TestSize.Level1)
HWTEST_F(RdbStoreImplTest, Insert, TestSize.Level1)
```

**正面示例（正确）：**

```cpp
// 正确：功能 + 场景 + 预期
HWTEST_F(RdbStoreImplTest, Rdb_BatchInsertTest_001, TestSize.Level1)
// 含义：RDB 批量插入测试，场景 001（基本插入）

HWTEST_F(RdbStoreImplTest, Rdb_QueryTest_WithEmptyTable_001, TestSize.Level3)
// 含义：RDB 查询测试，空表场景
```

### 3.3 注释规范

每个用例 MUST 包含以下注释信息：

```cpp
/**
 * @brief 测试 RdbStore 批量插入功能，验证插入 1000 行数据后行数正确
 * @param TestCaseName Rdb_BatchInsertTest_001
 * @since 1.0
 */
HWTEST_F(RdbStoreImplTest, Rdb_BatchInsertTest_001, TestSize.Level1)
{
    // 1. 准备：创建数据库和表
    auto store = GetRdbStore();
    ASSERT_NE(store, nullptr);
    std::string createTableSql = "CREATE TABLE test_table (id INTEGER PRIMARY KEY, data TEXT)";
    ASSERT_EQ(store->ExecuteSql(createTableSql), E_OK);

    // 2. 执行：批量插入 1000 行
    ValuesBucket values;
    for (int i = 0; i < 1000; i++) {
        values.PutInt("id", i);
        values.PutString("data", std::to_string(i));
    }
    int64_t rowId = 0;
    ASSERT_EQ(store->Put("test_table", values, rowId), E_OK);

    // 3. 验证：查询行数 == 1
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT COUNT(*) FROM test_table");
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    EXPECT_EQ(resultSet->GetInt(0), 1);
}
```

**注释要求：**

| 注释类型 | 要求 | 位置 |
|---|---|---|
| `@brief` | 用例摘要：测什么功能、验证什么结果 | 用例宏上方 |
| `@since` | 引入版本（可选） | 用例宏上方 |
| 步骤注释 | `// 1. 准备：` / `// 2. 执行：` / `// 3. 验证：` | 用例体内 |
| 关键断言注释 | 解释非显而易见的断言意图 | 断言上方 |

### 3.4 断言规范

| 宏 | 用途 | 失败行为 |
|---|---|---|
| `EXPECT_EQ` | 非致命断言，继续执行 | 记录失败，继续 |
| `ASSERT_EQ` | 致命断言，立即终止 | 记录失败，跳过后续 |
| `EXPECT_NE` / `ASSERT_NE` | 不等断言 | — |
| `EXPECT_TRUE` / `ASSERT_TRUE` | 布尔断言 | — |
| `EXPECT_FALSE` / `ASSERT_FALSE` | 布尔断言 | — |
| `EXPECT_STREQ` | C 字符串断言 | — |

**原则：**

- 前置条件（资源获取、环境准备）用 `ASSERT_*`：失败后继续无意义
- 结果验证用 `EXPECT_*`：允许收集多个失败点
- 禁止裸 `assert()` 或 `exit()`：使用 GTest 断言宏

### 3.5 用例隔离

#### 3.5.1 禁止用例间依赖

每个用例 MUST 独立运行，不依赖其他用例的执行顺序或副作用。

**禁止行为：**

```cpp
// 禁止：用例 B 依赖用例 A 创建的数据
HWTEST_F(RdbStoreImplTest, Rdb_InsertTest_001, TestSize.Level0)
{
    // 用例 A：插入数据
    store->Put("test_table", values);
}

HWTEST_F(RdbStoreImplTest, Rdb_QueryTest_001, TestSize.Level0)
{
    // 禁止：依赖用例 A 插入的数据
    auto resultSet = store->QuerySql("SELECT * FROM test_table");
    EXPECT_EQ(resultSet->GetRowCount(), 1);  // 依赖用例 A
}
```

**正确做法：**

```cpp
HWTEST_F(RdbStoreImplTest, Rdb_QueryTest_001, TestSize.Level0)
{
    // 自行准备数据
    store->Put("test_table", values);
    auto resultSet = store->QuerySql("SELECT * FROM test_table");
    EXPECT_EQ(resultSet->GetRowCount(), 1);
}
```

#### 3.5.2 TearDown 清理

每个 Fixture 的 `TearDown()` MUST 清理本 Fixture 所有用例产生的副作用：

- 删除测试数据库文件
- 清理临时文件和目录
- 释放资源（连接、文件句柄）
- 重置全局状态

```cpp
class RdbStoreImplTest : public testing::Test {
public:
    void SetUp() override
    {
        // 创建测试目录（如不存在）
        TestUtils::CreateTestDirectory();
        store_ = RdbHelper::GetRdbStore(...);
    }

    void TearDown() override
    {
        // 关闭数据库连接
        store_ = nullptr;
        // 删除测试数据库文件
        TestUtils::CleanTestFiles("test.db");
        // 清理临时目录
        TestUtils::CleanTempFiles();
    }
};
```

#### 3.5.3 数据库文件隔离

每个用例 MUST 使用唯一的数据库文件名，禁止共用：

```cpp
// 禁止：多个用例共用同一数据库文件
HWTEST_F(RdbStoreImplTest, Rdb_InsertTest_001, ...)
{
    store_ = GetStore("shared.db");  // 共用文件
}

// 正确：每个用例使用唯一文件
HWTEST_F(RdbStoreImplTest, Rdb_InsertTest_001, ...)
{
    store_ = GetStore("insert_001.db");  // 用例名对应文件名
}
```

### 3.6 禁止使用 sleep

**禁止使用 `sleep()`、`std::this_thread::sleep_for()`、`usleep()` 等固定延迟。**

固定延迟会导致：测试变慢、CI 不稳定（flaky）、无法真正验证同步语义。

**替代方案：**

| 场景 | 禁止 | 替代 |
|---|---|---|
| 等待异步操作完成 | `sleep(1)` | 使用回调/Future/条件变量等同步原语 |
| 等待文件写入完成 | `sleep(2)` | 使用 `fflush` / `fsync` 后检查返回值 |
| 等待线程启动 | `sleep(1)` | 使用 `std::condition_variable` 等待线程就绪信号 |
| 等待数据库锁释放 | `sleep(1)` | 使用 `busy_retry` 循环 + 超时上限 |
| 等待 SA 服务启动 | `sleep(5)` | 使用 `CheckSystemAbility` 轮询 + 超时 |

**超时等待示例（正确做法）：**

```cpp
// 正确：带超时的轮询等待
auto result = WaitForCondition(
    [&]() { return store_->IsReady(); },
    std::chrono::seconds(5),   // 超时上限
    std::chrono::milliseconds(50)  // 轮询间隔
);
EXPECT_TRUE(result);
```

> **例外**：性能测试中测量延迟的场景可使用定时器，但 MUST 在注释中说明原因。

### 3.7 禁止临时文件残留

#### 3.7.1 临时文件管理

| 规则 | 说明 |
|---|---|
| 所有临时文件 MUST 在 TearDown 中删除 | 包括 `.db`、`.db-journal`、`.db-wal`、`.db-shm` |
| 临时文件统一存放在测试数据目录 | `${RDB_MOCK_TEST_DIR}/`（mock 环境）或 `/data/test/`（设备环境） |
| 禁止在系统临时目录创建文件 | 禁止 `/tmp/`、`C:\Temp\` 等 |
| 禁止硬编码绝对路径 | 使用 `common.h` 中的路径常量 |

#### 3.7.2 SQLite 附属文件清理

SQLite 数据库会产生附属文件（`.db-journal`、`.db-wal`、`.db-shm`）。清理时 MUST 使用 `RdbHelper::DeleteRdbStore()` 接口，该接口会自动清理所有附属文件：

```cpp
void TearDown() override
{
    // 正确：使用 deleteRDB 接口清理，自动删除 .db-journal/.db-wal/.db-shm
    int err = RdbHelper::DeleteRdbStore(dir + "/" + dbName);
    EXPECT_EQ(err, E_OK);
}
```

> **禁止手动逐个删除数据库文件。** `DeleteRdbStore` 是官方清理接口，保证所有附属文件被正确清理。仅在接口不可用或需清理非 RDB 管理的临时文件时，才手动删除：

```cpp
// 仅在 deleteRDB 不可用时作为降级方案
void CleanDatabaseFiles(const std::string& dbName)
{
    std::string dir = TestUtils::GetTestDir();
    TestUtils::RemoveFile(dir + "/" + dbName);
    TestUtils::RemoveFile(dir + "/" + dbName + "-journal");
    TestUtils::RemoveFile(dir + "/" + dbName + "-wal");
    TestUtils::RemoveFile(dir + "/" + dbName + "-shm");
}
```

### 3.8 用例结构（AAA 模式）

每个用例 MUST 遵循 **Arrange-Act-Assert** 三段式结构：

```cpp
HWTEST_F(Fixture, TestCase, TestSize.Level1)
{
    // Arrange: 准备测试数据和前置条件
    auto store = GetRdbStore();
    ASSERT_NE(store, nullptr);
    store->ExecuteSql("CREATE TABLE t (id INTEGER, name TEXT)");

    // Act: 执行被测操作
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", "test");
    int64_t rowId = 0;
    int err = store->Put("t", values, rowId);

    // Assert: 验证结果
    EXPECT_EQ(err, E_OK);
    EXPECT_GT(rowId, 0);
}
```

### 3.9 FIRST 原则

用例 MUST 遵循 FIRST 原则：

| 原则 | 含义 | 要求 |
|---|---|---|
| **F**ast | 快速执行 | 单个用例 < 5 秒；禁止 sleep；避免大文件 I/O |
| **I**solated | 相互独立 | 用例间无依赖；每用例独立数据库文件；TearDown 清理 |
| **R**epeatable | 可重复 | 多次运行结果一致；不依赖时间/随机/网络 |
| **S**elf-validating | 自验证 | 通过断言自动判定 pass/fail；禁止依赖人工检查 |
| **T**imely | 及时 | 与被测代码同步提交；先写测试再改代码（TDD 鼓励） |

### 3.10 参数化测试

当需要用多组输入验证同一逻辑时，使用 `HWTEST_P`：

```cpp
class RdbRekeyExTest : public TestWithParam<RekeyExTestParam> {
    // ...
};

INSTANTIATE_TEST_SUITE_P(RekeyScenarios, RdbRekeyExTest,
    Values(
        RekeyExTestParam{ "normal", E_OK },
        RekeyExTestParam{ "empty_password", E_OK },
        RekeyExTestParam{ "wrong_old_password", E_ERROR }
    )
);

HWTEST_P(RdbRekeyExTest, RekeyEx_Scenario_001, TestSize.Level1)
{
    auto param = GetParam();
    // 使用 param.input 和 param.expected 验证
}
```

**参数化原则：**
- 每组参数代表一个独立场景
- 参数命名清晰，体现场景含义
- 避免过多参数导致用例爆炸（单组参数化建议 ≤ 20 组）

### 3.11 测试代码复用

| 场景 | 做法 |
|---|---|
| 多个用例需要相同的前置数据库 | 在 Fixture 的 `SetUp()` 中创建 |
| 多个 Fixture 共享创建逻辑 | 提取到公共工具函数（`common.cpp/h`） |
| 多个用例需要相同的数据集 | 在公共文件中定义测试数据生成函数 |
| 重复的断言逻辑 | 提取为辅助函数（如 `ExpectRowEquals(resultSet, expected)`） |

> 禁止 Copy-Paste 用例代码。如果两个用例超过 70% 代码相同，提取公共逻辑。

### 3.12 错误码验证

涉及接口返回值的用例 MUST 验证错误码：

```cpp
// 正确：验证返回码
int err = store->Put("test_table", values, rowId);
EXPECT_EQ(err, E_OK);

// 禁止：忽略返回码
store->Put("test_table", values, rowId);
// 未验证 err
```

错误码定义见 `relational_store/docs/error_code_layers.md`。

### 3.13 禁止无断言用例

每个用例 MUST 至少包含一个 `EXPECT_*` 或 `ASSERT_*` 断言。无断言的用例无法验证任何行为，属于无效用例，禁止合入。

**禁止行为：**

```cpp
// 禁止：无断言——调用了接口但未验证任何结果
HWTEST_F(RdbStoreImplTest, Rdb_InsertTest_001, TestSize.Level0)
{
    auto store = GetRdbStore();
    ValuesBucket values;
    values.PutInt("id", 1);
    store->Put("test_table", values, rowId);
    // 无任何断言，即使 Put 返回错误也无法发现
}
```

**正确做法：**

```cpp
HWTEST_F(RdbStoreImplTest, Rdb_InsertTest_001, TestSize.Level0)
{
    auto store = GetRdbStore();
    ASSERT_NE(store, nullptr);

    ValuesBucket values;
    values.PutInt("id", 1);
    int64_t rowId = 0;
    int err = store->Put("test_table", values, rowId);

    // 验证返回码
    EXPECT_EQ(err, E_OK);
    // 验证副作用：行数增加
    auto resultSet = store->QuerySql("SELECT COUNT(*) FROM test_table");
    ASSERT_NE(resultSet, nullptr);
    EXPECT_EQ(resultSet->GoToFirstRow(), E_OK);
    EXPECT_EQ(resultSet->GetInt(0), 1);
}
```

> **原则**：用例的价值在于断言。没有断言的用例只是"调用了接口"，不构成验证。提交前逐项确认每个用例至少有一个有意义的断言。

### 3.14 断言失败日志

断言 MUST 在 `<<` 操作符后补充上下文信息，帮助失败时快速定位问题。信息仅在断言失败时输出，不影响成功用例的输出整洁度。

**写法：**

```cpp
EXPECT_*(actual, expected) << "上下文信息: " << variable;
ASSERT_*(actual, expected) << "上下文信息: " << variable;
```

**建议补充日志的场景：**

| 场景 | 补充内容 | 示例 |
|---|---|---|
| 循环内断言 | 当前迭代索引和关键状态 | `EXPECT_EQ(err, E_OK) << "insert failed at row " << i;` |
| 错误码验证 | 错误码值和操作描述 | `EXPECT_EQ(err, E_OK) << "Put failed, err=" << err;` |
| 结果集验证 | 当前行号和列值 | `EXPECT_EQ(val, expected) << "row=" << row << ", col=" << col;` |
| 参数化测试 | 当前参数值 | `EXPECT_EQ(result, expected) << "param=" << GetParam().name;` |
| 多步骤用例 | 当前步骤和中间状态 | `EXPECT_EQ(step3Result, E_OK) << "step3 failed after step1/2 ok";` |

**示例：**

```cpp
HWTEST_F(RdbStoreImplTest, Rdb_BatchInsertTest_001, TestSize.Level1)
{
    auto store = GetRdbStore();
    ASSERT_NE(store, nullptr) << "GetRdbStore returned null";

    // Act: 批量插入 1000 行
    int successCount = 0;
    for (int i = 0; i < 1000; i++) {
        ValuesBucket values;
        values.PutInt("id", i);
        values.PutString("data", std::to_string(i));
        int64_t rowId = 0;
        int err = store->Put("test_table", values, rowId);
        successCount += (err == E_OK) ? 1 : 0;
    }

    // Assert: 断言失败时输出失败行数和错误码
    EXPECT_EQ(successCount, 1000)
        << "batch insert failed, success=" << successCount << "/1000";

    // 验证行数
    auto resultSet = store->QuerySql("SELECT COUNT(*) FROM test_table");
    ASSERT_NE(resultSet, nullptr) << "QuerySql returned null";
    EXPECT_EQ(resultSet->GoToFirstRow(), E_OK);
    EXPECT_EQ(resultSet->GetInt(0), 1)
        << "row count mismatch after batch insert, success=" << successCount;
}
```

**规范：**

| 规则 | 说明 |
|---|---|
| 使用 `<<` 补充断言上下文 | 仅断言失败时输出，成功时不产生噪音 |
| 禁止 `printf`/`std::cout` 替代 | 无法区分 pass/fail 输出，且不自动附加换行 |
| 补充关键变量值 | 错误码、索引、行号、路径、参数值等定位所需信息 |
| 循环内断言 MUST 补充索引 | 否则失败时无法定位是哪次迭代失败 |
| 禁止用打印替代断言 | `<<` 是断言的补充，不是验证本身（见 3.13） |

---

## 4. 用例新增流程

1. **确定测试层**：根据被测代码位置选择测试层（见第 1.2 节）
2. **选择或创建 Fixture**：优先复用已有 Fixture，仅在测试场景显著不同时新建
3. **选择文件**：放入对应功能域的测试文件，或新建文件（按第 2.1 节命名）
4. **编写用例**：按 AAA 结构编写，包含注释，选择正确的 TestSize.Level
5. **确保隔离**：独立数据库文件、TearDown 清理、无用例间依赖
6. **更新 CMakeLists**：如新增测试源文件，在对应 `.cmake` 文件的 source list 中添加
7. **验证**：构建并运行测试，确认 pass
8. **代码审查**：检查命名规范、注释完整性、无 sleep、无文件残留

---

## 5. 用例检查清单

用例提交前 MUST 逐项确认：

| 检查项 | 要求 | ✓ |
|---|---|---|
| 文件命名 | `功能域_功能点_test.cpp` 格式 | |
| 用例命名 | `Module_Function_Description_序号` 格式 | |
| 用例注释 | `@brief` 描述测试目的和预期结果 | |
| 用例结构 | Arrange-Act-Assert 三段式 | |
| 用例隔离 | 独立数据库文件、无用例间依赖 | |
| TearDown | 使用 `DeleteRdbStore` 接口清理数据库（自动清理 -journal/-wal/-shm） | |
| 禁止 sleep | 无 `sleep()` / `std::this_thread::sleep_for()` / `usleep()` | |
| 禁止临时文件残留 | 所有临时文件在 TearDown 中删除 | |
| 断言使用 | 前置条件用 `ASSERT_*`，结果验证用 `EXPECT_*` | |
| 禁止无断言用例 | 每个用例至少 1 个 `EXPECT_*` 或 `ASSERT_*`（见 3.13） | |
| 断言失败日志 | 断言 `<<` 后补充上下文信息（见 3.14） | |
| 错误码验证 | 接口返回值 MUST 验证错误码 | |
| TestSize.Level | 按用例重要性选择正确 Level | |
| 代码复用 | 与已有用例重复 > 70% 时提取公共逻辑 | |
| CMakeLists 更新 | 新增源文件已加入对应 `.cmake` source list | |
| 构建验证 | `ninja -j16` 零错误 | |
| 运行验证 | 用例单独运行 pass | |

---

## 6. 参考文档

| 文档 | 路径 | 说明 |
|---|---|---|
| [代码规范](./code_standards.md) | `relational_store/docs/` | R1~R10 编码规范 |
| [RDB Native 架构](./rdb_native.md) | `relational_store/docs/` | 核心类关系、目录结构 |
| [错误码分层](./error_code_layers.md) | `relational_store/docs/` | 错误码定义与使用 |
| [RDB 用例知识库](../../docs/rdb-test-knowledge-base.md) | `docs/` | 用例目录、Fixture 清单、测试二进制 |
| [测试运行指南](../../docs/agents-test-guide.md) | `docs/` | 测试环境、运行命令、Mock 系统 |
| [GN 到 CMake 转换](../../docs/agents-build-and-fix.md) | `docs/` | CMakeLists 编写规范 |
