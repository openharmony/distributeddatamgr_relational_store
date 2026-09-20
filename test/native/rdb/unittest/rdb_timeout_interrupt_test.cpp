/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "rdb_store_impl.h"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "transaction.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS;

namespace {
constexpr int DEFAULT_BLOB_SIZE = 4096;
// Large blob to ensure single-row INSERT takes long enough for timeout interrupt tests.
constexpr int LARGE_BLOB_SIZE = 2 * 1024 * 1024; // 2MB
// Limited by SQLite max variable (32766): 2 columns per row → max 16383 rows per SQL.
// The timeout-aware BatchInsert requires a single SQL statement (sqlArgs.size() == 1).
constexpr int LARGE_ROW_COUNT = 16000;
constexpr int BATCH_ROW_COUNT = 10000;
constexpr int EXECUTE_BATCH_ROW_COUNT = 5000;
} // namespace

class RdbTimeoutInterruptTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;

    /**
     * @brief Create a table with (id, name, data BLOB) schema and pre-insert
     *        a large number of rows with 4KB blobs to make subsequent operations slow.
     * @param tableName The target table name.
     * @param rowCount Number of rows to pre-insert.
     * @return E_OK on success, error code otherwise.
     */
    int PrepareLargeTable(const std::string &tableName, int rowCount);

    /**
     * @brief Build a ValuesBuckets containing rowCount rows with name + 4KB blob.
     */
    ValuesBuckets BuildLargeRows(int rowCount);

protected:
    std::shared_ptr<RdbStore> store_;
};

class RdbTimeoutInterruptTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override { return E_OK; }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override { return E_OK; }
};

const std::string RdbTimeoutInterruptTest::DATABASE_NAME = RDB_TEST_PATH + "timeout_interrupt_test.db";

void RdbTimeoutInterruptTest::SetUpTestCase(void) {}

void RdbTimeoutInterruptTest::TearDownTestCase(void) {}

void RdbTimeoutInterruptTest::SetUp(void)
{
    store_ = nullptr;
    int errCode = RdbHelper::DeleteRdbStore(DATABASE_NAME);
    EXPECT_EQ(E_OK, errCode);
    RdbStoreConfig config(RdbTimeoutInterruptTest::DATABASE_NAME);
    RdbTimeoutInterruptTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbTimeoutInterruptTest::TearDown(void)
{
    store_ = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

ValuesBuckets RdbTimeoutInterruptTest::BuildLargeRows(int rowCount)
{
    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 1);
    ValuesBuckets rows;
    for (int i = 0; i < rowCount; i++) {
        ValuesBucket row;
        row.Put("name", "test_" + std::to_string(i));
        row.PutBlob("data", blobData);
        rows.Put(row);
    }
    return rows;
}

int RdbTimeoutInterruptTest::PrepareLargeTable(const std::string &tableName, int rowCount)
{
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    if (res.first != E_OK) {
        return res.first;
    }
    auto rows = BuildLargeRows(rowCount);
    auto [errCode, count] = store_->BatchInsert(tableName, rows);
    return errCode;
}

/* *
 * @tc.name: BatchInsert_Timeout_001
 * @tc.desc: BatchInsert with sufficient timeout, all rows should be inserted.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, BatchInsert_Timeout_001, TestSize.Level1)
{
    std::string tableName = "BatchInsertTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    const int rowCount = 100;
    auto rows = BuildLargeRows(rowCount);

    BatchInsertConfig config;
    config.timeoutMs = 5000;
    auto [errCode, result] = store_->BatchInsert(tableName, rows, ConflictResolution::ON_CONFLICT_NONE, config);
    ASSERT_EQ(errCode, E_OK);

    auto resultSet = store_->QueryByStep("SELECT COUNT(*) FROM " + tableName);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToNextRow(), E_OK);
    int64_t actualCount = 0;
    resultSet->GetLong(0, actualCount);
    EXPECT_EQ(actualCount, rowCount);

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: BatchInsert_Timeout_002
 * @tc.desc: BatchInsert 2w rows with very short timeout(1ms), interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, BatchInsert_Timeout_002, TestSize.Level1)
{
    std::string tableName = "BatchInsertTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    auto rows = BuildLargeRows(LARGE_ROW_COUNT);

    BatchInsertConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, insertResult] =
        store_->BatchInsert(tableName, rows, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("BatchInsert_Timeout_002: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    ASSERT_EQ(errCode, E_SQLITE_INTERRUPT);
    EXPECT_EQ(insertResult.changed, -1);

    auto resultSet = store_->QueryByStep("SELECT COUNT(*) FROM " + tableName);
    ASSERT_NE(resultSet, nullptr);
    resultSet->GoToNextRow();
    int64_t actualCount = 0;
    resultSet->GetLong(0, actualCount);
    EXPECT_LT(actualCount, LARGE_ROW_COUNT)
        << "BatchInsert not interrupted, all " << LARGE_ROW_COUNT << " rows inserted, elapsed=" << elapsed << "ms";

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: BatchInsert_Timeout_003
 * @tc.desc: BatchInsert 2w rows with 120ms timeout, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, BatchInsert_Timeout_003, TestSize.Level1)
{
    std::string tableName = "BatchInsertTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    auto rows = BuildLargeRows(LARGE_ROW_COUNT);

    BatchInsertConfig config;
    config.timeoutMs = 120;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, insertResult] =
        store_->BatchInsert(tableName, rows, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("BatchInsert_Timeout_003: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    ASSERT_EQ(errCode, E_SQLITE_INTERRUPT);
    EXPECT_EQ(insertResult.changed, -1);

    auto resultSet = store_->QueryByStep("SELECT COUNT(*) FROM " + tableName);
    ASSERT_NE(resultSet, nullptr);
    resultSet->GoToNextRow();
    int64_t actualCount = 0;
    resultSet->GetLong(0, actualCount);
    EXPECT_LT(actualCount, LARGE_ROW_COUNT)
        << "BatchInsert not interrupted, all " << LARGE_ROW_COUNT << " rows inserted, elapsed=" << elapsed << "ms";

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Insert_Timeout_001
 * @tc.desc: Insert with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Insert_Timeout_000, TestSize.Level1)
{
    std::string tableName = "InsertTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 1);
    ValuesBucket newRow;
    newRow.Put("name", "timeout_row");
    newRow.PutBlob("data", blobData);

    InsertConfig config;
    config.timeoutMs = 0;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, rowId] =
        store_->Insert(tableName, newRow, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Insert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_OK)
        << "Unexpected errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Insert_Timeout_001
 * @tc.desc: Insert with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Insert_Timeout_001, TestSize.Level1)
{
    std::string tableName = "InsertTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 1);
    ValuesBucket newRow;
    newRow.Put("name", "timeout_row");
    newRow.PutBlob("data", blobData);

    InsertConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, rowId] =
        store_->Insert(tableName, newRow, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Insert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Insert_Timeout_002
 * @tc.desc: Insert with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Insert_Timeout_002, TestSize.Level1)
{
    std::string tableName = "InsertTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    std::vector<uint8_t> blobData(LARGE_BLOB_SIZE, 1);
    ValuesBucket newRow;
    newRow.Put("name", "timeout_row");
    newRow.PutBlob("data", blobData);

    InsertConfig config;
    config.timeoutMs = 5;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, rowId] =
        store_->Insert(tableName, newRow, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Insert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Delete_Timeout_001
 * @tc.desc: Delete with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Delete_Timeout_001, TestSize.Level1)
{
    std::string tableName = "DeleteTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    AbsRdbPredicates predicates(tableName);
    predicates.EqualTo("name", "nonexistent"); // Force full table scan

    DeleteConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, deleteResult] = store_->Delete(predicates, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Delete_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Delete_Timeout_002
 * @tc.desc: Delete with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Delete_Timeout_002, TestSize.Level1)
{
    std::string tableName = "DeleteTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    AbsRdbPredicates predicates(tableName);
    predicates.EqualTo("name", "nonexistent"); // Force full table scan

    DeleteConfig config;
    config.timeoutMs = 3;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, deleteResult] = store_->Delete(predicates, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Delete_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Update_Timeout_001
 * @tc.desc: Update with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Update_Timeout_001, TestSize.Level1)
{
    std::string tableName = "UpdateTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    ValuesBucket updateRow;
    updateRow.Put("name", "updated");
    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 2);
    updateRow.PutBlob("data", blobData);

    AbsRdbPredicates predicates(tableName);
    predicates.EqualTo("name", "nonexistent"); // Force full table scan

    UpdateConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, updateResult] =
        store_->Update(updateRow, predicates, config, ConflictResolution::ON_CONFLICT_NONE);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Update_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Update_Timeout_002
 * @tc.desc: Update with short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Update_Timeout_002, TestSize.Level1)
{
    std::string tableName = "UpdateTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    ValuesBucket updateRow;
    updateRow.Put("name", "updated");
    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 2);
    updateRow.PutBlob("data", blobData);

    AbsRdbPredicates predicates(tableName);
    predicates.EqualTo("name", "nonexistent"); // Force full table scan

    UpdateConfig config;
    config.timeoutMs = 3;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, updateResult] =
        store_->Update(updateRow, predicates, config, ConflictResolution::ON_CONFLICT_NONE);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Update_Timeout_002: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Execute_Timeout_001
 * @tc.desc: Execute a DELETE SQL with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Execute_Timeout_001, TestSize.Level1)
{
    std::string tableName = "ExecuteTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    std::string deleteSql = "DELETE FROM " + tableName + " WHERE name LIKE '%test_%'";
    ExecuteConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, value] = store_->Execute(deleteSql, {}, 0, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Execute_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Execute_Timeout_002
 * @tc.desc: Execute a large multi-row INSERT SQL with short timeout, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Execute_Timeout_002, TestSize.Level1)
{
    std::string tableName = "ExecuteBatchTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 1);
    std::string sql = "INSERT INTO " + tableName + " (name, data) VALUES ";
    std::vector<ValueObject> args;
    for (int i = 0; i < EXECUTE_BATCH_ROW_COUNT; i++) {
        if (i > 0) sql += ", ";
        sql += "(?, ?)";
        args.push_back(ValueObject("test_" + std::to_string(i)));
        args.push_back(ValueObject(blobData));
    }

    ExecuteConfig config;
    config.timeoutMs = 100;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, value] = store_->Execute(sql, args, 0, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Execute_Timeout_002: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: QuerySql_Timeout_001
 * @tc.desc: QuerySql with very short timeout on a large table, interrupt during Count() in
 *           result set construction should cause QuerySql to return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, QuerySql_Timeout_001, TestSize.Level1)
{
    std::string tableName = "QuerySqlTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    // Full table scan with ORDER BY on non-indexed column to force slow Count() in constructor
    std::string querySql = "SELECT * FROM " + tableName + " ORDER BY name";
    QueryConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto resultSet = store_->QuerySql(querySql, {}, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("QuerySql_Timeout_001: elapsed=%lldms, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), static_cast<long long>(config.timeoutMs));

    // When Count() is interrupted during construction, QuerySql returns nullptr
    EXPECT_EQ(resultSet, nullptr)
        << "QuerySql should return nullptr when Count() is interrupted, elapsed=" << elapsed << "ms";

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: QuerySql_Timeout_002
 * @tc.desc: QuerySql with very short timeout on a large table, interrupt during Count() in
 *           result set construction should cause QuerySql to return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, QuerySql_Timeout_002, TestSize.Level1)
{
    std::string tableName = "QuerySqlTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    // Full table scan with ORDER BY on non-indexed column to force slow Count() in constructor
    std::string querySql = "SELECT * FROM " + tableName + " ORDER BY name";
    QueryConfig config;
    config.timeoutMs = 50;
    auto start = std::chrono::steady_clock::now();
    auto resultSet = store_->QuerySql(querySql, {}, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("QuerySql_Timeout_001: elapsed=%lldms, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), static_cast<long long>(config.timeoutMs));

    // When Count() is interrupted during construction, QuerySql returns nullptr
    EXPECT_EQ(resultSet, nullptr)
        << "QuerySql should return nullptr when Count() is interrupted, elapsed=" << elapsed << "ms";

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: QueryByStep_Timeout_001
 * @tc.desc: QueryByStep with very short timeout on a large table, interrupt during Count() in
 *           result set construction should cause QueryByStep to return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, QueryByStep_Timeout_001, TestSize.Level1)
{
    std::string tableName = "QueryByStepTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    // Full table scan with ORDER BY on non-indexed column to force slow Count() in constructor
    std::string querySql = "SELECT * FROM " + tableName + " ORDER BY name";
    OHOS::DistributedRdb::QueryOptions options;
    options.preCount = true; // Enable Count() in constructor to test interrupt during count phase
    QueryConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto resultSet = store_->QueryByStep(querySql, {}, options, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("QueryByStep_Timeout_001: elapsed=%lldms, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), static_cast<long long>(config.timeoutMs));

    // When Count() is interrupted during construction, QueryByStep returns nullptr
    EXPECT_EQ(resultSet, nullptr)
        << "QueryByStep should return nullptr when Count() is interrupted, elapsed=" << elapsed << "ms";

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: QueryByStep_Timeout_002
 * @tc.desc: QueryByStep with very short timeout on a large table, interrupt during Count() in
 *           result set construction should cause QueryByStep to return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, QueryByStep_Timeout_002, TestSize.Level1)
{
    std::string tableName = "QueryByStepTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    // Full table scan with ORDER BY on non-indexed column to force slow Count() in constructor
    std::string querySql = "SELECT * FROM " + tableName + " ORDER BY name";
    OHOS::DistributedRdb::QueryOptions options;
    options.preCount = true; // Enable Count() in constructor to test interrupt during count phase
    QueryConfig config;
    config.timeoutMs = 50;
    auto start = std::chrono::steady_clock::now();
    auto resultSet = store_->QueryByStep(querySql, {}, options, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("QueryByStep_Timeout_002: elapsed=%lldms, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), static_cast<long long>(config.timeoutMs));

    // When Count() is interrupted during construction, QueryByStep returns nullptr
    EXPECT_EQ(resultSet, nullptr)
        << "QueryByStep should return nullptr when Count() is interrupted, elapsed=" << elapsed << "ms";

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Insert_Timeout_001
 * @tc.desc: Transaction Insert with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Insert_Timeout_001, TestSize.Level1)
{
    std::string tableName = "TransInsertTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    std::vector<uint8_t> blobData(LARGE_BLOB_SIZE, 1);
    ValuesBucket newRow;
    newRow.Put("name", "timeout_row");
    newRow.PutBlob("data", blobData);

    InsertConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, rowId] = trans->Insert(tableName, newRow, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Insert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Insert_Timeout_002
 * @tc.desc: Transaction Insert with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Insert_Timeout_002, TestSize.Level1)
{
    std::string tableName = "TransInsertTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    std::vector<uint8_t> blobData(LARGE_BLOB_SIZE, 1);
    ValuesBucket newRow;
    newRow.Put("name", "timeout_row");
    newRow.PutBlob("data", blobData);

    InsertConfig config;
    config.timeoutMs = 2;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, rowId] = trans->Insert(tableName, newRow, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Insert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_BatchInsert_Timeout_001
 * @tc.desc: Transaction BatchInsert with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_BatchInsert_Timeout_001, TestSize.Level1)
{
    std::string tableName = "TransBatchInsertTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    auto rows = BuildLargeRows(LARGE_ROW_COUNT);

    BatchInsertConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, insertResult] =
        trans->BatchInsert(tableName, rows, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_BatchInsert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_BatchInsert_Timeout_002
 * @tc.desc: Transaction BatchInsert with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_BatchInsert_Timeout_002, TestSize.Level1)
{
    std::string tableName = "TransBatchInsertTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    auto rows = BuildLargeRows(LARGE_ROW_COUNT);

    BatchInsertConfig config;
    config.timeoutMs = 100;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, insertResult] =
        trans->BatchInsert(tableName, rows, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_BatchInsert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Update_Timeout_001
 * @tc.desc: Transaction Update with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Update_Timeout_001, TestSize.Level1)
{
    std::string tableName = "TransUpdateTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    ValuesBucket updateRow;
    updateRow.Put("name", "updated");
    std::vector<uint8_t> blobData(LARGE_BLOB_SIZE, 2);
    updateRow.PutBlob("data", blobData);

    AbsRdbPredicates predicates(tableName);
    predicates.EqualTo("name", "nonexistent"); // Force full table scan

    UpdateConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, updateResult] =
        trans->Update(updateRow, predicates, config, ConflictResolution::ON_CONFLICT_NONE);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Update_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Update_Timeout_001
 * @tc.desc: Transaction Update with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Update_Timeout_002, TestSize.Level1)
{
    std::string tableName = "TransUpdateTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    ValuesBucket updateRow;
    updateRow.Put("name", "updated");
    std::vector<uint8_t> blobData(LARGE_BLOB_SIZE, 2);
    updateRow.PutBlob("data", blobData);

    AbsRdbPredicates predicates(tableName);
    predicates.EqualTo("name", "nonexistent"); // Force full table scan

    UpdateConfig config;
    config.timeoutMs = 3;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, updateResult] =
        trans->Update(updateRow, predicates, config, ConflictResolution::ON_CONFLICT_NONE);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Update_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Delete_Timeout_001
 * @tc.desc: Transaction Delete with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Delete_Timeout_001, TestSize.Level1)
{
    std::string tableName = "TransDeleteTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    AbsRdbPredicates predicates(tableName);
    // No WHERE clause — delete all rows to ensure operation takes long enough for interrupt

    DeleteConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, deleteResult] = trans->Delete(predicates, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Delete_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Delete_Timeout_001
 * @tc.desc: Transaction Delete with very short timeout on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Delete_Timeout_002, TestSize.Level1)
{
    std::string tableName = "TransDeleteTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    AbsRdbPredicates predicates(tableName);
    // No WHERE clause — delete all rows to ensure operation takes long enough for interrupt

    DeleteConfig config;
    config.timeoutMs = 3;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, deleteResult] = trans->Delete(predicates, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Delete_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Execute_Timeout_001
 * @tc.desc: Transaction Execute a slow UPDATE SQL with very short timeout, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Execute_Timeout_001, TestSize.Level1)
{
    std::string tableName = "TransExecuteTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    std::string sql = "UPDATE " + tableName + " SET name = name || '_x'";
    ExecuteConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, value] = trans->Execute(sql, {}, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Execute_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Execute_Timeout_001
 * @tc.desc: Transaction Execute a slow UPDATE SQL with very short timeout, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Execute_Timeout_002, TestSize.Level1)
{
    std::string tableName = "TransExecuteTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    std::string sql = "UPDATE " + tableName + " SET name = name || '_x'";
    ExecuteConfig config;
    config.timeoutMs = 5;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, value] = trans->Execute(sql, {}, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Execute_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_QueryByStep_Timeout_001
 * @tc.desc: Transaction QueryByStep with very short timeout on a large table, interrupt during
 *           Count() should cause QueryByStep to return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_QueryByStep_Timeout_001, TestSize.Level1)
{
    std::string tableName = "TransQueryTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    std::string querySql = "SELECT * FROM " + tableName + " ORDER BY name";
    OHOS::DistributedRdb::QueryOptions options;
    options.preCount = true;
    QueryConfig config;
    config.timeoutMs = 1;
    auto start = std::chrono::steady_clock::now();
    auto resultSet = trans->QueryByStep(querySql, {}, options, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_QueryByStep_Timeout_001: elapsed=%lldms, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), static_cast<long long>(config.timeoutMs));

    EXPECT_EQ(resultSet, nullptr)
        << "Transaction QueryByStep should return nullptr when interrupted, elapsed=" << elapsed << "ms";

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_QueryByStep_Timeout_001
 * @tc.desc: Transaction QueryByStep with very short timeout on a large table, interrupt during
 *           Count() should cause QueryByStep to return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_QueryByStep_Timeout_002, TestSize.Level1)
{
    std::string tableName = "TransQueryTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    std::string querySql = "SELECT * FROM " + tableName + " ORDER BY name";
    OHOS::DistributedRdb::QueryOptions options;
    options.preCount = true;
    QueryConfig config;
    config.timeoutMs = 30;
    auto start = std::chrono::steady_clock::now();
    auto resultSet = trans->QueryByStep(querySql, {}, options, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_QueryByStep_Timeout_001: elapsed=%lldms, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), static_cast<long long>(config.timeoutMs));

    EXPECT_EQ(resultSet, nullptr)
        << "Transaction QueryByStep should return nullptr when interrupted, elapsed=" << elapsed << "ms";

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: ExecuteConfig_Decouple_001
 * @tc.desc: Default ExecuteConfig has inactive timeout (timeoutMs=0) and empty returning,
 *           verifying the two concerns are independent and default-safe.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, ExecuteConfig_Decouple_001, TestSize.Level1)
{
    ExecuteConfig config;
    EXPECT_EQ(config.timeoutMs, 0);
    EXPECT_TRUE(config.returning.columns.empty());
    EXPECT_EQ(config.returning.maxReturningCount, ReturningConfig::DEFAULT_RETURNING_COUNT);
    auto token = DeadlineToken::FromMs(config.timeoutMs);
    EXPECT_FALSE(token.IsActive());
}

/* *
 * @tc.name: ExecuteConfig_Decouple_002
 * @tc.desc: Setting timeout does not perturb ReturningConfig and vice versa;
 *           the two fields are orthogonal.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, ExecuteConfig_Decouple_002, TestSize.Level1)
{
    ExecuteConfig config;
    config.timeoutMs = 1000;
    EXPECT_EQ(config.timeoutMs, 1000);
    EXPECT_TRUE(config.returning.columns.empty())
        << "setting timeout leaked into returning";

    ExecuteConfig other;
    other.returning = ReturningConfig{ std::vector<std::string>{ "name" }, 16 };
    EXPECT_EQ(other.timeoutMs, 0) << "setting returning leaked into timeout";
    EXPECT_EQ(other.returning.columns.size(), 1);
    EXPECT_EQ(other.returning.maxReturningCount, 16);
}

/* *
 * @tc.name: ExecuteConfig_Decouple_003
 * @tc.desc: Construct ExecuteConfig with timeoutMs=0 (returning default) and run an
 *           Insert with no timeout; the row must be inserted, proving the no-timeout
 *           path is equivalent to the no-config path.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, ExecuteConfig_Decouple_003, TestSize.Level1)
{
    std::string tableName = "DecoupleTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 1);
    ValuesBucket newRow;
    newRow.Put("name", "decouple_row");
    newRow.PutBlob("data", blobData);

    InsertConfig config{ 0 };
    EXPECT_EQ(config.timeoutMs, 0);
    auto [errCode, rowId] = store_->Insert(tableName, newRow, ConflictResolution::ON_CONFLICT_NONE, config);
    EXPECT_EQ(errCode, E_OK);

    auto resultSet = store_->QueryByStep("SELECT COUNT(*) FROM " + tableName);
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToNextRow(), E_OK);
    int64_t actualCount = 0;
    resultSet->GetLong(0, actualCount);
    EXPECT_EQ(actualCount, 1);

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}