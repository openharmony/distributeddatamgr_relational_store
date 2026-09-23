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
constexpr int LARGE_BLOB_SIZE = 8 * 1024 * 1024; // 8MB, ensures single-row INSERT > 50ms
constexpr int LARGE_ROW_COUNT = 16000;
constexpr int BATCH_ROW_COUNT = 10000;
constexpr int EXECUTE_BATCH_ROW_COUNT = 10000;
constexpr int64_t TEST_TIMEOUT_MS = 5;
} // namespace

class RdbTimeoutInterruptTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string databaseName;

    int PrepareLargeTable(const std::string &tableName, int rowCount);
    ValuesBuckets BuildLargeRows(int rowCount);
    int64_t QueryCount(const std::string &sql);

protected:
    std::shared_ptr<RdbStore> store_;
};

class RdbTimeoutInterruptTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override { return E_OK; }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override { return E_OK; }
};

const std::string RdbTimeoutInterruptTest::databaseName = RDB_TEST_PATH + "timeout_interrupt_test.db";

void RdbTimeoutInterruptTest::SetUpTestCase(void) {}

void RdbTimeoutInterruptTest::TearDownTestCase(void) {}

void RdbTimeoutInterruptTest::SetUp(void)
{
    store_ = nullptr;
    int errCode = RdbHelper::DeleteRdbStore(databaseName);
    EXPECT_EQ(E_OK, errCode);
    RdbStoreConfig config(RdbTimeoutInterruptTest::databaseName);
    RdbTimeoutInterruptTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbTimeoutInterruptTest::TearDown(void)
{
    store_ = nullptr;
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(databaseName);
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

int64_t RdbTimeoutInterruptTest::QueryCount(const std::string &sql)
{
    auto resultSet = store_->QueryByStep(sql);
    if (resultSet == nullptr) {
        return -1;
    }
    if (resultSet->GoToNextRow() != E_OK) {
        return -1;
    }
    int64_t count = 0;
    resultSet->GetLong(0, count);
    return count;
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
 * @tc.desc: BatchInsert with 200ms timeout, interrupt should be effective.
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
    config.timeoutMs = 500;
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
    EXPECT_EQ(actualCount, 0)
        << "BatchInsert should be rolled back, actualCount=" << actualCount;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Insert_Timeout_001
 * @tc.desc: Insert with timeout. Uses a trigger to make single-row INSERT
 *           interruptible (OP_Insert itself is atomic; the trigger's full-table
 *           UPDATE loop checks the interrupt flag between rows).
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Insert_Timeout_001, TestSize.Level1)
{
    std::string largeTable = "InsertTimeoutLarge";
    ASSERT_EQ(PrepareLargeTable(largeTable, BATCH_ROW_COUNT), E_OK);

    std::string tableName = "InsertTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    store_->Execute("DROP TRIGGER IF EXISTS insert_trigger");
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);
    store_->Execute("CREATE TRIGGER insert_trigger AFTER INSERT ON " + tableName +
        " BEGIN UPDATE " + largeTable + " SET name = name || '_x'; END");

    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 1);
    ValuesBucket newRow;
    newRow.Put("name", "timeout_row");
    newRow.PutBlob("data", blobData);

    InsertConfig config;
    config.timeoutMs = 50;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, rowId] =
        store_->Insert(tableName, newRow, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Insert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto insertCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(insertCount, 0) << "Insert should be rolled back, actualCount=" << insertCount;
    auto updatedCount = QueryCount("SELECT COUNT(*) FROM " + largeTable + " WHERE name LIKE '%_x'");
    EXPECT_EQ(updatedCount, 0)
        << "Trigger UPDATE should be rolled back, updated=" << updatedCount;

    store_->Execute("DROP TRIGGER IF EXISTS insert_trigger");
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    store_->Execute("DROP TABLE IF EXISTS " + largeTable);
}

/* *
 * @tc.name: Delete_Timeout_001
 * @tc.desc: Delete with min timeout(100ms) on a large table, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Delete_Timeout_001, TestSize.Level1)
{
    std::string tableName = "DeleteTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    AbsRdbPredicates predicates(tableName);
    predicates.EqualTo("name", "nonexistent"); // Force full table scan

    DeleteConfig config;
    config.timeoutMs = TEST_TIMEOUT_MS;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, deleteResult] = store_->Delete(predicates, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Delete_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto actualCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(actualCount, BATCH_ROW_COUNT)
        << "Delete should not affect any rows, actualCount=" << actualCount;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Update_Timeout_001
 * @tc.desc: Update with min timeout(100ms) on a large table, interrupt should be effective.
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
    config.timeoutMs = TEST_TIMEOUT_MS;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, updateResult] =
        store_->Update(updateRow, predicates, config, ConflictResolution::ON_CONFLICT_NONE);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Update_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto updatedCount = QueryCount("SELECT COUNT(*) FROM " + tableName + " WHERE name = 'updated'");
    EXPECT_EQ(updatedCount, 0)
        << "Update should not modify any rows, updatedCount=" << updatedCount;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Execute_Timeout_001
 * @tc.desc: Execute a large multi-row INSERT SQL with 100ms timeout, interrupt should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Execute_Timeout_001, TestSize.Level1)
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
        if (i > 0) {
            sql += ", ";
        }
        sql += "(?, ?)";
        args.push_back(ValueObject("test_" + std::to_string(i)));
        args.push_back(ValueObject(blobData));
    }

    ExecuteConfig config;
    config.timeoutMs = TEST_TIMEOUT_MS;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, value] = store_->Execute(sql, args, 0, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Execute_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto actualCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(actualCount, 0)
        << "Execute should be rolled back, actualCount=" << actualCount;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: QuerySql_Timeout_001
 * @tc.desc: QuerySql with min timeout(100ms) on a large table, interrupt during Count() should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, QuerySql_Timeout_001, TestSize.Level1)
{
    std::string tableName = "QuerySqlTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    std::string querySql = "SELECT * FROM " + tableName + " ORDER BY name";
    QueryConfig config;
    config.timeoutMs = TEST_TIMEOUT_MS;
    auto start = std::chrono::steady_clock::now();
    auto resultSet = store_->QuerySql(querySql, {}, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("QuerySql_Timeout_001: elapsed=%lldms, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), static_cast<long long>(config.timeoutMs));

    if (resultSet != nullptr) {
        EXPECT_EQ(resultSet->GoToNextRow(), E_SQLITE_INTERRUPT)
            << "QuerySql should be interrupted, elapsed=" << elapsed << "ms";
    }

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: QueryByStep_Timeout_001
 * @tc.desc: QueryByStep with min timeout(100ms) on a large table, interrupt during Count() should be effective.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, QueryByStep_Timeout_001, TestSize.Level1)
{
    std::string tableName = "QueryByStepTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    std::string querySql = "SELECT * FROM " + tableName + " ORDER BY name";
    OHOS::DistributedRdb::QueryOptions options;
    options.preCount = true;
    options.isGotoNextRowReturnLastError = true;
    QueryConfig config;
    config.timeoutMs = TEST_TIMEOUT_MS;
    auto start = std::chrono::steady_clock::now();
    auto resultSet = store_->QueryByStep(querySql, {}, options, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("QueryByStep_Timeout_001: elapsed=%lldms, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), static_cast<long long>(config.timeoutMs));

    if (resultSet != nullptr) {
        EXPECT_EQ(resultSet->GoToNextRow(), E_SQLITE_INTERRUPT)
            << "QueryByStep should be interrupted, elapsed=" << elapsed << "ms";
    }

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Insert_Timeout_001
 * @tc.desc: Transaction Insert with timeout. Uses a trigger to make single-row
 *           INSERT interruptible (OP_Insert itself is atomic; the trigger's
 *           full-table UPDATE loop checks the interrupt flag between rows).
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Insert_Timeout_001, TestSize.Level1)
{
    std::string largeTable = "TransInsertLarge";
    ASSERT_EQ(PrepareLargeTable(largeTable, BATCH_ROW_COUNT), E_OK);

    std::string tableName = "TransInsertTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    store_->Execute("DROP TRIGGER IF EXISTS trans_insert_trigger");
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);
    store_->Execute("CREATE TRIGGER trans_insert_trigger AFTER INSERT ON " + tableName +
        " BEGIN UPDATE " + largeTable + " SET name = name || '_x'; END");

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 1);
    ValuesBucket newRow;
    newRow.Put("name", "timeout_row");
    newRow.PutBlob("data", blobData);

    InsertConfig config;
    config.timeoutMs = 50;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, rowId] = trans->Insert(tableName, newRow, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Insert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto insertCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(insertCount, 0) << "Trans Insert should be rolled back, actualCount=" << insertCount;
    auto updatedCount = QueryCount("SELECT COUNT(*) FROM " + largeTable + " WHERE name LIKE '%_x'");
    EXPECT_EQ(updatedCount, 0)
        << "Trigger UPDATE should be rolled back, updated=" << updatedCount;

    trans->Close();
    store_->Execute("DROP TRIGGER IF EXISTS trans_insert_trigger");
    // Verify rollback: subsequent write via RdbStore should succeed, not E_SQLITE_BUSY
    auto writeRes = store_->Execute(
        "INSERT INTO " + tableName + " (name, data) VALUES ('rb_verify', NULL)");
    EXPECT_EQ(writeRes.first, E_OK)
        << "Transaction should be rolled back, write lock released, but got errCode=" << writeRes.first;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    store_->Execute("DROP TABLE IF EXISTS " + largeTable);
}

/* *
 * @tc.name: Transaction_BatchInsert_Timeout_001
 * @tc.desc: Transaction BatchInsert with min timeout(100ms), interrupt should be effective.
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
    config.timeoutMs = 500;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, insertResult] =
        trans->BatchInsert(tableName, rows, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_BatchInsert_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto actualCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(actualCount, 0)
        << "Trans BatchInsert should be rolled back, actualCount=" << actualCount;

    trans->Close();
    // Verify rollback: subsequent write via RdbStore should succeed, not E_SQLITE_BUSY
    auto writeRes = store_->Execute(
        "INSERT INTO " + tableName + " (name, data) VALUES ('rb_verify', NULL)");
    EXPECT_EQ(writeRes.first, E_OK)
        << "Transaction should be rolled back, write lock released, but got errCode=" << writeRes.first;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Update_Timeout_001
 * @tc.desc: Transaction Update with min timeout(100ms) on a large table, interrupt should be effective.
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
    config.timeoutMs = 50;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, updateResult] =
        trans->Update(updateRow, predicates, config, ConflictResolution::ON_CONFLICT_NONE);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Update_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto updatedCount = QueryCount("SELECT COUNT(*) FROM " + tableName + " WHERE name = 'updated'");
    EXPECT_EQ(updatedCount, 0)
        << "Trans Update should not modify any rows, updatedCount=" << updatedCount;

    trans->Close();
    // Verify rollback: subsequent write via RdbStore should succeed, not E_SQLITE_BUSY
    auto writeRes = store_->Execute(
        "INSERT INTO " + tableName + " (name, data) VALUES ('rb_verify', NULL)");
    EXPECT_EQ(writeRes.first, E_OK)
        << "Transaction should be rolled back, write lock released, but got errCode=" << writeRes.first;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Delete_Timeout_001
 * @tc.desc: Transaction Delete with min timeout(100ms) on a large table, interrupt should be effective.
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
    predicates.EqualTo("name", "nonexistent"); // Force full table scan

    DeleteConfig config;
    config.timeoutMs = TEST_TIMEOUT_MS;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, deleteResult] = trans->Delete(predicates, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Delete_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto actualCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(actualCount, BATCH_ROW_COUNT)
        << "Trans Delete should not affect any rows, actualCount=" << actualCount;

    trans->Close();
    // Verify rollback: subsequent write via RdbStore should succeed, not E_SQLITE_BUSY
    auto writeRes = store_->Execute(
        "INSERT INTO " + tableName + " (name, data) VALUES ('rb_verify', NULL)");
    EXPECT_EQ(writeRes.first, E_OK)
        << "Transaction should be rolled back, write lock released, but got errCode=" << writeRes.first;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Execute_Timeout_001
 * @tc.desc: Transaction Execute a slow UPDATE SQL with min timeout(100ms), interrupt should be effective.
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
    config.timeoutMs = TEST_TIMEOUT_MS;
    auto start = std::chrono::steady_clock::now();
    auto [errCode, value] = trans->Execute(sql, {}, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Execute_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto updatedCount = QueryCount("SELECT COUNT(*) FROM " + tableName + " WHERE name LIKE '%_x'");
    EXPECT_EQ(updatedCount, 0)
        << "Trans Execute should be rolled back, updated=" << updatedCount;

    trans->Close();
    // Verify rollback: subsequent write via RdbStore should succeed, not E_SQLITE_BUSY
    auto writeRes = store_->Execute(
        "INSERT INTO " + tableName + " (name, data) VALUES ('rb_verify', NULL)");
    EXPECT_EQ(writeRes.first, E_OK)
        << "Transaction should be rolled back, write lock released, but got errCode=" << writeRes.first;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_QueryByStep_Timeout_001
 * @tc.desc: Transaction QueryByStep with min timeout(100ms) on a large table, interrupt during
 *           Count() should be effective.
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
    options.isGotoNextRowReturnLastError = true;
    QueryConfig config;
    config.timeoutMs = TEST_TIMEOUT_MS;
    auto start = std::chrono::steady_clock::now();
    auto resultSet = trans->QueryByStep(querySql, {}, options, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_QueryByStep_Timeout_001: elapsed=%lldms, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), static_cast<long long>(config.timeoutMs));

    if (resultSet != nullptr) {
        EXPECT_NE(resultSet->GoToNextRow(), E_OK)
            << "Transaction QueryByStep should be interrupted, elapsed=" << elapsed << "ms";
    }

    trans->Close();
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: BatchInsert_Returning_Timeout_001
 * @tc.desc: BatchInsert with RETURNING clause and timeout. With RETURNING, the VDBE
 *           loops over inserted rows, checking the interrupt flag between iterations.
 *           Verify interrupt is effective and partial data state.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, BatchInsert_Returning_Timeout_001, TestSize.Level1)
{
    std::string tableName = "BatchInsertReturningTimeoutTest";
    store_->Execute("DROP TABLE IF EXISTS " + tableName);
    auto res = store_->Execute(
        "CREATE TABLE " + tableName + " (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, data BLOB)");
    ASSERT_EQ(res.first, E_OK);

    auto rows = BuildLargeRows(LARGE_ROW_COUNT);

    BatchInsertConfig config;
    config.timeoutMs = 100;
    config.returning.columns = { "id", "name" };
    auto start = std::chrono::steady_clock::now();
    auto [errCode, insertResult] =
        store_->BatchInsert(tableName, rows, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("BatchInsert_Returning_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto actualCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(actualCount, 0)
        << "BatchInsert with RETURNING should be rolled back, actualCount=" << actualCount;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Update_Returning_Timeout_001
 * @tc.desc: Update matching all rows with RETURNING clause and timeout. The VDBE loops
 *           over matched rows, checking the interrupt flag between iterations.
 *           Verify interrupt is effective and data state.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Update_Returning_Timeout_001, TestSize.Level1)
{
    std::string tableName = "UpdateReturningTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    ValuesBucket updateRow;
    updateRow.Put("name", "updated");
    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 2);
    updateRow.PutBlob("data", blobData);

    AbsRdbPredicates predicates(tableName);
    predicates.GreaterThanOrEqualTo("id", "1"); // Match all rows

    UpdateConfig config;
    config.timeoutMs = 100;
    config.returning.columns = { "id" };
    auto start = std::chrono::steady_clock::now();
    auto [errCode, updateResult] =
        store_->Update(updateRow, predicates, config, ConflictResolution::ON_CONFLICT_NONE);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Update_Returning_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto updatedCount = QueryCount("SELECT COUNT(*) FROM " + tableName + " WHERE name = 'updated'");
    EXPECT_EQ(updatedCount, 0)
        << "Update with RETURNING should be rolled back, updatedCount=" << updatedCount;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Delete_Returning_Timeout_001
 * @tc.desc: Delete matching all rows with RETURNING clause and timeout. The VDBE loops
 *           over matched rows, checking the interrupt flag between iterations.
 *           Verify interrupt is effective and data state.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Delete_Returning_Timeout_001, TestSize.Level1)
{
    std::string tableName = "DeleteReturningTimeoutTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    AbsRdbPredicates predicates(tableName);
    predicates.GreaterThanOrEqualTo("id", "1"); // Match all rows

    DeleteConfig config;
    config.timeoutMs = 100;
    config.returning.columns = { "id", "name" };
    auto start = std::chrono::steady_clock::now();
    auto [errCode, deleteResult] = store_->Delete(predicates, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Delete_Returning_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    auto remainingCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(remainingCount, BATCH_ROW_COUNT)
        << "Delete with RETURNING should be rolled back, remainingCount=" << remainingCount;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_BatchInsert_Returning_Timeout_001
 * @tc.desc: Transaction BatchInsert with RETURNING clause and timeout. The VDBE loops
 *           over inserted rows, checking the interrupt flag between iterations.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_BatchInsert_Returning_Timeout_001, TestSize.Level1)
{
    std::string tableName = "TransBatchInsertReturningTest";
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
    config.returning.columns = { "id", "name" };
    auto start = std::chrono::steady_clock::now();
    auto [errCode, insertResult] =
        trans->BatchInsert(tableName, rows, ConflictResolution::ON_CONFLICT_NONE, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_BatchInsert_Returning_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    auto actualCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(actualCount, 0)
        << "Trans BatchInsert with RETURNING should be rolled back, actualCount=" << actualCount;

    // Verify rollback: subsequent write via RdbStore should succeed, not E_SQLITE_BUSY
    auto writeRes = store_->Execute(
        "INSERT INTO " + tableName + " (name, data) VALUES ('rb_verify', NULL)");
    EXPECT_EQ(writeRes.first, E_OK)
        << "Transaction should be rolled back, write lock released, but got errCode=" << writeRes.first;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Update_Returning_Timeout_001
 * @tc.desc: Transaction Update matching all rows with RETURNING clause and timeout.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Update_Returning_Timeout_001, TestSize.Level1)
{
    std::string tableName = "TransUpdateReturningTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    ValuesBucket updateRow;
    updateRow.Put("name", "updated");
    std::vector<uint8_t> blobData(DEFAULT_BLOB_SIZE, 2);
    updateRow.PutBlob("data", blobData);

    AbsRdbPredicates predicates(tableName);
    predicates.GreaterThanOrEqualTo("id", "1"); // Match all rows

    UpdateConfig config;
    config.timeoutMs = 100;
    config.returning.columns = { "id" };
    auto start = std::chrono::steady_clock::now();
    auto [errCode, updateResult] =
        trans->Update(updateRow, predicates, config, ConflictResolution::ON_CONFLICT_NONE);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Update_Returning_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    auto updatedCount = QueryCount("SELECT COUNT(*) FROM " + tableName + " WHERE name = 'updated'");
    EXPECT_EQ(updatedCount, 0)
        << "Trans Update with RETURNING should be rolled back, updatedCount=" << updatedCount;

    // Verify rollback: subsequent write via RdbStore should succeed, not E_SQLITE_BUSY
    auto writeRes = store_->Execute(
        "INSERT INTO " + tableName + " (name, data) VALUES ('rb_verify', NULL)");
    EXPECT_EQ(writeRes.first, E_OK)
        << "Transaction should be rolled back, write lock released, but got errCode=" << writeRes.first;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}

/* *
 * @tc.name: Transaction_Delete_Returning_Timeout_001
 * @tc.desc: Transaction Delete matching all rows with RETURNING clause and timeout.
 * @tc.type: FUNC
 */
HWTEST_F(RdbTimeoutInterruptTest, Transaction_Delete_Returning_Timeout_001, TestSize.Level1)
{
    std::string tableName = "TransDeleteReturningTest";
    ASSERT_EQ(PrepareLargeTable(tableName, BATCH_ROW_COUNT), E_OK);

    auto [transErr, trans] = store_->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(transErr, E_OK);
    ASSERT_NE(trans, nullptr);

    AbsRdbPredicates predicates(tableName);
    predicates.GreaterThanOrEqualTo("id", "1"); // Match all rows

    DeleteConfig config;
    config.timeoutMs = 100;
    config.returning.columns = { "id", "name" };
    auto start = std::chrono::steady_clock::now();
    auto [errCode, deleteResult] = trans->Delete(predicates, config);
    auto end = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    printf("Transaction_Delete_Returning_Timeout_001: elapsed=%lldms, errCode=%d, timeoutMs=%lld\n",
        static_cast<long long>(elapsed), errCode, static_cast<long long>(config.timeoutMs));

    EXPECT_TRUE(errCode == E_SQLITE_INTERRUPT)
        << "Unexpected errCode=" << errCode;

    trans->Close();
    auto remainingCount = QueryCount("SELECT COUNT(*) FROM " + tableName);
    EXPECT_EQ(remainingCount, BATCH_ROW_COUNT)
        << "Trans Delete with RETURNING should be rolled back, remainingCount=" << remainingCount;

    // Verify rollback: subsequent write via RdbStore should succeed, not E_SQLITE_BUSY
    auto writeRes = store_->Execute(
        "INSERT INTO " + tableName + " (name, data) VALUES ('rb_verify', NULL)");
    EXPECT_EQ(writeRes.first, E_OK)
        << "Transaction should be rolled back, write lock released, but got errCode=" << writeRes.first;

    store_->Execute("DROP TABLE IF EXISTS " + tableName);
}