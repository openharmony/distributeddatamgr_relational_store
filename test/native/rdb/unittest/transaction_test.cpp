/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

static const std::string DATABASE_NAME = RDB_TEST_PATH + "transaction_test.db";
static const char CREATE_TABLE_SQL[] =
    "CREATE TABLE IF NOT EXISTS test "
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";

class TransactionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static inline std::shared_ptr<RdbStore> store_;

    class TransactionTestOpenCallback : public RdbOpenCallback {
    public:
        int OnCreate(RdbStore &store) override;
        int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    };
};

int TransactionTest::TransactionTestOpenCallback::OnCreate(RdbStore &store)
{
    auto [ret, value] = store.Execute(CREATE_TABLE_SQL);
    return ret;
}

int TransactionTest::TransactionTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void TransactionTest::SetUpTestCase()
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(DATABASE_NAME);
    TransactionTestOpenCallback helper;
    TransactionTest::store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(TransactionTest::store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void TransactionTest::TearDownTestCase()
{
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

void TransactionTest::SetUp()
{
    store_->Execute("DELETE FROM test");
}

void TransactionTest::TearDown()
{
}

/**
 * @tc.name: RdbStore_Transaction_001
 * @tc.desc: createTransaction and commit
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(1, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(2, result.second);

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 2);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    ValueObject value;
    ret = resultSet->Get(0, value);
    ASSERT_EQ(ret, E_ALREADY_CLOSED);

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(3, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);

    resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 3);
}

/**
 * @tc.name: RdbStore_Transaction_002
 * @tc.desc: createTransaction and rollback
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(1, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(2, result.second);

    ret = transaction->Rollback();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 0);

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(3, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);

    resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 1);
}

/**
 * @tc.name: RdbStore_Transaction_003
 * @tc.desc: batchInsert
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Rows rows{
        UTUtils::SetRowData(UTUtils::g_rowData[0]),
        UTUtils::SetRowData(UTUtils::g_rowData[1]),
        UTUtils::SetRowData(UTUtils::g_rowData[2]),
    };
    auto result = transaction->BatchInsert("test", rows);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 3);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 3);
}

/**
 * @tc.name: RdbStore_Transaction_004
 * @tc.desc: batchInsert
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::RefRows rows;
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[0]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[1]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[2]));

    auto result = transaction->BatchInsert("test", rows);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 3);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 3);
}

/**
 * @tc.name: RdbStore_Transaction_005
 * @tc.desc: Update
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    result = transaction->Update("test", UTUtils::SetRowData(UTUtils::g_rowData[1]), "id=1");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
    ret = resultSet->GoToFirstRow();
    ASSERT_EQ(ret, E_OK);
    int32_t columnIndex{};
    ret = resultSet->GetColumnIndex("id", columnIndex);
    ASSERT_EQ(ret, E_OK);
    int32_t id{};
    ret = resultSet->GetInt(columnIndex, id);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(id, 2);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", ValueObject(2));
    result = transaction->Update(UTUtils::SetRowData(UTUtils::g_rowData[2]), predicates);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
    ret = resultSet->GoToFirstRow();
    ASSERT_EQ(ret, E_OK);
    resultSet->GetColumnIndex("id", columnIndex);
    ret = resultSet->GetInt(columnIndex, id);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 3);
}

/**
 * @tc.name: RdbStore_Transaction_006
 * @tc.desc: Delete
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::RefRows rows;
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[0]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[1]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[2]));

    auto result = transaction->BatchInsert("test", rows);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 3);

    result = transaction->Delete("test", "id=1");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", ValueObject(2));
    result = transaction->Delete(predicates);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
    ret = resultSet->GoToFirstRow();
    ASSERT_EQ(ret, E_OK);
    int32_t columnIndex{};
    resultSet->GetColumnIndex("id", columnIndex);
    int32_t id{};
    ret = resultSet->GetInt(columnIndex, id);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 3);
}

/**
 * @tc.name: RdbStore_Transaction_007
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_007, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 1);
}

/**
 * @tc.name: RdbStore_Transaction_008
 * @tc.desc: Insert with ConflictResolution::ON_CONFLICT_ROLLBACK
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_008, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    result = transaction->Insert("test1", row, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_SQLITE_CONSTRAINT);
    ASSERT_EQ(result.second, -1);
    ASSERT_EQ(transaction->Commit(), E_ALREADY_CLOSED);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 0);
}

/**
 * @tc.name: RdbStore_Transaction_009
 * @tc.desc: Update with ConflictResolution::ON_CONFLICT_ROLLBACK
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_009, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    row.Put("name", ValueObject());
    result = transaction->Update(
        "test1", row, "id = ?", std::vector<ValueObject>{ "1" }, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_SQLITE_CONSTRAINT);
    ASSERT_EQ(result.second, 0);
    ASSERT_EQ(transaction->Commit(), E_ALREADY_CLOSED);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 0);
}

/**
 * @tc.name: RdbStore_Transaction_010
 * @tc.desc: Update with ConflictResolution::ON_CONFLICT_ROLLBACK
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_010, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    row.Put("name", ValueObject());
    AbsRdbPredicates predicates("test1");
    predicates.EqualTo("id", 1);
    result = transaction->Update(row, predicates, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_SQLITE_CONSTRAINT);
    ASSERT_EQ(result.second, 0);
    ASSERT_EQ(transaction->Commit(), E_ALREADY_CLOSED);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 0);
}

/**
 * @tc.name: RdbStore_Transaction_011
 * @tc.desc: BatchInsert with ConflictResolution::ON_CONFLICT_ROLLBACK
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_011, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    Transaction::Row row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_SQLITE_CONSTRAINT);
    ASSERT_EQ(result.second, 0);
    ASSERT_EQ(transaction->Commit(), E_ALREADY_CLOSED);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 0);
}

/**
 * @tc.name: RdbStore_Transaction_012
 * @tc.desc: BatchInsert with ConflictResolution::ON_CONFLICT_ABORT
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_012, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    Transaction::Row row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_ABORT);
    ASSERT_EQ(result.first, E_SQLITE_CONSTRAINT);
    ASSERT_EQ(result.second, 0);
    ASSERT_EQ(transaction->Commit(), E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 1);
}

/**
 * @tc.name: RdbStore_Transaction_013
 * @tc.desc: BatchInsert with ConflictResolution::ON_CONFLICT_FAIL
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_013, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    Transaction::Row row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_FAIL);
    ASSERT_EQ(result.first, E_SQLITE_CONSTRAINT);
    ASSERT_EQ(result.second, 2);
    ASSERT_EQ(transaction->Commit(), E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 3);
}

/**
 * @tc.name: RdbStore_Transaction_014
 * @tc.desc: BatchInsert with ConflictResolution::ON_CONFLICT_IGNORE
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_014, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim_batchInsert");
        rows.Put(row);
    }
    Transaction::Row row;
    row.Put("id", 2);
    row.Put("name", "Jim_insert");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 4);
    ASSERT_EQ(transaction->Commit(), E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 5);
    resultSet = store->QueryByStep("SELECT * FROM test1 where id = 2");
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    int columnIndex = -1;
    ASSERT_EQ(resultSet->GetColumnIndex("name", columnIndex), E_OK);
    std::string name;
    EXPECT_EQ(resultSet->GetString(columnIndex, name), E_OK);
    EXPECT_EQ(name, "Jim_insert");
}

/**
 * @tc.name: RdbStore_Transaction_015
 * @tc.desc: BatchInsert with ConflictResolution::ON_CONFLICT_REPLACE
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_015, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim_batchInsert");
        rows.Put(row);
    }
    Transaction::Row row;
    row.Put("id", 2);
    row.Put("name", "Jim_insert");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 5);
    ASSERT_EQ(transaction->Commit(), E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 5);
    resultSet = store->QueryByStep("SELECT * FROM test1 where id = 2");
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    int columnIndex = -1;
    ASSERT_EQ(resultSet->GetColumnIndex("name", columnIndex), E_OK);
    std::string name;
    EXPECT_EQ(resultSet->GetString(columnIndex, name), E_OK);
    EXPECT_EQ(name, "Jim_batchInsert");
}

/**
 * @tc.name: RdbStore_Transaction_016
 * @tc.desc: BatchInsert with ConflictResolution::ON_CONFLICT_REPLACE and failed
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_016, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", i == 2 ? ValueObject() : "Jim_batchInsert");
        rows.Put(row);
    }
    Transaction::Row row;
    row.Put("id", 2);
    row.Put("name", "Jim_insert");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    // ON_CONFLICT_REPLACE is equivalent to ON_CONFLICT_ABORT after failure
    ASSERT_EQ(result.first, E_SQLITE_CONSTRAINT);
    ASSERT_EQ(result.second, 0);
    ASSERT_EQ(transaction->Commit(), E_OK);

    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    ASSERT_EQ(resultSet->GoToFirstRow(), E_OK);
    int columnIndex = -1;
    ASSERT_EQ(resultSet->GetColumnIndex("name", columnIndex), E_OK);
    std::string name;
    EXPECT_EQ(resultSet->GetString(columnIndex, name), E_OK);
    EXPECT_EQ(name, "Jim_insert");
}

/**
 * @tc.name: RdbStore_Transaction_017
 * @tc.desc: BatchInsert when busy
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_017, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret1, transaction1] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret1, E_OK);
    ASSERT_NE(transaction1, nullptr);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim_batchInsert");
        rows.Put(row);
    }
    auto result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_ABORT);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_FAIL);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);
}

/**
 * @tc.name: RdbStore_Transaction_018
 * @tc.desc: BatchInsert when over limit rows
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_018, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    //sqlite default max param number
    int32_t maxNumber = 32766;
    int32_t maxRows = maxNumber / 2 + 1;
    ValuesBuckets rows;
    for (int32_t i = 0; i < maxRows; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim_batchInsert");
        rows.Put(row);
    }
    auto result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_ABORT);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_FAIL);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);
}

/**
 * @tc.name: RdbStore_Transaction_019
 * @tc.desc: Normal BatchInsertWithConflictResolution
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_019, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    auto result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 0);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 0);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_ABORT);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 0);
    for (int i = 0; i < 2; i++) {
        Transaction::Row row;
        row.Put("name", "Jim_batchInsert");
        rows.Put(row);
    }
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_FAIL);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsertWithConflictResolution("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);

    ASSERT_EQ(transaction->Commit(), E_OK);
    auto resultSet = store->QueryByStep("SELECT * FROM test1");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 6);
}

/**
 * @tc.name: RdbStore_Transaction_020
 * @tc.desc: After executing the ddl statement, the transaction links cached in the history need to be cleared.
 * Continuing to use the old connections will result in errors due to changes in the table structure.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_020, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test", row);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);
    transaction = nullptr;

    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute(
        "CREATE TABLE IF NOT EXISTS test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    // After creating the table, the links will be cleared, and creating a new transaction will create a new connection,
    // ensuring that the transaction operation does not report errors.
    std::tie(ret, transaction) = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowCount, 1);
}

/**
 * @tc.name: RdbStore_Transaction_021
 * @tc.desc: Abnormal testcase of Insert after commit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_021, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    auto [err, rows] = transaction->Insert(
        "test", UTUtils::SetRowData(UTUtils::g_rowData[0]), Transaction::NO_ACTION);
    EXPECT_EQ(err, E_ALREADY_CLOSED);
}

/**
 * @tc.name: RdbStore_Transaction_022
 * @tc.desc: Abnormal testcase of BatchInsert after commit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_022, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    Transaction::Rows rows{
        UTUtils::SetRowData(UTUtils::g_rowData[0]),
        UTUtils::SetRowData(UTUtils::g_rowData[1]),
        UTUtils::SetRowData(UTUtils::g_rowData[2]),
    };
    auto result = transaction->BatchInsert("test", rows);
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);
    ASSERT_EQ(result.second, -1);
}

/**
 * @tc.name: RdbStore_Transaction_023
 * @tc.desc: Abnormal testcase of BatchInsert after commit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_023, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    Transaction::RefRows rows;
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[0]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[1]));
    rows.Put(UTUtils::SetRowData(UTUtils::g_rowData[2]));
    auto result = transaction->BatchInsert("test", rows);
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);
    ASSERT_EQ(result.second, -1);
}

/**
 * @tc.name: RdbStore_Transaction_024
 * @tc.desc: Abnormal testcase of BatchInsertWithConflictResolution after commit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_024, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto result = transaction->BatchInsertWithConflictResolution(
        "test", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);
}

/**
 * @tc.name: RdbStore_Transaction_025
 * @tc.desc: Abnormal testcase of Update after commit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_025, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    auto result = transaction->Update("test", UTUtils::SetRowData(UTUtils::g_rowData[1]), "id=1");
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);
}

/**
 * @tc.name: RdbStore_Transaction_026
 * @tc.desc: Abnormal testcase of Update after commit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_026, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", ValueObject(2));
    auto result = transaction->Update(UTUtils::SetRowData(UTUtils::g_rowData[2]), predicates);
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);
}

/**
 * @tc.name: RdbStore_Transaction_027
 * @tc.desc: Abnormal testcase of Delete after commit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_027, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    auto result = transaction->Delete("test", "id=1");
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);
    ASSERT_EQ(result.second, -1);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", ValueObject(2));
    result = transaction->Delete(predicates);
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);
    ASSERT_EQ(result.second, -1);
}

/**
 * @tc.name: RdbStore_Transaction_028
 * @tc.desc: Abnormal testcase of QueryByStep after commit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_028, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    auto result = transaction->QueryByStep("SELECT * FROM test");
    ASSERT_EQ(result, nullptr);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", ValueObject(2));
    result = transaction->QueryByStep(predicates);
    ASSERT_EQ(result, nullptr);
}

/**
 * @tc.name: RdbStore_Transaction_029
 * @tc.desc: Abnormal testcase of QueryByStep after commit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_029, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    auto result = transaction->Execute(CREATE_TABLE_SQL);
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);
}