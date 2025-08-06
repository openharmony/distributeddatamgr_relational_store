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
#include <cstdlib>

#include "abs_rdb_predicates.h"
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
static const char CREATE_TABLE1_SQL[] =
    "CREATE TABLE IF NOT EXISTS test1 "
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
    ASSERT_NE(TransactionTest::store_, nullptr);
    ASSERT_EQ(errCode, E_OK);
}

void TransactionTest::TearDownTestCase()
{
    store_ = nullptr;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

void TransactionTest::SetUp()
{
    ASSERT_NE(store_, nullptr);
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
    ASSERT_EQ(transaction->Commit(), E_SQLITE_ERROR);

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
    ASSERT_EQ(transaction->Commit(), E_SQLITE_ERROR);

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
    ASSERT_EQ(transaction->Commit(), E_SQLITE_ERROR);

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
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_SQLITE_CONSTRAINT);
    ASSERT_EQ(result.second, 0);
    ASSERT_EQ(transaction->Commit(), E_SQLITE_ERROR);

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
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ABORT);
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
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_FAIL);
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
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_IGNORE);
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
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
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
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
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
    auto result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ABORT);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_FAIL);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result.first, E_SQLITE_BUSY);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
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
    auto result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ABORT);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_FAIL);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result.first, E_INVALID_ARGS);
    ASSERT_EQ(result.second, -1);
}

/**
 * @tc.name: RdbStore_Transaction_019
 * @tc.desc: Normal BatchInsert
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
    auto result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 0);
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 0);
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ABORT);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 0);
    for (int i = 0; i < 2; i++) {
        Transaction::Row row;
        row.Put("name", "Jim_batchInsert");
        rows.Put(row);
    }
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_FAIL);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 2);
    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
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

    auto [err, rows] = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]), Transaction::NO_ACTION);
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
 * @tc.desc: Abnormal testcase of BatchInsert after commit.
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
    auto result = transaction->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);

    auto res = transaction->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(res.first, E_ALREADY_CLOSED);
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

    auto res = transaction->ExecuteExt(CREATE_TABLE_SQL);
    ASSERT_EQ(res.first, E_ALREADY_CLOSED);
}

/**
 * @tc.name: RdbStore_Transaction_030
 * @tc.desc: Abnormal testcase of commit after commit and rollback.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_030, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_ALREADY_CLOSED);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: RdbStore_Transaction_031
 * @tc.desc: normal testcase of batch insert with returning 1.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_031, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);
    ValuesBuckets rows;
    for (int i = 0; i < 1; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    std::string returningField = "id";
    auto [status, result] = transaction->BatchInsert("test", rows, { returningField });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 1);
    
    int columnIndex = -1;
    ASSERT_EQ(result.results->GetColumnIndex(returningField, columnIndex), E_OK);
    int value = -1;
    result.results->GetInt(columnIndex, value);
    EXPECT_EQ(value, 0);
    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_032
 * @tc.desc: normal testcase of batch insert with returning 0.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_032, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);
    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 2);
    row.Put("name", "Jim");
    auto res = transaction->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 2);
    rows.Put(row);
    auto [status, result] = transaction->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 0);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 0);
    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_033
 * @tc.desc: normal testcase of batch insert with returning overlimit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_033, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 1025; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto [status, result] = transaction->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1025);
    int rowCount = -1;
    int maxRowCount = 1024;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, maxRowCount);
    int colIndex = -1;
    ASSERT_EQ(result.results->GetColumnIndex("id", colIndex), E_OK);
    for (size_t i = 0; i < maxRowCount; i++) {
        int value = -1;
        ASSERT_EQ(result.results->GetInt(colIndex, value), E_OK);
        EXPECT_EQ(value, i);
        if (i != maxRowCount - 1) {
            ASSERT_EQ(result.results->GoToNextRow(), E_OK);
        }
    }

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_034
 * @tc.desc: normal testcase of batch insert with not exist returning field.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_034, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto [status, result] =
        transaction->BatchInsert("test", rows, { "notExist" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_SQLITE_ERROR);
    EXPECT_EQ(result.changed, -1);
    ASSERT_EQ(result.results, nullptr);

    ret = transaction->Commit();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_035
 * @tc.desc: normal testcase of batch insert with Busy.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_035, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [res, transactionImme] = store->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(res, E_OK);
    ASSERT_NE(transactionImme, nullptr);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto [status, result] = transaction->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_SQLITE_BUSY);
    EXPECT_EQ(result.changed, -1);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 0);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_036
 * @tc.desc: normal testcase of update with returning 1.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_036, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto res = transaction->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 1);

    row.Put("name", "Bob");
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);
    auto [status, result] = transaction->Update(row, predicates, { "id" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 1);
    int columnIndex = -1;
    ASSERT_EQ(result.results->GetColumnIndex("id", columnIndex), E_OK);
    int value = -1;
    ASSERT_EQ(result.results->GetInt(columnIndex, value), E_OK);
    EXPECT_EQ(value, 1);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_037
 * @tc.desc: abnormal testcase of update with returning 0.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_037, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto res = transaction->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 1);

    row.Put("name", "Bob");
    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 2);
    auto [status, result] = transaction->Update(row, predicates, { "id" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 0);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 0);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_038
 * @tc.desc: abnormal testcase of update with returning overlimit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_038, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 1025; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto res = transaction->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(res.first, E_OK);
    EXPECT_EQ(res.second, 1025);

    ValuesBucket row;
    row.Put("name", "Tom");

    AbsRdbPredicates predicates("test");
    auto [status, result] = transaction->Update(row, predicates, { "id" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1025);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 1024);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_039
 * @tc.desc: abnormal testcase of update with returning not exist field.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_039, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 2; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto res = transaction->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(res.first, E_OK);
    EXPECT_EQ(res.second, 2);

    ValuesBucket row;
    row.Put("name", "Tom");

    AbsRdbPredicates predicates("test");
    auto [status, result] = transaction->Update(row, predicates, { "notExist" });
    EXPECT_EQ(status, E_SQLITE_ERROR);
    EXPECT_EQ(result.changed, -1);
    ASSERT_EQ(result.results, nullptr);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_040
 * @tc.desc: abnormal testcase of update with Busy.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_040, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [res, transactionImme] = store->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(res, E_OK);
    ASSERT_NE(transactionImme, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto [status, result] =
        transactionImme->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 5);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 5);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBucket row;
    row.Put("name", "Tom");
    AbsRdbPredicates predicates("test");
    std::tie(status, result) = transaction->Update(row, predicates, { "id" });
    EXPECT_EQ(status, E_SQLITE_BUSY);
    EXPECT_EQ(result.changed, -1);
    
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 0);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_041
 * @tc.desc: normal testcase of delete with returning 1.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_041, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto res = transaction->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 1);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 1);
    auto [status, result] = transaction->Delete(predicates, { "id" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 1);
    int columnIndex = -1;
    ASSERT_EQ(result.results->GetColumnIndex("id", columnIndex), E_OK);
    int value = -1;
    ASSERT_EQ(result.results->GetInt(columnIndex, value), E_OK);
    EXPECT_EQ(value, 1);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_042
 * @tc.desc: normal testcase of delete with returning 0.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_042, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    Transaction::Row row;
    row.Put("id", 1);
    row.Put("name", "Jim");
    auto res = transaction->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    ASSERT_EQ(res.second, 1);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", 2);
    auto [status, result] = transaction->Delete(predicates, { "id" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 0);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 0);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_043
 * @tc.desc: abnormal testcase of delete with returning over limit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_043, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 1025; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto [status, result] = transaction->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1025);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 1024);

    AbsRdbPredicates predicates("test");
    std::tie(status, result) = transaction->Delete(predicates, { "id" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1025);
    
    rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 1024);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_044
 * @tc.desc: abnormal testcase of delete with returning no exist field.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_044, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 2; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto [status, result] = transaction->BatchInsert("test", rows, { "id" }, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 2);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 2);

    AbsRdbPredicates predicates("test");
    std::tie(status, result) = transaction->Delete(predicates, { "noExist" });
    EXPECT_EQ(status, E_SQLITE_ERROR);
    EXPECT_EQ(result.changed, -1);
    
    ASSERT_EQ(result.results, nullptr);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_045
 * @tc.desc: normal testcase of execute with returning over limit.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_045, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    std::vector<ValueObject> args = { "tt", 28, 50000.0, "ttt", 58, 500080.0 };
    auto [status, result] =
        transaction->ExecuteExt("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ?, ?) returning name", args);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 2);
    
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 2);
    
    int columnIndex = -1;
    ASSERT_EQ(result.results->GetColumnIndex("name", columnIndex), E_OK);
    std::string value;
    ASSERT_EQ(result.results->GetString(columnIndex, value), E_OK);
    EXPECT_EQ(value, "tt");
    ASSERT_EQ(result.results->GoToNextRow(), E_OK);
    ASSERT_EQ(result.results->GetString(columnIndex, value), E_OK);
    EXPECT_EQ(value, "ttt");

    std::tie(status, result) =
        transaction->ExecuteExt("update test set name = ? where name = ? returning name", { "update", "tt" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 1);
    ASSERT_EQ(result.results->GetColumnIndex("name", columnIndex), E_OK);
    result.results->GetString(columnIndex, value);
    EXPECT_EQ(value, "update");

    std::tie(status, result) = transaction->ExecuteExt("delete from test returning name");
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 2);
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 2);
    ASSERT_EQ(result.results->GetColumnIndex("name", columnIndex), E_OK);
    ASSERT_EQ(result.results->GetString(columnIndex, value), E_OK);
    EXPECT_EQ(value, "update");
    ASSERT_EQ(result.results->GoToNextRow(), E_OK);
    ASSERT_EQ(result.results->GetString(columnIndex, value), E_OK);
    EXPECT_EQ(value, "ttt");

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_046
 * @tc.desc: abnormal testcase of execute with returning.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_046, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    std::vector<ValueObject> args = { "0", 0 };
    std::string sql = "INSERT INTO test(name, age) VALUES (?, ?)";
    for (int32_t i = 1; i < 1025; i++) {
        sql.append(", (?, ?)");
        args.push_back(std::to_string(i));
        args.push_back(i);
    }
    auto [status, result] = transaction->ExecuteExt(sql + " returning name", args);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1025);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 1024);
    int columnIndex = -1;
    ASSERT_EQ(result.results->GetColumnIndex("name", columnIndex), E_OK);
    std::string value;
    ASSERT_EQ(result.results->GetString(columnIndex, value), E_OK);
    EXPECT_EQ(value, "0");
    ASSERT_EQ(result.results->GoToRow(1000), E_OK);
    ASSERT_EQ(result.results->GetString(columnIndex, value), E_OK);
    EXPECT_EQ(value, "1000");

    std::tie(status, result) = transaction->ExecuteExt("update test set name = ? returning name", { "update" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1025);
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 1024);
    ASSERT_EQ(result.results->GetColumnIndex("name", columnIndex), E_OK);
    ASSERT_EQ(result.results->GetString(columnIndex, value), E_OK);
    EXPECT_EQ(value, "update");

    std::tie(status, result) = transaction->ExecuteExt("delete from test returning name", {});
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1025);
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 1024);
    ASSERT_EQ(result.results->GetColumnIndex("name", columnIndex), E_OK);
    ASSERT_EQ(result.results->GetString(columnIndex, value), E_OK);
    EXPECT_EQ(value, "update");

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_047
 * @tc.desc: normal testcase of execute with returning 0 rows.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_047, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    std::vector<ValueObject> args = { 1, "tt", 28, 50000.0 };
    auto [status, result] =
        transaction->ExecuteExt("INSERT INTO test(id, name, age, salary) VALUES (?, ?, ?, ?) returning id", args);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 1);
    int columnIndex = -1;
    ASSERT_EQ(result.results->GetColumnIndex("id", columnIndex), E_OK);
    int64_t value;
    ASSERT_EQ(result.results->GetLong(columnIndex, value), E_OK);
    EXPECT_EQ(value, 1);
    std::tie(status, result) =
        transaction->ExecuteExt("INSERT INTO test(id, name, age, salary) VALUES (?, ?, ?, ?) returning id", args);
    EXPECT_EQ(status, E_SQLITE_CONSTRAINT);
    EXPECT_EQ(result.changed, 0);
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 0);

    std::tie(status, result) =
        transaction->ExecuteExt("update test set name = ? where name = ? returning name", { "update", "noExist" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 0);
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 0);

    std::tie(status, result) = transaction->ExecuteExt("delete from test where name = ? returning name", { "noExist" });
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 0);
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 0);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_048
 * @tc.desc: abnormal testcase of execute busy with returning.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_048, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [res, immeTrans] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(res, E_OK);
    ASSERT_NE(immeTrans, nullptr);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    std::vector<ValueObject> args = { 1, "tt", 28, 50000.0 };
    auto [status, result] =
        transaction->ExecuteExt("INSERT INTO test(id, name, age, salary) VALUES (?, ?, ?, ?) returning id", args);
    EXPECT_EQ(status, E_SQLITE_BUSY);
    EXPECT_EQ(result.changed, -1);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 0);

    std::tie(status, result) =
        transaction->ExecuteExt("update test set name = ? where name = ? returning name", { "update", "noExist" });
    EXPECT_EQ(status, E_SQLITE_BUSY);
    EXPECT_EQ(result.changed, -1);
    rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 0);


    std::tie(status, result) = transaction->ExecuteExt("delete from test where name = ? returning name", { "noExist" });
    EXPECT_EQ(status, E_SQLITE_BUSY);
    EXPECT_EQ(result.changed, -1);
    rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 0);

    ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_049
 * @tc.desc: Crash Occurs When Test Commit Fails
 *           This test case constructs a transaction commit failure scenario.
 *           A special command is used to operate the database file.
 *           To avoid affecting other test cases, this test case uses an independent database file.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_049, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "transaction049_test.db";
    RdbHelper::DeleteRdbStore(dbPath);
    RdbStoreConfig config(dbPath);
    config.SetHaMode(HAMode::MAIN_REPLICA); // Dual-write must be enabled.
    config.SetReadOnly(false);
    TransactionTestOpenCallback helper;
    int errCode = E_OK;
    const int version = 1;
    std::shared_ptr<RdbStore> storePtr = RdbHelper::GetRdbStore(config, version, helper, errCode);
    EXPECT_NE(storePtr, nullptr);
    EXPECT_EQ(errCode, E_OK);

    storePtr->Execute("DROP TABLE IF EXISTS test1");
    auto res = storePtr->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = storePtr->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    const int idValue = 1;
    Transaction::Row row;
    row.Put("id", idValue);
    row.Put("name", "Jim");
    auto result = transaction->Insert("test1", row);
    ASSERT_EQ(result.first, E_OK);
    const int count = 1;
    ASSERT_EQ(result.second, count);

    // Constructing a Commit Failure Scenario
    std::string walFile = dbPath + "-wal";

    // Disabling wal File Operations
    std::string chattrAddiCmd = "chattr +i " + walFile;
    system(chattrAddiCmd.c_str());

    ret = transaction->Commit();
    EXPECT_NE(ret, E_OK);

    // Enable the wal file operation.
    std::string chattrSubiCmd = "chattr -i " + walFile;
    system(chattrSubiCmd.c_str());

    RdbHelper::DeleteRdbStore(dbPath);
}

/**
 * @tc.name: RdbStore_Transaction_050
 * @tc.desc: abnormal testcase of trigger delete with returning in trans.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_050, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [res, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(res, E_OK);
    ASSERT_NE(transaction, nullptr);
    
    auto [code, result1] = transaction->Execute(
        "CREATE TRIGGER before_update BEFORE UPDATE ON test"
        " BEGIN DELETE FROM test WHERE name = 'wang'; END");
    EXPECT_EQ(code, E_OK);

    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 200);
    row.Put("name", "wang");
    rows.Put(std::move(row));
    row.Put("id", 201);
    row.Put("name", "zhang");
    rows.Put(std::move(row));

    auto [status, result] =
        transaction->BatchInsert("test", rows, { "name" }, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 2);
    ASSERT_NE(result.results, nullptr);

    auto predicates = AbsRdbPredicates("test");
    predicates.EqualTo("name", "zhang");
    ValuesBucket values;
    values.PutString("name", "liu");

    std::tie(status, result) = transaction->Update(values, predicates, { "name" });

    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 1);
    int columnIndex = -1;
    ASSERT_EQ(result.results->GetColumnIndex("name", columnIndex), E_OK);
    std::string value;
    ASSERT_EQ(result.results->GetString(columnIndex, value), E_OK);
    EXPECT_EQ(value, "liu");

    // Check the trigger effect
    auto resultSet = transaction->QueryByStep("SELECT * FROM test");

    rowCount = -1;
    resultSet->GetRowCount(rowCount);
    ASSERT_EQ(rowCount, 1);

    transaction->Execute("DROP TRIGGER IF EXISTS before_update");

    int ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_051
 * @tc.desc: abnormal testcase of trigger update with returning in trans.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_051, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [res, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(res, E_OK);
    ASSERT_NE(transaction, nullptr);
    
    auto [code, result1] = transaction->Execute(
        "CREATE TRIGGER before_delete BEFORE DELETE ON test"
        " BEGIN UPDATE test SET name = 'li' WHERE name = 'zhao'; END");
    EXPECT_EQ(code, E_OK);

    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("id", 201);
    row.Put("name", "zhang");
    rows.Put(std::move(row));
    row.Put("id", 202);
    row.Put("name", "zhao");
    rows.Put(std::move(row));

    auto [status, result] =
        transaction->BatchInsert("test", rows, { "name" }, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 2);
    ASSERT_NE(result.results, nullptr);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("name", "zhang");
    std::tie(status, result) = transaction->Delete(predicates, { "name" });

    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    ASSERT_EQ(rowCount, 1);
    std::string value;
    ASSERT_EQ(result.results->GetString(0, value), E_OK);
    EXPECT_EQ(value, "zhang");

    // Check the trigger effect
    AbsRdbPredicates predicates1("test");
    predicates1.EqualTo("id", 202);
    auto [queryResult, queryStatus] = transaction->QueryByStep("select name from test where id = 202");

    rowCount = -1;
    queryResult->GetRowCount(rowCount);
    ASSERT_EQ(rowCount, 1);
    ASSERT_EQ(queryResult->GoToNextRow(), E_OK);

    value.clear();
    EXPECT_EQ(E_OK, queryResult->GetString(0, value));
    EXPECT_EQ(value, "li");

    transaction->Execute("DROP TRIGGER IF EXISTS before_update");

    int ret = transaction->Rollback();
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_052
 * @tc.desc: abnormal testcase of virtual table with returning in transaction.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_052, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;
    auto [createTableStatus, createTableresult] =
        store->Execute("CREATE VIRTUAL TABLE IF NOT EXISTS articles USING fts5(title, content);");

    auto [res, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(res, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    ValuesBucket row;
    row.Put("title", "fts5");
    row.Put("content", "test virtual tables");
    rows.Put(std::move(row));
    auto [status, result] =
        transaction->BatchInsert("articles", rows, {"title"}, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(status, E_OK);
    EXPECT_EQ(result.changed, 1);
    ASSERT_NE(result.results, nullptr);
    int rowCount = -1;
    ASSERT_EQ(result.results->GetRowCount(rowCount), E_OK);
    EXPECT_EQ(rowCount, 1);
    RowEntity rowEntity;
    EXPECT_EQ(result.results->GetRow(rowEntity), E_OK);
    EXPECT_EQ(std::string(rowEntity.Get("title")), "fts5");

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("title", "fts5");
    ValuesBucket values;
    values.PutString("title", "fts5 updated");

    std::tie(status, result) = transaction->Update(values, predicates, { "title" });
    // UPDATE RETURNING is not available on virtual tables
    EXPECT_EQ(status, E_SQLITE_ERROR);
    EXPECT_EQ(result.changed, -1);
    EXPECT_EQ(result.results, nullptr);

    std::tie(status, result) = store_->Delete(predicates, { "title" });
    // DELETE RETURNING is not available on virtual tables
    EXPECT_EQ(status, E_SQLITE_ERROR);
    EXPECT_EQ(result.changed, -1);
    
    transaction->Execute("Drop TABLE articles");
    EXPECT_EQ(transaction->Rollback(), E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_053
 * @tc.desc: abnormal testcase of drop the table before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_053, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    ValuesBucket row;
    row.Put("name", "Jim");
    auto res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    int rowCount = 0;
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    auto [rs, obj] = transaction->Execute("DROP TABLE test");
    ASSERT_EQ(rs, E_SQLITE_LOCKED);

    rs = resultSet->Close();
    ASSERT_EQ(rs, E_OK);
    rs = transaction->Rollback();
    ASSERT_EQ(rs, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_054
 * @tc.desc: abnormal testcase of drop the table before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_054, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    ValuesBucket row;
    row.Put("name", "Jim");
    auto res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    int rowCount = 0;
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount - 1; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    auto [rs, obj] = transaction->Execute("DROP TABLE test");
    ASSERT_EQ(rs, E_SQLITE_LOCKED);

    rs = resultSet->Close();
    ASSERT_EQ(rs, E_OK);
    rs = transaction->Rollback();
    ASSERT_EQ(rs, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_055
 * @tc.desc: normal testcase of drop the table after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_055, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [rt, object] = store->Execute(CREATE_TABLE1_SQL);
    ASSERT_EQ(rt, E_OK);

    ValuesBucket row;
    row.Put("name", "Jim");
    auto res = store->Insert("test1", row);
    ASSERT_EQ(res.first, E_OK);
    res = store->Insert("test1", row);
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test1");
    int rowCount = 0;
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    ret = resultSet->Close();
    ASSERT_EQ(ret, E_OK);

    auto [rs, obj] = transaction->Execute("DROP TABLE test1");
    ASSERT_EQ(rs, E_OK);

    rs = transaction->Commit();
    ASSERT_EQ(rs, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_056
 * @tc.desc: abnormal testcase of drop the index before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_056, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [rt, object] = store->Execute("CREATE INDEX test_index ON test(age)");
    ASSERT_EQ(rt, E_OK);

    ValuesBucket row;
    row.Put("name", "Jim");
    auto res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    int rowCount = 0;
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    auto [rs, obj] = transaction->Execute("DROP INDEX test_index");
    ASSERT_EQ(rs, E_SQLITE_LOCKED);

    rs = resultSet->Close();
    ASSERT_EQ(rs, E_OK);
    rs = transaction->Rollback();
    ASSERT_EQ(rs, E_OK);

    std::tie(rt, object) = store->Execute("DROP INDEX test_index");
    ASSERT_EQ(rt, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_057
 * @tc.desc: abnormal testcase of drop the index before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_057, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [rt, object] = store->Execute("CREATE INDEX test_index ON test(age)");
    ASSERT_EQ(rt, E_OK);

    ValuesBucket row;
    row.Put("name", "Jim");
    auto res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    int rowCount = 0;
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount - 1; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    auto [rs, obj] = transaction->Execute("DROP INDEX test_index");
    ASSERT_EQ(rs, E_SQLITE_LOCKED);

    rs = resultSet->Close();
    ASSERT_EQ(rs, E_OK);
    rs = transaction->Rollback();
    ASSERT_EQ(rs, E_OK);

    std::tie(rt, object) = store->Execute("DROP INDEX test_index");
    ASSERT_EQ(rt, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_058
 * @tc.desc: normal testcase of drop the index after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_058, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [rt, object] = store->Execute("CREATE INDEX test_index ON test(age)");
    ASSERT_EQ(rt, E_OK);

    ValuesBucket row;
    row.Put("name", "Jim");
    auto res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    int rowCount = 0;
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    ret = resultSet->Close();
    ASSERT_EQ(ret, E_OK);

    auto [rs, obj] = transaction->Execute("DROP INDEX test_index");
    ASSERT_EQ(rs, E_OK);

    rs = transaction->Commit();
    ASSERT_EQ(rs, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_059
 * @tc.desc: normal testcase of drop the table after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_059, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [rt, object] = store->Execute(CREATE_TABLE1_SQL);
    ASSERT_EQ(rt, E_OK);

    auto [res, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(res, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test1");
    int rowCount = 0;
    auto ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    auto [rs, obj] = transaction->Execute("DROP TABLE test1");
    ASSERT_EQ(rs, E_OK);

    rs = resultSet->Close();
    ASSERT_EQ(rs, E_OK);

    rs = transaction->Commit();
    ASSERT_EQ(rs, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_060
 * @tc.desc: normal testcase of drop the index after querying the data and closing the resultSet.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_060, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [rt, object] = store->Execute("CREATE INDEX test_index ON test(age)");
    ASSERT_EQ(rt, E_OK);

    auto [res, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(res, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    int rowCount = 0;
    auto ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    auto [rs, obj] = transaction->Execute("DROP INDEX test_index");
    ASSERT_EQ(rs, E_OK);

    rs = resultSet->Close();
    ASSERT_EQ(rs, E_OK);

    rs = transaction->Commit();
    ASSERT_EQ(rs, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_061
 * @tc.desc: abnormal testcase of drop the table before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_061, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    auto [rt, object] = store->Execute(CREATE_TABLE1_SQL);
    ASSERT_EQ(rt, E_OK);

    ValuesBucket row;
    row.Put("name", "Jim");
    auto res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    int rowCount = 0;
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    auto [rs, obj] = transaction->Execute("DROP TABLE test1");
    ASSERT_EQ(rs, E_SQLITE_LOCKED);

    rs = resultSet->Close();
    ASSERT_EQ(rs, E_OK);
    rs = transaction->Rollback();
    ASSERT_EQ(rs, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_062
 * @tc.desc: abnormal testcase of drop the table before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_062, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    ValuesBucket row;
    row.Put("name", "Jim");
    auto res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");

    auto [rs, obj] = transaction->Execute("DROP TABLE test");
    ASSERT_EQ(rs, E_OK);

    rs = resultSet->Close();
    ASSERT_EQ(rs, E_OK);
    rs = transaction->Commit();
    ASSERT_EQ(rs, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_054
 * @tc.desc: normal testcase of drop the table before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_054, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = TransactionTest::store_;

    ValuesBucket row;
    row.Put("name", "Jim");
    auto res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);
    res = store->Insert("test", row);
    ASSERT_EQ(res.first, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    int rowCount = 0;
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    for (int i = 0; i < rowCount; i++) {
        ret = resultSet->GoToNextRow();
        ASSERT_EQ(ret, E_OK);
    }

    ret = resultSet->GoToNextRow();
    ASSERT_NE(ret, E_OK);

    auto [rs, obj] = transaction->Execute("DROP TABLE test");
    ASSERT_EQ(rs, E_OK);

    rs = resultSet->Close();
    ASSERT_EQ(rs, E_OK);
    rs = transaction->Rollback();
    ASSERT_EQ(rs, E_OK);
}
