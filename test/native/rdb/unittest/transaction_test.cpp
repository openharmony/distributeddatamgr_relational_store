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
    rs = transaction->Rollback();
    ASSERT_EQ(rs, E_OK);
}

/**
 * @tc.name: RdbStore_Transaction_063
 * @tc.desc: normal testcase of drop the table before closing the resultSet after querying the data.
 * @tc.type: FUNC
 */
HWTEST_F(TransactionTest, RdbStore_Transaction_063, TestSize.Level1)
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
