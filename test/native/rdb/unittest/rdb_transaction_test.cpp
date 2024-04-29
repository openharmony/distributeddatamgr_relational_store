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

#include <climits>
#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbTransactionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

const std::string RdbTransactionTest::DATABASE_NAME = RDB_TEST_PATH + "transaction_test.db";
std::shared_ptr<RdbStore> RdbTransactionTest::store = nullptr;

class TransactionTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string TransactionTestOpenCallback::CREATE_TABLE_TEST = std::string("CREATE TABLE IF NOT EXISTS test ")
                                                                   + std::string("(id INTEGER PRIMARY KEY "
                                                                                 "AUTOINCREMENT, name TEXT NOT NULL, "
                                                                                 "age INTEGER, salary REAL, blobType "
                                                                                 "BLOB)");

int TransactionTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int TransactionTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbTransactionTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(RdbTransactionTest::DATABASE_NAME);
    TransactionTestOpenCallback helper;
    RdbTransactionTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbTransactionTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbTransactionTest::TearDownTestCase(void)
{
    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbTransactionTest::DATABASE_NAME);
}

void RdbTransactionTest::SetUp(void)
{
    store->ExecuteSql("DELETE FROM test");
}

void RdbTransactionTest::TearDown(void)
{
}


/**
 * @tc.name: RdbStore_Transaction_001
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_Transaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;

    int64_t id;
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Commit();
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_Transaction_002
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_Transaction_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;

    int64_t id;
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Commit();
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_Transaction_003
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_Transaction_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;

    int64_t id;
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->RollBack();
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 0);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 0);
}


/**
 * @tc.name: RdbStore_NestedTransaction_001
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_NestedTransaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;

    int64_t id;
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);
    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);
    ret = store->Commit(); // not commit
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Commit();
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_NestedTransaction_002
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_NestedTransaction_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;

    int64_t id;
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);
    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);
    ret = store->Commit();
    EXPECT_EQ(ret, E_OK);
    ret = store->Commit(); // commit
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_NestedTransaction_003
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_NestedTransaction_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;

    int64_t id;
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);
    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);
    ret = store->Commit(); // not commit
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Commit(); // not commit
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_NestedTransaction_004
 * @tc.desc: test RdbStore BaseTransaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbTransactionTest, RdbStore_NestedTransaction_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;

    int64_t id;
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);
    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);
    ret = store->Commit(); // commit
    EXPECT_EQ(ret, E_OK);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    ret = store->Commit(); // commit
    EXPECT_EQ(ret, E_OK);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    int deletedRows;
    ret = store->Delete(deletedRows, "test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 3);
}

/**
 * @tc.name: RdbStore_BatchInsert_001
 * @tc.desc: test RdbStore BatchInsert
 * @tc.type: FUNC
 * @tc.require: issueI5GZGX
 */
HWTEST_F(RdbTransactionTest, RdbStore_BatchInsert_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;

    ValuesBucket values;

    values.PutString("name", "zhangsan");
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 100; i++) {
        valuesBuckets.push_back(values);
    }
    int64_t insertNum = 0;
    int ret = store->BatchInsert(insertNum, "test", valuesBuckets);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(100, insertNum);
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    int rowCount = 0;
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(100, rowCount);
}


/**
 * @tc.name: RdbStore_BatchInsert_002
 * @tc.desc: test RdbStore BatchInsert
 * @tc.type: FUNC
 * @tc.require: issue-I6BAX0
 */
HWTEST_F(RdbTransactionTest, RdbStore_BatchInsert_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;
    store->ExecuteSql("delete from test");
    std::string name = "zhangsan";
    int age = 18;
    double salary = 100.5;
    std::vector<uint8_t> blob = { 1, 2, 3 };
    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 100; i++) {
        ValuesBucket values;
        values.PutString("name", name);
        values.PutInt("age", age + i);
        values.PutDouble("salary", salary + i);
        values.PutBlob("blobType", blob);
        valuesBuckets.push_back(std::move(values));
    }

    int64_t number = 0;
    int error = store->BatchInsert(number, "test", valuesBuckets);
    EXPECT_EQ(E_OK, error);
    EXPECT_EQ(100, number);
    int rowCount = 0;
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(100, rowCount);
}


/**
 * @tc.name: RdbStore_BatchInsert_003
 * @tc.desc: test RdbStore BatchInsert
 * @tc.type: FUNC
 * @tc.require: issue-I6BAX0
 */
HWTEST_F(RdbTransactionTest, RdbStore_BatchInsert_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbTransactionTest::store;
    store->ExecuteSql("delete from test");

    int id = 0;
    std::string name = "zhangsan";
    int age = 18;
    double salary = 100.5;
    std::vector<uint8_t> blob = { 1, 2, 3 };
    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 100; i++) {
        RowData rowData1 = {id + i, name, age + i, salary + i, blob};
        ValuesBucket values = UTUtils::SetRowData(rowData1);
        valuesBuckets.push_back(std::move(values));
    }

    int64_t number = 0;
    int error = store->BatchInsert(number, "test", valuesBuckets);
    EXPECT_EQ(E_OK, error);
    EXPECT_EQ(100, number);

    int rowCount = 0;
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test");
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(100, rowCount);

    valuesBuckets.clear();
    for (int i = 50; i < 100; i++) {
        RowData rowData2 = {id + i, name, age + i, salary + i, blob};
        ValuesBucket values = UTUtils::SetRowData(rowData2);
        valuesBuckets.push_back(std::move(values));
    }

    number = INT_MIN;
    error = store->BatchInsert(number, "test", valuesBuckets);
    EXPECT_EQ(E_OK, error);
    EXPECT_EQ(50, number);

    resultSet = store->QuerySql("SELECT * FROM test");
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(100, rowCount);
    number = 0L;
    while (true) {
        error = resultSet->GoToNextRow();
        if (error != E_OK) {
            break;
        }
        number++;
    }
    resultSet->Close();
    EXPECT_EQ(100, number);
}