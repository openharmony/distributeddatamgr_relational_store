/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

class RdbExecuteTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static const std::string CREATE_TABLE_TEST;
};

const std::string RdbExecuteTest::DATABASE_NAME = RDB_TEST_PATH + "execute_test.db";
std::shared_ptr<RdbStore> RdbExecuteTest::store = nullptr;

class ExecuteTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

const std::string RdbExecuteTest::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                                      "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                      "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                      "blobType BLOB)";

int ExecuteTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int ExecuteTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbExecuteTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(RdbExecuteTest::DATABASE_NAME);
    RdbStoreConfig config(RdbExecuteTest::DATABASE_NAME);
    ExecuteTestOpenCallback helper;
    RdbExecuteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbExecuteTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbExecuteTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbExecuteTest::DATABASE_NAME);
    store = nullptr;
}

void RdbExecuteTest::SetUp(void)
{
    store->ExecuteSql(CREATE_TABLE_TEST);
}

void RdbExecuteTest::TearDown(void)
{
    store->ExecuteSql("DROP TABLE test");
}

/**
 * @tc.name: RdbStore_Execute_001
 * @tc.desc: test RdbStore Execute
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("wangyjing"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 7, 8, 9 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    ret = store->ExecuteSql("DELETE FROM test WHERE age = ? OR age = ?",
        std::vector<ValueObject>{ ValueObject(std::string("18")), ValueObject(std ::string("20")) });
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test where age = 19");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 1);

    ret = store->ExecuteSql("DELETE FROM test WHERE age = 19");
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 0);
}

/**
 * @tc.name: RdbStore_Execute_002
 * @tc.desc: test RdbStore Execute
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    int64_t id;
    ValuesBucket values;

    int ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    ret = store->Insert(id, "test", UTUtils::SetRowData(UTUtils::g_rowData[2]));
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    int64_t count;
    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test", std::vector<ValueObject>());
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 3);

    ret = store->ExecuteSql("DELETE FROM test WHERE age = ? OR age = ?",
        std::vector<ValueObject>{ ValueObject(std::string("18")), ValueObject(std ::string("20")) });
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(
        count, "SELECT COUNT(*) FROM test where age = ?", std::vector<ValueObject>{ ValueObject(std::string("19")) });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 1);

    ret = store->ExecuteSql("DELETE FROM test WHERE age = 19");
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test", std::vector<ValueObject>());
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(count, 0);

    ret = store->ExecuteSql("DROP TABLE IF EXISTS test");
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(ret, E_SQLITE_ERROR);
}

/**
 * @tc.name: RdbStore_Execute_003
 * @tc.desc: test RdbStore Execute
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    int64_t pageSize;
    int ret = store->ExecuteAndGetLong(pageSize, "PRAGMA page_size");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(pageSize, 4096);

    int64_t journalSize;
    ret = store->ExecuteAndGetLong(journalSize, "PRAGMA journal_size_limit");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(journalSize, 1048576);

    std::string journalMode;
    ret = store->ExecuteAndGetString(journalMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(journalMode, "wal");
}

/**
 * @tc.name: RdbStore_Execute_004
 * @tc.desc: Abnormal testCase for ExecuteAndGetString, if sqlstatementtype is special
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_004, TestSize.Level4)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    std::string outValue;
    int ret = store->ExecuteAndGetString(outValue, "BEGIN;");
    EXPECT_NE(E_OK, ret);
}

/**
 * @tc.name: RdbStore_Execute_005
 * @tc.desc: Abnormal testCase for ExecuteForLastInsertedRowId, if sql is invalid
 * @tc.type: FUNC
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_005, TestSize.Level4)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;
    int64_t outValue;
    int ret = store->ExecuteForLastInsertedRowId(outValue, "", {});
    EXPECT_NE(E_OK, ret);
}

/**
 * @tc.name: RdbStore_Execute_006
 * @tc.desc: Abnormal testCase for ExecuteForChangedRowCount, if sql is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_006, TestSize.Level4)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;
    int64_t outValue;
    int ret = store->ExecuteForChangedRowCount(outValue, "", {});
    EXPECT_NE(E_OK, ret);
}

/**
 * @tc.name: RdbStore_Execute_007
 * @tc.desc: Normal testCase for ExecuteAndGetString, check integrity for store
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_007, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    auto [ret, outValue] = store->Execute("PRAGMA integrity_check");
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(ValueObjectType::TYPE_STRING, outValue.GetType());

    std::string outputResult;
    outValue.GetString(outputResult);
    EXPECT_EQ("ok", outputResult);
}

/**
 * @tc.name: RdbStore_Execute_008
 * @tc.desc: Normal testCase for Execute, check integrity for store
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_008, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    auto [ret, outValue] = store->Execute("PRAGMA quick_check");
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(ValueObjectType::TYPE_STRING, outValue.GetType());

    std::string outputResult;
    outValue.GetString(outputResult);
    EXPECT_EQ("ok", outputResult);
}

/**
 * @tc.name: RdbStore_Execute_009
 * @tc.desc: Normal testCase for Execute, get user_version of store
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_009, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    // set user_version as 5
    store->SetVersion(5);
    auto [ret, outValue] = store->Execute("PRAGMA user_version");
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(ValueObjectType::TYPE_INT, outValue.GetType());

    int64_t outputResult {0};
    outValue.GetLong(outputResult);
    EXPECT_EQ(5, outputResult);

    // set user_version as 0
    store->SetVersion(0);
}

/**
 * @tc.name: RdbStore_Execute_0010
 * @tc.desc: AbNormal testCase for Execute, execute select sql
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0010, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    auto [ret, outValue] = store->Execute("SELECT * FROM test");
    EXPECT_EQ(E_NOT_SUPPORT_THE_SQL, ret);
}

/**
 * @tc.name: RdbStore_Execute_0011
 * @tc.desc: Normal testCase for Execute, execute sql for inserting data
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0011, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    std::vector<ValueObject> args = {
        ValueObject(std::string("tt")), ValueObject(int(28)), ValueObject(double(50000.0)) };
    auto [ret, outValue] = store->Execute("INSERT INTO test(name, age, salary) VALUES (?, ?, ?);", args);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(ValueObjectType::TYPE_INT, outValue.GetType());

    int64_t outputResult;
    outValue.GetLong(outputResult);
    // 1 represent that the last data is inserted in the first row
    EXPECT_EQ(1, outputResult);
}

/**
 * @tc.name: RdbStore_Execute_0012
 * @tc.desc: Normal testCase for Execute, execute sql for batch insert data
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0012, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    std::vector<ValueObject> args = { ValueObject(std::string("tt")), ValueObject(int(28)),
        ValueObject(double(50000.0)), ValueObject(std::string("ttt")), ValueObject(int(58)),
        ValueObject(double(500080.0)) };
    auto [ret, outValue] = store->Execute("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ?, ?)", args);
    EXPECT_EQ(E_OK, ret);

    EXPECT_EQ(ValueObjectType::TYPE_INT, outValue.GetType());

    int64_t outputResult;
    outValue.GetLong(outputResult);
    // 2 represent that the last data is inserted in the second row
    EXPECT_EQ(2, outputResult);
}

/**
 * @tc.name: RdbStore_Execute_0013
 * @tc.desc: Normal testCase for Execute, execute sql for updating data
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0013, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    std::vector<ValueObject> args = { ValueObject(std::string("tt")), ValueObject(int(28)),
        ValueObject(double(50000.0)), ValueObject(std::string("ttt")), ValueObject(int(58)),
        ValueObject(double(500080.0)) };
    auto [ret1, outValue1] = store->Execute("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ?, ?)", args);
    EXPECT_EQ(E_OK, ret1);
    EXPECT_EQ(ValueObjectType::TYPE_INT, outValue1.GetType());

    int64_t outputResult;
    outValue1.GetLong(outputResult);
    // 2 represent that the last data is inserted in the second row
    EXPECT_EQ(2, outputResult);

    auto [ret2, outValue2] = store->Execute("UPDATE test SET name='dd' WHERE id = 2");
    EXPECT_EQ(E_OK, ret2);
    EXPECT_EQ(ValueObjectType::TYPE_INT, outValue2.GetType());

    outValue2.GetLong(outputResult);
    // 1 represent that effected row id
    EXPECT_EQ(1, outputResult);
}

/**
 * @tc.name: RdbStore_Execute_0014
 * @tc.desc: Normal testCase for Execute, execute sql for deleting data
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0014, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    std::vector<ValueObject> args = { ValueObject(std::string("tt")), ValueObject(int(28)),
        ValueObject(double(50000.0)), ValueObject(std::string("ttt")), ValueObject(int(82)),
        ValueObject(double(500080.0)) };
    auto [ret1, outValue1] = store->Execute("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ?, ?)", args);
    EXPECT_EQ(E_OK, ret1);
    EXPECT_EQ(ValueObjectType::TYPE_INT, outValue1.GetType());

    int64_t outputResult;
    outValue1.GetLong(outputResult);
    // 2 represent that the last data is inserted in the second row
    EXPECT_EQ(2, outputResult);

    auto [ret2, outValue2] = store->Execute("DELETE FROM test");
    EXPECT_EQ(E_OK, ret2);
    EXPECT_EQ(ValueObjectType::TYPE_INT, outValue2.GetType());

    outValue2.GetLong(outputResult);
    // 2 represent that effected row id
    EXPECT_EQ(2, outputResult);
}

/**
 * @tc.name: RdbStore_Execute_0015
 * @tc.desc: AbNormal testCase for Execute, execute sql for attaching database and transaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0015, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    auto [ret1, outValue1] = store->Execute("ATTACH DATABASE 'execute_attach_test.db' AS 'attach.db'");
    EXPECT_EQ(E_NOT_SUPPORT_THE_SQL, ret1);

    auto [ret2, outValue2] = store->Execute("DETACH DATABASE 'attach.db'");
    EXPECT_EQ(E_NOT_SUPPORT_THE_SQL, ret2);

    auto [ret3, outValue3] = store->Execute("BEGIN TRANSACTION");
    EXPECT_EQ(E_NOT_SUPPORT_THE_SQL, ret3);

    auto [ret4, outValue4] = store->Execute("COMMIT");
    EXPECT_EQ(E_NOT_SUPPORT_THE_SQL, ret4);

    auto [ret5, outValue5] = store->Execute("ROLLBACK");
    EXPECT_EQ(E_NOT_SUPPORT_THE_SQL, ret5);
}

/**
 * @tc.name: RdbStore_Execute_0016
 * @tc.desc: Normal testCase for Execute, execute DDL sql for creating and dropping table
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0016, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;
    int64_t intOutValue;

    const std::string CREATE_TABLE_TEST2 = "CREATE TABLE IF NOT EXISTS test2 "
                                           "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                           "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                           "blobType BLOB)";
    const std::string DROP_TABLE_TEST2 = "DROP TABLE test2";
    const std::string TEST_TABLE_IS_EXIST = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='test2'";

    auto [ret1, outValue1] = store->Execute(CREATE_TABLE_TEST2);
    EXPECT_EQ(E_OK, ret1);
    EXPECT_EQ(ValueObjectType::TYPE_NULL, outValue1.GetType());

    std::shared_ptr<ResultSet> resultSet = store->QuerySql(TEST_TABLE_IS_EXIST);
    EXPECT_NE(nullptr, resultSet);
    resultSet->GoToFirstRow();
    // 0 represent that get count of table test in the first row
    resultSet->GetLong(0, intOutValue);
    // 1 represent that the table exists
    EXPECT_EQ(1, intOutValue);
    resultSet->Close();

    auto [ret2, outValue2] = store->Execute(DROP_TABLE_TEST2);
    EXPECT_EQ(E_OK, ret2);
    EXPECT_EQ(ValueObjectType::TYPE_NULL, outValue2.GetType());

    resultSet = store->QuerySql(TEST_TABLE_IS_EXIST);
    EXPECT_NE(nullptr, resultSet);
    resultSet->GoToFirstRow();
    // 0 represent that get count of table test in the first column
    resultSet->GetLong(0, intOutValue);
    // 0 represent the table does not exist
    EXPECT_EQ(0, intOutValue);
    resultSet->Close();
}

/**
 * @tc.name: RdbStore_Execute_0017
 * @tc.desc: Normal testCase for Execute, execute sql for creating table and insert, query data
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0017, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;
    int64_t intOutValue;
    int intOutResultSet;

    const std::string CREATE_TABLE_TEST2 = "CREATE TABLE IF NOT EXISTS test2 "
                                           "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                           "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                           "blobType BLOB)";
    const std::string DROP_TABLE_TEST2 = "DROP TABLE test2";

    auto [ret1, outValue1] = store->Execute(CREATE_TABLE_TEST2);
    EXPECT_EQ(E_OK, ret1);

    std::vector<ValueObject> args = { ValueObject("tt"), ValueObject(28), ValueObject(50000) };
    auto [ret2, outValue2] = store->Execute("INSERT INTO test2(name, age, salary) VALUES (?, ?, ?)", args);
    EXPECT_EQ(E_OK, ret2);
    outValue2.GetLong(intOutValue);
    // 1 represent that the last data is inserted in the first row
    EXPECT_EQ(1, intOutValue);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test2");
    EXPECT_NE(nullptr, resultSet);
    EXPECT_EQ(E_OK, resultSet->GetRowCount(intOutResultSet));
    // 1 represent that the row number of resultSet
    EXPECT_EQ(1, intOutResultSet);
    resultSet->Close();

    auto [ret3, outValue3] = store->Execute(DROP_TABLE_TEST2);
    EXPECT_EQ(E_OK, ret3);
}

/**
 * @tc.name: RdbStore_Execute_0018
 * @tc.desc: AbNormal testCase for Execute, execute sql for inserting data but args is []
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0018, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;
    ValueObject outValue;

    auto [ret1, outValue1] = store->Execute("INSERT INTO test(name, age, salary) VALUES (?, ?, ?), (?, ?, ?)");
    EXPECT_NE(E_OK, ret1);
}

/**
 * @tc.name: RdbStore_Execute_0019
 * @tc.desc: Normal testCase for Execute, set user_version of store
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0019, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    // set user_version as 5
    auto [ret, outValue] = store->Execute("PRAGMA user_version=5");
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(ValueObjectType::TYPE_NULL, outValue.GetType());

    // set user_version as 0
    std::tie(ret, outValue) = store->Execute("PRAGMA user_version=0");
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(ValueObjectType::TYPE_NULL, outValue.GetType());
}

/**
 * @tc.name: RdbStore_Execute_0020
 * @tc.desc: AbNormal testCase for Execute, get table_info
 * @tc.type: FUNC
 */
HWTEST_F(RdbExecuteTest, RdbStore_Execute_0020, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbExecuteTest::store;

    auto [ret, outValue] = store->Execute("PRAGMA table_info(test)");
    EXPECT_EQ(E_NOT_SUPPORT_THE_SQL, ret);
}