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
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
 
using namespace testing::ext;
using namespace OHOS::NativeRdb;
 
class RdbDoubleWriteTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void CheckResultSet(std::shared_ptr<RdbStore> &store);
    void CheckAge(std::shared_ptr<ResultSet> &resultSet);
    void CheckSalary(std::shared_ptr<ResultSet> &resultSet);
    void CheckBlob(std::shared_ptr<ResultSet> &resultSet);
    void CheckNumber(std::shared_ptr<RdbStore> &store, int num);
 
    static const std::string DATABASE_NAME;
    static const std::string SLAVE_DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<RdbStore> slaveStore;
    static std::shared_ptr<RdbStore> store3;
};
 
const std::string RdbDoubleWriteTest::DATABASE_NAME = RDB_TEST_PATH + "insert_test.db";
const std::string RdbDoubleWriteTest::SLAVE_DATABASE_NAME = RDB_TEST_PATH + "insert_test_slave.db";
std::shared_ptr<RdbStore> RdbDoubleWriteTest::store = nullptr;
std::shared_ptr<RdbStore> RdbDoubleWriteTest::slaveStore = nullptr;
std::shared_ptr<RdbStore> RdbDoubleWriteTest::store3 = nullptr;
const int BLOB_SIZE = 3;
const uint8_t EXPECTED_BLOB_DATA[] {1, 2, 3};
const int CHECKAGE = 18;
const double CHECKCOLUMN = 100.5;
 
class DoubleWriteTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};
 
const std::string DoubleWriteTestOpenCallback::CREATE_TABLE_TEST =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");
 
int DoubleWriteTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}
 
int DoubleWriteTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}
 
void RdbDoubleWriteTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MASTER_SLAVER);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::store, nullptr);
 
    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::slaveStore, nullptr);
}
 
void RdbDoubleWriteTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
}
 
void RdbDoubleWriteTest::SetUp(void)
{
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
}
 
void RdbDoubleWriteTest::TearDown(void)
{
}
 
/**
 * @tc.name: RdbStore_DoubleWrite_001
 * @tc.desc: test RdbStore doubleWrite
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbDoubleWriteTest::store;
    std::shared_ptr<RdbStore> &slaveStore = RdbDoubleWriteTest::slaveStore;
 
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
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);
 
    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20L);
    values.PutDouble("salary", 100.5f);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);
 
    RdbDoubleWriteTest::CheckResultSet(slaveStore);
}
 
void RdbDoubleWriteTest::CheckResultSet(std::shared_ptr<RdbStore> &store)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    EXPECT_NE(resultSet, nullptr);
 
    int columnIndex;
    int intVal;
    std::string strVal;
    ColumnType columnType;
    int position;
    int ret = resultSet->GetRowIndex(position);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(position, -1);
 
    ret = resultSet->GetColumnType(0, columnType);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
 
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
 
    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnIndex, 0);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, intVal);
 
    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_STRING);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("zhangsan", strVal);
 
    RdbDoubleWriteTest::CheckAge(resultSet);
    RdbDoubleWriteTest::CheckSalary(resultSet);
    RdbDoubleWriteTest::CheckBlob(resultSet);
 
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
 
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
 
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}
 
void RdbDoubleWriteTest::CheckAge(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    int intVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_INTEGER);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(CHECKAGE, intVal);
}
 
void RdbDoubleWriteTest::CheckSalary(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    double dVal;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("salary", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_FLOAT);
    ret = resultSet->GetDouble(columnIndex, dVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(CHECKCOLUMN, dVal);
}
 
void RdbDoubleWriteTest::CheckBlob(std::shared_ptr<ResultSet> &resultSet)
{
    int columnIndex;
    std::vector<uint8_t> blob;
    ColumnType columnType;
    int ret = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(columnType, ColumnType::TYPE_BLOB);
    ret = resultSet->GetBlob(columnIndex, blob);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(BLOB_SIZE, static_cast<int>(blob.size()));
    for (int i = 0; i < BLOB_SIZE; i++) {
        EXPECT_EQ(EXPECTED_BLOB_DATA[i], blob[i]);
    }
}
 
void RdbDoubleWriteTest::CheckNumber(std::shared_ptr<RdbStore> &store, int num)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test;");
    EXPECT_NE(resultSet, nullptr);
    int countNum;
    int ret = resultSet->GetRowCount(countNum);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(num, countNum);
}
 
/**
 * @tc.name: RdbStore_DoubleWrite_002
 * @tc.desc: test RdbStore waL limit
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbDoubleWriteTest::store;
    std::shared_ptr<RdbStore> &slaveStore = RdbDoubleWriteTest::slaveStore;
    int64_t id = 10;
    ValuesBucket values;
    for (int i = 0; i < 25158; i++) {
        id++;
        values.Clear();
        values.PutInt("id", id);
        values.PutString("name", std::string("zhangsan"));
        values.PutInt("age", 18);
        values.PutDouble("salary", 100.5);
        values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
        int ret = store->Insert(id, "test", values);
        EXPECT_EQ(ret, E_OK);
    }
    RdbDoubleWriteTest::CheckNumber(slaveStore, 25158);
}
 
/**
 * @tc.name: RdbStore_DoubleWrite_003
 * @tc.desc: test RdbStore execute
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbDoubleWriteTest::store;
    std::shared_ptr<RdbStore> &slaveStore = RdbDoubleWriteTest::slaveStore;
 
    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 25);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    auto [ret2, outValue2] = store->Execute("UPDATE test SET age= 18 WHERE id = 1");
    EXPECT_EQ(E_OK, ret2);
    
    RdbDoubleWriteTest::CheckResultSet(slaveStore);
}
 
/**
 * @tc.name: RdbStore_DoubleWrite_004
 * @tc.desc: test RdbStore updata
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbDoubleWriteTest::store;
    std::shared_ptr<RdbStore> &slaveStore = RdbDoubleWriteTest::slaveStore;
 
    int64_t id;
 
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 25);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
 
    int changedRows;
    values.Clear();
    values.PutInt("age", 18);
    ret = store->Update(changedRows, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);
    
    RdbDoubleWriteTest::CheckResultSet(slaveStore);
}
 
/**
 * @tc.name: RdbStore_DoubleWrite_005
 * @tc.desc: test RdbStore delete
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbDoubleWriteTest::store;
    std::shared_ptr<RdbStore> &slaveStore = RdbDoubleWriteTest::slaveStore;
 
    ValuesBucket values;
    int64_t id;
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
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);
 
    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 20L);
    values.PutDouble("salary", 100.5f);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);
 
    int deletedRows;
    ret = store->Delete(deletedRows, "test", "id = 2");
    ret = store->Delete(deletedRows, "test", "id = 3");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, deletedRows);
    
    RdbDoubleWriteTest::CheckNumber(slaveStore, 1);
}