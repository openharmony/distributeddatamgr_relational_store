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
#define LOG_TAG "RdbDoubleWriteTest"
#include <gtest/gtest.h>

#include <fstream>
#include <string>

#include "logger.h"
#include "common.h"
#include "sqlite_utils.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
 
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;
 
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
    void CheckNumber(std::shared_ptr<RdbStore> &store, int num, int errCode = E_OK,
        const std::string &tableName = "test");
    void Insert(int64_t start, int count, bool isSlave = false);
    void WaitForBackupFinish(int32_t expectStatus);

    static const std::string DATABASE_NAME;
    static const std::string SLAVE_DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<RdbStore> slaveStore;
    static std::shared_ptr<RdbStore> store3;

    enum SlaveStatus : uint32_t {
        UNDEFINED,
        DB_NOT_EXITS,
        BACKING_UP,
        BACKUP_INTERRUPT,
        BACKUP_FINISHED,
    };
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
}
 
void RdbDoubleWriteTest::TearDownTestCase(void)
{
}
 
void RdbDoubleWriteTest::SetUp(void)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
}
 
void RdbDoubleWriteTest::TearDown(void)
{
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
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

void RdbDoubleWriteTest::Insert(int64_t start, int count, bool isSlave)
{
    ValuesBucket values;
    int64_t id = start;
    int ret = E_OK;
    for (int i = 0; i < count; i++) {
        values.Clear();
        values.PutInt("id", id);
        values.PutString("name", std::string("zhangsan"));
        values.PutInt("age", CHECKAGE);
        values.PutDouble("salary", CHECKCOLUMN);
        values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
        if (isSlave) {
            ret = slaveStore->Insert(id, "test", values);
        } else {
            ret = store->Insert(id, "test", values);
        }
        EXPECT_EQ(ret, E_OK);
        id++;
    }
}

void RdbDoubleWriteTest::WaitForBackupFinish(int32_t expectStatus)
{
    int32_t curStatus = store->GetBackupStatus();
    int tryTimes = 0;
    while (curStatus != expectStatus && (++tryTimes <= 5)) { // 5 is try time
        usleep(50000); // 50000 is wait time
        curStatus = store->GetBackupStatus();
    }
    LOG_INFO("----------cur backup Status:%{public}d---------", curStatus);
    ASSERT_EQ(curStatus, expectStatus);
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
 
void RdbDoubleWriteTest::CheckNumber(std::shared_ptr<RdbStore> &store, int num, int errCode,
    const std::string &tableName)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM " + tableName);
    ASSERT_NE(resultSet, nullptr);
    int countNum;
    int ret = resultSet->GetRowCount(countNum);
    EXPECT_EQ(ret, errCode);
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
        values.PutInt("age", CHECKAGE);
        values.PutDouble("salary", CHECKCOLUMN);
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
    values.PutDouble("salary", CHECKCOLUMN);
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

/**
 * @tc.name: RdbStore_DoubleWrite_007
 * @tc.desc: open SINGLE db, write, close, open MAIN_REPLICA db, check slave
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_007, TestSize.Level1)
{
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);

    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::SINGLE);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    int64_t id = 10;
    int count = 100;
    Insert(id, count);

    store = nullptr;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::store, nullptr);

    WaitForBackupFinish(BACKUP_FINISHED);

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::slaveStore, nullptr);

    RdbDoubleWriteTest::CheckNumber(RdbDoubleWriteTest::slaveStore, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_008
 * @tc.desc: open MAIN_REPLICA db, write, close, corrupt, reopen db allow rebuild, db returns to normal
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_008, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbDoubleWriteTest::store;
    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_008 insert finish");

    store = nullptr;

    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = {0x6, 0x6};
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_008 corrupt db finish");

    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetAllowRebuild(true);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);
    RebuiltType rebuiltType;
    store->GetRebuilt(rebuiltType);
    EXPECT_EQ(rebuiltType, RebuiltType::REPAIRED);
    LOG_INFO("RdbStore_DoubleWrite_008 reopen db finish");

    RdbDoubleWriteTest::CheckNumber(store, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_009
 * @tc.desc: open MAIN_REPLICA db, write, slave db has 100 more data than main db, restore, check count
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_009, TestSize.Level1)
{
    int64_t id = 10;
    Insert(id, 100);
    id = 200;
    Insert(id, 100, true);
    RdbDoubleWriteTest::CheckNumber(store, 100);
    RdbDoubleWriteTest::CheckNumber(slaveStore, 200);
    EXPECT_EQ(store->Restore(std::string(""), {}), E_OK);
    RdbDoubleWriteTest::CheckNumber(store, 200);
}

/**
 * @tc.name: RdbStore_DoubleWrite_010
 * @tc.desc: open MAIN_REPLICA db, write, close all, corrupt slave, open MAIN_REPLICA db, slave returns to normal
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_010, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbDoubleWriteTest::store;
    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_010 insert finish");

    slaveStore = nullptr;
    store = nullptr;

    std::fstream file(SLAVE_DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = {0x6, 0x6};
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_010 corrupt db finish");

    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_010 reopen main db finish");

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::slaveStore, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_010 reopen slave db finish");

    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_011
 * @tc.desc: open MAIN_REPLICA db, write, close slave, corrupt slave, backup, check slave
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_011, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbDoubleWriteTest::store;
    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_011 insert finish");

    slaveStore = nullptr;

    std::fstream file(SLAVE_DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = {0x6, 0x6};
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_011 corrupt db finish");

    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
    LOG_INFO("RdbStore_DoubleWrite_011 backup db finish");

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    int errCode;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::slaveStore, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_011 reopen slave db finish");

    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_012
 * @tc.desc: test RdbStore transaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_012, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbDoubleWriteTest::store;
    std::shared_ptr<RdbStore> &slaveStore = RdbDoubleWriteTest::slaveStore;

    int err = store->BeginTransaction();
    EXPECT_EQ(err, E_OK);
    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 25);
    values.PutDouble("salary", CHECKCOLUMN);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    auto [ret2, outValue2] = store->Execute("UPDATE test SET age= 18 WHERE id = 1");
    EXPECT_EQ(E_OK, ret2);
    err = store->Commit();
    EXPECT_EQ(err, E_OK);

    RdbDoubleWriteTest::CheckResultSet(slaveStore);
}

/**
 * @tc.name: RdbStore_DoubleWrite_013
 * @tc.desc: open MANUAL_TRIGGER db, open slave, write, slave is empty, backup, check slave, write, check slave
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_013, TestSize.Level1)
{
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);

    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_013 reopen main db finish");

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::slaveStore, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_013 reopen slave db finish");

    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_013 insert finish");

    RdbDoubleWriteTest::CheckNumber(slaveStore, 0);

    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    LOG_INFO("RdbStore_DoubleWrite_013 backup finish");

    RdbDoubleWriteTest::CheckNumber(slaveStore, count);

    id = 1000;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_013 insert finish");
    RdbDoubleWriteTest::CheckNumber(slaveStore, 200); // 200 is all count
}

/**
 * @tc.name: RdbStore_DoubleWrite_014
 * @tc.desc: open MANUAL_TRIGGER db, write, backup, open slave, check slave, write, check slave
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_014, TestSize.Level1)
{
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);

    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_014 reopen main db finish");

    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_014 insert finish");

    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    LOG_INFO("RdbStore_DoubleWrite_014 backup finish");

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::slaveStore, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_014 reopen slave db finish");

    RdbDoubleWriteTest::CheckNumber(slaveStore, count);

    id = 1000;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_014 insert finish");
    RdbDoubleWriteTest::CheckNumber(slaveStore, 200); // 200 is all count
}

/**
 * @tc.name: RdbStore_DoubleWrite_015
 * @tc.desc: open MAIN_REPLICA db, write, close, corrupt, slave create table, open MAIN_REPLICA db. check count
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_015, TestSize.Level1)
{
    int64_t id = 10;
    int count = 100;
    ValuesBucket values;
    for (int i = 0; i < count; i++) {
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
    LOG_INFO("RdbStore_DoubleWrite_015 insert finish");

    store = nullptr;

    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = {0x6, 0x6};
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_015 corrupt db finish");

    int errCode = slaveStore->ExecuteSql("CREATE TABLE IF NOT EXISTS xx (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)");
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(slaveStore->Insert(id, "xx", values), E_OK);

    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetAllowRebuild(true);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_015 reopen db finish");

    RdbDoubleWriteTest::CheckNumber(store, 1, E_OK, std::string("xx"));
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, 1, E_OK, std::string("xx"));
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_016
 * @tc.desc: open MAIN_REPLICA db, write, close, delete db file, reopen, check count
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_016, TestSize.Level1)
{
    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_016 insert finish");

    store = nullptr;

    SqliteUtils::DeleteFile(DATABASE_NAME);
    SqliteUtils::DeleteFile(DATABASE_NAME + "-shm");
    SqliteUtils::DeleteFile(DATABASE_NAME + "-wal");
    LOG_INFO("RdbStore_DoubleWrite_016 delete db file finish");

    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteTestOpenCallback helper;
    int errCode;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_016 reopen db finish");

    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_017
 * @tc.desc: open MAIN_REPLICA db, write, close, reopen, corrupt db, restore, check count
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_017, TestSize.Level1)
{
    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_017 insert finish");

    store = nullptr;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetAllowRebuild(true);
    DoubleWriteTestOpenCallback helper;
    int errCode;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_017 reopen db finish");

    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(0, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = {0x6, 0x6};
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_017 corrupt db finish");

    EXPECT_EQ(store->Restore(std::string(""), {}), E_OK);
    LOG_INFO("RdbStore_DoubleWrite_017 restore db finish");

    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
}