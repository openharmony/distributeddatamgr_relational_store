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
#include <sys/stat.h>
#include <sqlite3sym.h>
#include <unistd.h>

#include <fstream>
#include <string>

#include "common.h"
#include "file_ex.h"
#include "grd_api_manager.h"
#include "logger.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_security_manager.h"
#ifndef CROSS_PLATFORM
#include "relational/relational_store_sqlite_ext.h"
#endif
#include "sqlite_connection.h"
#include "sqlite_utils.h"
#include "sys/types.h"

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
    void CheckNumber(
        std::shared_ptr<RdbStore> &store, int num, int errCode = E_OK, const std::string &tableName = "test");
    void Insert(int64_t start, int count, bool isSlave = false, int dataSize = 0);
    void WaitForBackupFinish(int32_t expectStatus, int maxTimes = 400);
    void WaitForAsyncRepairFinish(int maxTimes = 400);
    void TryInterruptBackup();
    void InitDb(HAMode mode = HAMode::MAIN_REPLICA);

    static const std::string DATABASE_NAME;
    static const std::string SLAVE_DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<RdbStore> slaveStore;
    static std::shared_ptr<RdbStore> store3;
    static const struct sqlite3_api_routines_hw *originalHwApi;
    static struct sqlite3_api_routines_hw mockHwApi;
#ifndef CROSS_PLATFORM
    static const struct sqlite3_api_routines_relational *originalKvApi;
    static struct sqlite3_api_routines_relational mockKvApi;
#endif

    enum SlaveStatus : uint32_t {
        UNDEFINED,
        DB_NOT_EXITS,
        BACKING_UP,
        BACKUP_INTERRUPT,
        BACKUP_FINISHED,
    };
};

const std::string RdbDoubleWriteTest::DATABASE_NAME = RDB_TEST_PATH + "dual_write_test.db";
const std::string RdbDoubleWriteTest::SLAVE_DATABASE_NAME = RDB_TEST_PATH + "dual_write_test_slave.db";
std::shared_ptr<RdbStore> RdbDoubleWriteTest::store = nullptr;
std::shared_ptr<RdbStore> RdbDoubleWriteTest::slaveStore = nullptr;
std::shared_ptr<RdbStore> RdbDoubleWriteTest::store3 = nullptr;
const struct sqlite3_api_routines_hw *RdbDoubleWriteTest::originalHwApi = sqlite3_export_hw_symbols;
struct sqlite3_api_routines_hw RdbDoubleWriteTest::mockHwApi = *sqlite3_export_hw_symbols;
#ifndef CROSS_PLATFORM
const struct sqlite3_api_routines_relational *RdbDoubleWriteTest::originalKvApi = sqlite3_export_relational_symbols;
struct sqlite3_api_routines_relational RdbDoubleWriteTest::mockKvApi = *sqlite3_export_relational_symbols;
#endif
const int BLOB_SIZE = 3;
const uint8_t EXPECTED_BLOB_DATA[]{ 1, 2, 3 };
const int CHECKAGE = 18;
const double CHECKCOLUMN = 100.5;
const int HUGE_DATA_SIZE = 6 * 1024 * 1024; // 1MB

class DoubleWriteTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    int OnOpen(RdbStore &rdbStore) override;
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

int DoubleWriteTestOpenCallback::OnOpen(RdbStore &rdbStore)
{
    int version = 0;
    rdbStore.GetVersion(version);
    EXPECT_TRUE(version > -1);
    return E_OK;
}

static int MockNotSupportBinlog(void)
{
    return SQLITE_ERROR;
}

static int MockSupportBinlog(void)
{
    return SQLITE_OK;
}

#ifndef CROSS_PLATFORM
static int MockNotSupportBinlogWithParam(const char *name)
{
    return SQLITE_ERROR;
}

static int MockSupportBinlogWithParam(const char *name)
{
    return SQLITE_OK;
}
#endif
static int MockReplayBinlog(sqlite3 *srcDb, sqlite3 *destDb)
{
    return SQLITE_OK;
}

static int MockCleanBinlog(sqlite3 *db, BinlogFileCleanModeE mode)
{
    return SQLITE_OK;
}

void RdbDoubleWriteTest::SetUpTestCase(void)
{
    mockHwApi.is_support_binlog = MockNotSupportBinlog;
    mockHwApi.replay_binlog = MockReplayBinlog;
    mockHwApi.clean_binlog = MockCleanBinlog;
    sqlite3_export_hw_symbols = &mockHwApi;
#ifndef CROSS_PLATFORM
    mockKvApi.is_support_binlog = MockNotSupportBinlogWithParam;
    sqlite3_export_relational_symbols = &mockKvApi;
#endif
}

void RdbDoubleWriteTest::TearDownTestCase(void)
{
    sqlite3_export_hw_symbols = originalHwApi;
#ifndef CROSS_PLATFORM
    sqlite3_export_relational_symbols = originalKvApi;
#endif
}

void RdbDoubleWriteTest::SetUp(void)
{
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
}

void RdbDoubleWriteTest::TearDown(void)
{
    RdbDoubleWriteTest::WaitForAsyncRepairFinish();
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
}

void RdbDoubleWriteTest::InitDb(HAMode mode)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(mode);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbDoubleWriteTest::store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    ASSERT_NE(RdbDoubleWriteTest::slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
}

/**
 * @tc.name: RdbStore_DoubleWrite_001
 * @tc.desc: test RdbStore doubleWrite
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_001, TestSize.Level1)
{
    InitDb();
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

void RdbDoubleWriteTest::Insert(int64_t start, int count, bool isSlave, int dataSize)
{
    ValuesBucket values;
    int64_t id = start;
    int ret = E_OK;
    for (int i = 0; i < count; i++) {
        values.Clear();
        values.PutInt("id", id);
        if (dataSize > 0) {
            values.PutString("name", std::string(dataSize, 'a'));
        } else {
            values.PutString("name", std::string("zhangsan"));
        }
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

void RdbDoubleWriteTest::WaitForBackupFinish(int32_t expectStatus, int maxTimes)
{
    int32_t curStatus = store->GetBackupStatus();
    int tryTimes = 0;
    while (curStatus != expectStatus && (++tryTimes <= maxTimes)) {
        usleep(50000); // 50000 delay
        curStatus = store->GetBackupStatus();
    }
    LOG_INFO("----------cur backup Status:%{public}d---------", curStatus);
    ASSERT_EQ(curStatus, expectStatus);
}

void RdbDoubleWriteTest::WaitForAsyncRepairFinish(int maxTimes)
{
    LOG_INFO("---- start wait for async finish----");
    sleep(1);
    int tryTimes = 0;
    auto keyFiles = RdbSecurityManager::KeyFiles(DATABASE_NAME + "-async.restore");
    while (keyFiles.Lock(false) != E_OK && (++tryTimes <= maxTimes)) {
        sleep(1);
    }
    LOG_INFO("---- end wait for async finish ----, %{public}d", tryTimes);
}

void RdbDoubleWriteTest::TryInterruptBackup()
{
    int err = store->InterruptBackup();
    int tryTimes = 0;
    while (err != E_OK && (++tryTimes <= 1000)) { // 1000 is try time
        usleep(10000);                            // 10000 delay
        err = store->InterruptBackup();
    }
    EXPECT_EQ(err, E_OK);
    LOG_INFO("----------interrupt backup---------");
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

void RdbDoubleWriteTest::CheckNumber(
    std::shared_ptr<RdbStore> &store, int num, int errCode, const std::string &tableName)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM " + tableName);
    ASSERT_NE(resultSet, nullptr);
    int countNum;
    int ret = resultSet->GetRowCount(countNum);
    EXPECT_EQ(ret, errCode);
    EXPECT_EQ(num, countNum);
}

/**
 * @tc.name: RdbStore_DoubleWrite_003
 * @tc.desc: test RdbStore execute
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_003, TestSize.Level1)
{
    InitDb();

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
    InitDb();

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
    InitDb();

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
    InitDb();
    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_008 insert finish");

    store = nullptr;

    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_008 corrupt db finish");

    SqliteUtils::DeleteFile(RdbDoubleWriteTest::DATABASE_NAME + "-dwr");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::SLAVE_DATABASE_NAME + "-dwr");
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
    InitDb();
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
    InitDb();
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
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_010 corrupt db finish");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::DATABASE_NAME + "-dwr");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::SLAVE_DATABASE_NAME + "-dwr");

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
    WaitForBackupFinish(BACKUP_FINISHED);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_011
 * @tc.desc: open MAIN_REPLICA db, write, close slave, corrupt slave, backup, check slave
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_011, TestSize.Level1)
{
    InitDb();
    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_011 insert finish");

    slaveStore = nullptr;

    std::fstream file(SLAVE_DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_011 corrupt db finish");

    EXPECT_NE(store->Backup(std::string(""), {}), E_OK);
    LOG_INFO("RdbStore_DoubleWrite_011 backup db finish");
    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);

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
    InitDb();

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
    InitDb();
    int64_t id = 10;
    int count = 100;
    ValuesBucket values;
    for (int i = 0; i < count; i++) {
        id++;
        values.Clear();
        values.PutInt("id", id);
        values.PutString("name", std::string("zhangsan"));
        values.PutInt("age", 18);
        values.PutDouble("salary", CHECKCOLUMN);
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
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_015 corrupt db finish");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::DATABASE_NAME + "-dwr");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::SLAVE_DATABASE_NAME + "-dwr");

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
    InitDb();
    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_016 insert finish");

    store = nullptr;
    LOG_INFO("RdbStore_DoubleWrite_016 close finish");

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

    WaitForBackupFinish(BACKUP_FINISHED);

    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_018
 * @tc.desc: open MAIN_REPLICA db, update slave, insert, M succ && S failed,
 *           check failureFlag, backup, check failureFlag
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_018, TestSize.Level1)
{
    InitDb();

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 25);
    values.PutDouble("salary", CHECKCOLUMN);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);

    auto [ret2, outValue2] = slaveStore->Execute("UPDATE test SET id = 3 WHERE id = 1");
    EXPECT_EQ(E_OK, ret2);

    int64_t id2;
    ValuesBucket values2;
    values2.PutInt("id", 3);
    values2.PutString("name", std::string("zhangsan"));
    values2.PutInt("age", 25);
    values2.PutDouble("salary", CHECKCOLUMN);
    values2.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret3 = store->Insert(id2, "test", values2);
    EXPECT_EQ(E_OK, ret3);
    std::string failureFlagPath = RdbDoubleWriteTest::DATABASE_NAME + +"-slaveFailure";
    bool isFlagFileExists = OHOS::FileExists(failureFlagPath);
    ASSERT_TRUE(isFlagFileExists);
    ASSERT_TRUE(store->IsSlaveDiffFromMaster());

    int errCode;
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    isFlagFileExists = OHOS::FileExists(failureFlagPath);
    ASSERT_FALSE(isFlagFileExists);
}

/**
 * @tc.name: RdbStore_DoubleWrite_019
 * @tc.desc: open MAIN_REPLICA db, update slave, insert, M succ && S failed,
 *           check failureFlag, reopen, check failureFlag
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_019, TestSize.Level1)
{
    InitDb();

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 25);
    values.PutDouble("salary", CHECKCOLUMN);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);

    auto [ret2, outValue2] = slaveStore->Execute("UPDATE test SET id = 3 WHERE id = 1");
    EXPECT_EQ(E_OK, ret2);

    int64_t id2;
    ValuesBucket values2;
    values2.PutInt("id", 3);
    values2.PutString("name", std::string("zhangsan"));
    values2.PutInt("age", 25);
    values2.PutDouble("salary", CHECKCOLUMN);
    values2.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret3 = store->Insert(id2, "test", values2);
    EXPECT_EQ(E_OK, ret3);
    std::string failureFlagPath = RdbDoubleWriteTest::DATABASE_NAME + +"-slaveFailure";
    bool isFlagFileExists = OHOS::FileExists(failureFlagPath);
    ASSERT_TRUE(isFlagFileExists);
    ASSERT_TRUE(store->IsSlaveDiffFromMaster());

    store = nullptr;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetAllowRebuild(true);
    DoubleWriteTestOpenCallback helper;
    int errCode;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    WaitForBackupFinish(BACKUP_FINISHED);
    store = nullptr;
    isFlagFileExists = OHOS::FileExists(failureFlagPath);
    ASSERT_FALSE(isFlagFileExists);
}

/**
 * @tc.name: RdbStore_DoubleWrite_026
 * @tc.desc: open MANUAL_TRIGGER db, write, restore, insert, check count
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_026, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);

    int64_t id = 10;
    int count = 100;
    Insert(id, count);

    EXPECT_EQ(store->Restore(std::string(""), {}), E_INVALID_FILE_PATH);

    id = 2000;
    Insert(id, count);
    RdbDoubleWriteTest::CheckNumber(store, count + count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_027
 * @tc.desc: open MANUAL_TRIGGER db, write, close, corrupt db, reopen, insert, check count
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_027, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    config.SetAllowRebuild(true);
    DoubleWriteTestOpenCallback helper;

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::slaveStore, nullptr);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);

    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);

    store = nullptr;

    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);

    id = 1000;
    Insert(id, count);
    RdbDoubleWriteTest::CheckNumber(store, count + count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_029
 * @tc.desc: open db, write, corrupt slave db, backup, backup, check count
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_029, TestSize.Level1)
{
    InitDb();
    int64_t id = 10;
    int count = 100;
    Insert(id, count);

    std::fstream slaveFile(SLAVE_DATABASE_NAME, std::ios::in | std::ios::out | std::ios::trunc);
    ASSERT_TRUE(slaveFile.is_open() == true);
    slaveFile << "0000";
    slaveFile.flush();
    slaveFile.close();

    std::fstream slaveWalFile(SLAVE_DATABASE_NAME + "-wal", std::ios::in | std::ios::out | std::ios::trunc);
    ASSERT_TRUE(slaveWalFile.is_open() == true);
    slaveWalFile << "0000";
    slaveWalFile.flush();
    slaveWalFile.close();

    EXPECT_NE(store->Backup(std::string(""), {}), E_OK);
    LOG_INFO("RdbStore_DoubleWrite_029 backup again");
    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);

    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, -1, E_SQLITE_CORRUPT);

    int errCode = E_OK;
    slaveStore = nullptr;
    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::slaveStore, nullptr);

    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_030
 * @tc.desc: open db, write, update slave, insert, check failure, restore, check count
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_030, TestSize.Level1)
{
    InitDb();
    int64_t id = 10;
    int count = 100;
    Insert(id, count);

    auto [ret2, outValue2] = slaveStore->Execute("UPDATE test SET id = 666 WHERE id = 22");
    EXPECT_EQ(E_OK, ret2);

    id = 666;
    Insert(id, 1);

    std::string failureFlagPath = RdbDoubleWriteTest::DATABASE_NAME + +"-slaveFailure";
    bool isFlagFileExists = OHOS::FileExists(failureFlagPath);
    ASSERT_TRUE(isFlagFileExists);

    EXPECT_NE(store->Restore(std::string(""), {}), E_OK);

    RdbDoubleWriteTest::CheckNumber(store, count + 1);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_031
 * @tc.desc: open db, delete main.db, deleteRdbStore, check slave db
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_031, TestSize.Level1)
{
    InitDb();
    remove(RdbDoubleWriteTest::DATABASE_NAME.c_str());
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    EXPECT_NE(access(RdbDoubleWriteTest::SLAVE_DATABASE_NAME.c_str(), F_OK), 0);
}

/**
 * @tc.name: RdbStore_DoubleWrite_032
 * @tc.desc: open db, delete main.db, deleteRdbStore, check slave db
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_032, TestSize.Level1)
{
    InitDb();
    remove(RdbDoubleWriteTest::DATABASE_NAME.c_str());
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(config);
    EXPECT_NE(access(RdbDoubleWriteTest::SLAVE_DATABASE_NAME.c_str(), F_OK), 0);
}

/**
 * @tc.name: RdbStore_DoubleWrite_033
 * @tc.desc: open db, write, close, corrupt, open SINGLE db, check
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_033, TestSize.Level1)
{
    InitDb();
    int64_t id = 10;
    int count = 100;
    Insert(id, count);

    store = nullptr;
    slaveStore = nullptr;

    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();

    SqliteUtils::DeleteFile(RdbDoubleWriteTest::DATABASE_NAME + "-dwr");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::SLAVE_DATABASE_NAME + "-dwr");
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::SINGLE);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);

    RebuiltType rebuiltType;
    store->GetRebuilt(rebuiltType);
    EXPECT_EQ(rebuiltType, RebuiltType::REPAIRED);

    RdbDoubleWriteTest::CheckNumber(store, count);
}

/**
 * @tc.name: RdbStore_DoubleWrite_Manual_Trigger_Not_Verify_Db
 * @tc.desc: open MANUAL_TRIGGER db, write, corrupt db, check backup with verify and no verify
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Manual_Trigger_Not_Verify_Db, TestSize.Level0)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);
    LOG_INFO("RdbStore_DoubleWrite_Manual_Trigger_Not_Verify_Db reopen main db finish");

    int64_t id = 10;
    int count = 100;
    Insert(id, count);
    LOG_INFO("RdbStore_DoubleWrite_Manual_Trigger_Not_Verify_Db insert finish");

    RdbDoubleWriteTest::CheckNumber(store, count);
    store = nullptr;
    
    std::fstream file(RdbDoubleWriteTest::DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open());

    file.seekp(0x2000, std::ios::beg);
    ASSERT_TRUE(file.good());

    char bytes[128];
    std::fill_n(bytes, 128, 0xff);
    file.write(bytes, 128);
    file.flush();
    file.close();
    LOG_INFO("RdbStore_DoubleWrite_Manual_Trigger_Not_Verify_Db corrupt db finish");

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);

    errCode = store->Backup(std::string(""));
    EXPECT_EQ(errCode, E_SQLITE_CORRUPT);

    errCode = store->Backup(std::string(""), {}, false);
    EXPECT_EQ(errCode, E_OK);
    store = nullptr;
}

/**
 * @tc.name: RdbStore_DoubleWrite_Huge_DB_001
 * @tc.desc: test db is deleted while open huge database, in MANUAL_TRIGGER
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Huge_DB_001, TestSize.Level3)
{
    LOG_INFO("---- start RdbStore_DoubleWrite_Huge_DB_001 ----");
    InitDb(HAMode::MANUAL_TRIGGER);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    int64_t id = 10;
    int count = 200;
    LOG_INFO("---- step 1: insert huge data ----");
    Insert(id, count, false, HUGE_DATA_SIZE);
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
    LOG_INFO("---- step 2: close store ----");
    store = nullptr;
    slaveStore = nullptr;
    LOG_INFO("---- step 3: remove db file ----");
    remove(RdbDoubleWriteTest::DATABASE_NAME.c_str());
    LOG_INFO("---- step 4: reopen and trigger restore ----");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::DATABASE_NAME + "-dwr");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::SLAVE_DATABASE_NAME + "-dwr");
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (errCode != E_SQLITE_BUSY) {
        EXPECT_EQ(errCode, E_OK);
        ASSERT_NE(store, nullptr);
        LOG_INFO("---- step 5: execute sql while restore ----");
        EXPECT_EQ(store->ExecuteSql("select * from test;"), E_DATABASE_BUSY);
        LOG_INFO("---- step 6: check db count ----");
        RdbDoubleWriteTest::WaitForAsyncRepairFinish();
        RdbDoubleWriteTest::CheckNumber(store, count);
    }
    LOG_INFO("---- end RdbStore_DoubleWrite_Huge_DB_001 ----");
}

/**
 * @tc.name: RdbStore_DoubleWrite_Huge_DB_002
 * @tc.desc: test db is deleted while open huge database, in MAIN_REPLICA
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Huge_DB_002, TestSize.Level3)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    LOG_INFO("---- start RdbStore_DoubleWrite_Huge_DB_002 ----");
    InitDb();
    int64_t id = 10;
    int count = 200;
    LOG_INFO("---- step 1: insert huge data ----");
    Insert(id, count, false, HUGE_DATA_SIZE);
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
    LOG_INFO("---- step 2: close store ----");
    store = nullptr;
    slaveStore = nullptr;
    LOG_INFO("---- step 3: remove db file ----");
    remove(RdbDoubleWriteTest::DATABASE_NAME.c_str());
    LOG_INFO("---- step 4: reopen and trigger restore ----");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::DATABASE_NAME + "-dwr");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::SLAVE_DATABASE_NAME + "-dwr");
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (errCode != E_SQLITE_BUSY) {
        EXPECT_EQ(errCode, E_OK);
        ASSERT_NE(store, nullptr);
        LOG_INFO("---- step 5: execute sql while restore ----");
        EXPECT_EQ(store->ExecuteSql("select * from test;"), E_DATABASE_BUSY);
        LOG_INFO("---- step 6: check db count ----");
        RdbDoubleWriteTest::WaitForAsyncRepairFinish();
        RdbDoubleWriteTest::CheckNumber(store, count);
    }
    LOG_INFO("---- end RdbStore_DoubleWrite_Huge_DB_002 ----");
}

/**
 * @tc.name: RdbStore_DoubleWrite_Huge_DB_003
 * @tc.desc: test async restore for huge db in MAIN_REPLICA
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Huge_DB_003, TestSize.Level3)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    LOG_INFO("---- start RdbStore_DoubleWrite_Huge_DB_003 ----");
    InitDb();
    int64_t id = 10;
    int count = 200;
    LOG_INFO("---- step 1: insert huge data ----");
    Insert(id, count, false, HUGE_DATA_SIZE);
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
    LOG_INFO("---- step 2: corrupt store ----");
    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("---- step 3: manually trigger repair ----");
    EXPECT_EQ(store->Restore(std::string(""), {}), E_OK);
    EXPECT_EQ(store->ExecuteSql("select * from test;"), E_DATABASE_BUSY);
    LOG_INFO("---- step 4: check db count ----");
    RdbDoubleWriteTest::WaitForAsyncRepairFinish();
    RdbDoubleWriteTest::CheckNumber(store, count);
    LOG_INFO("---- end RdbStore_DoubleWrite_Huge_DB_003 ----");
}

/**
 * @tc.name: RdbStore_DoubleWrite_Huge_DB_004
 * @tc.desc: test async restore for huge db in MANUAL_TRIGGER
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Huge_DB_004, TestSize.Level3)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    LOG_INFO("---- start RdbStore_DoubleWrite_Huge_DB_004 ----");
    InitDb(HAMode::MANUAL_TRIGGER);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    int64_t id = 10;
    int count = 200;
    LOG_INFO("---- step 1: insert huge data ----");
    Insert(id, count, false, HUGE_DATA_SIZE);
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
    LOG_INFO("---- step 2: corrupt store ----");
    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("---- step 3: manually trigger repair ----");
    EXPECT_EQ(store->Restore(std::string(""), {}), E_OK);
    EXPECT_EQ(store->ExecuteSql("select * from test;"), E_DATABASE_BUSY);
    LOG_INFO("---- step 4: check db count ----");
    RdbDoubleWriteTest::WaitForAsyncRepairFinish();
    RdbDoubleWriteTest::CheckNumber(store, count);
    LOG_INFO("---- end RdbStore_DoubleWrite_Huge_DB_004 ----");
}

/**
 * @tc.name: RdbStore_DoubleWrite_Huge_DB_005
 * @tc.desc: test restore is called while doing async restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Huge_DB_005, TestSize.Level3)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    LOG_INFO("---- start RdbStore_DoubleWrite_Huge_DB_005 ----");
    InitDb(HAMode::MANUAL_TRIGGER);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    int64_t id = 10;
    int count = 200;
    LOG_INFO("---- step 1: insert huge data ----");
    Insert(id, count, false, HUGE_DATA_SIZE);
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
    LOG_INFO("---- step 2: corrupt store ----");
    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("---- step 3: manually trigger repair ----");
    EXPECT_EQ(store->Restore(std::string(""), {}), E_OK);
    EXPECT_EQ(store->ExecuteSql("select * from test;"), E_DATABASE_BUSY);
    LOG_INFO("---- step 4: trigger repair again ----");
    EXPECT_EQ(store->Restore(std::string(""), {}), E_OK);
    LOG_INFO("---- step 5: check db count ----");
    RdbDoubleWriteTest::WaitForAsyncRepairFinish();
    RdbDoubleWriteTest::CheckNumber(store, count);
    LOG_INFO("---- end RdbStore_DoubleWrite_Huge_DB_005 ----");
}

/**
 * @tc.name: RdbStore_DoubleWrite_Huge_DB_006
 * @tc.desc: test call restore for huge db when slave db is corrupted
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Huge_DB_006, TestSize.Level3)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    LOG_INFO("---- start RdbStore_DoubleWrite_Huge_DB_006 ----");
    InitDb(HAMode::MANUAL_TRIGGER);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    int64_t id = 10;
    int count = 200;
    LOG_INFO("---- step 1: insert huge data ----");
    Insert(id, count, false, HUGE_DATA_SIZE);
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
    LOG_INFO("---- step 2: corrupt store ----");
    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    file.seekp(30, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    char bytes[2] = { 0x6, 0x6 };
    file.write(bytes, 2);
    ASSERT_TRUE(file.good() == true);
    file.close();
    LOG_INFO("---- step 3: mark backup db corrupted ----");
    SqliteUtils::SetSlaveInvalid(DATABASE_NAME);
    EXPECT_TRUE(SqliteUtils::IsSlaveInvalid(DATABASE_NAME));
    LOG_INFO("---- step 4: manually trigger repair ----");
    EXPECT_EQ(store->Restore(std::string(""), {}), E_SQLITE_CORRUPT);
    LOG_INFO("---- end RdbStore_DoubleWrite_Huge_DB_006 ----");
}

/**
 * @tc.name: RdbStore_DoubleWrite_Huge_DB_007
 * @tc.desc: test execsql when restore mark is abnormal
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Huge_DB_007, TestSize.Level3)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    LOG_INFO("---- start RdbStore_DoubleWrite_Huge_DB_007 ----");
    InitDb(HAMode::MANUAL_TRIGGER);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    int64_t id = 10;
    int count = 200;
    LOG_INFO("---- step 1: insert huge data ----");
    Insert(id, count, false, HUGE_DATA_SIZE);
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
    LOG_INFO("---- step 2: mark backup db as restoring ----");
    SqliteUtils::SetSlaveRestoring(DATABASE_NAME);
    EXPECT_TRUE(SqliteUtils::IsSlaveRestoring(DATABASE_NAME));
    LOG_INFO("---- step 3: manually trigger create statement should remove the mark ----");
    EXPECT_EQ(store->ExecuteSql("select * from test;"), E_OK);
    EXPECT_FALSE(SqliteUtils::IsSlaveRestoring(DATABASE_NAME));
    LOG_INFO("---- step 4: lock database for restoring and trigger create statement should not remove the mark  ----");
    SqliteUtils::SetSlaveRestoring(DATABASE_NAME);
    EXPECT_TRUE(SqliteUtils::IsSlaveRestoring(DATABASE_NAME));
    auto keyFiles = RdbSecurityManager::KeyFiles(DATABASE_NAME + "-async.restore");
    EXPECT_EQ(keyFiles.Lock(false), E_OK);
    LOG_INFO("---- step 5: manually trigger create statement should not remove the mark ----");
    EXPECT_EQ(store->ExecuteSql("select * from test;"), E_DATABASE_BUSY);
    EXPECT_TRUE(SqliteUtils::IsSlaveRestoring(DATABASE_NAME));
    SqliteUtils::SetSlaveRestoring(DATABASE_NAME, false);
    keyFiles.Unlock();
    LOG_INFO("---- end RdbStore_DoubleWrite_Huge_DB_007 ----");
}

/**
 * @tc.name: RdbStore_DoubleWrite_Huge_DB_008
 * @tc.desc: test trigger async repair
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Huge_DB_008, TestSize.Level3)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    LOG_INFO("---- start RdbStore_DoubleWrite_Huge_DB_008 ----");
    InitDb(HAMode::MANUAL_TRIGGER);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    int64_t id = 10;
    int count = 200;
    LOG_INFO("---- step 1: insert huge data ----");
    Insert(id, count, false, HUGE_DATA_SIZE);
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
    LOG_INFO("---- step 2: corrupt both slave and master db ----");
    store = nullptr;
    slaveStore = nullptr;
    EXPECT_TRUE(SqliteUtils::CopyFile(DATABASE_NAME + "-dwr", DATABASE_NAME));
    std::fstream file(SLAVE_DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    file.seekp(1, std::ios::beg);
    std::vector<char> null_buffer(count, '\0');
    file.write(null_buffer.data(), count);
    file.close();
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::DATABASE_NAME + "-dwr");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::SLAVE_DATABASE_NAME + "-dwr");
    SqliteUtils::SetSlaveInvalid(DATABASE_NAME);
    EXPECT_TRUE(SqliteUtils::IsSlaveInvalid(DATABASE_NAME));

    LOG_INFO("---- step 3: reopen should give E_SQLITE_CORRUPT ----");
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_SQLITE_CORRUPT);
    LOG_INFO("---- end RdbStore_DoubleWrite_Huge_DB_008 ----");
}

/**
 * @tc.name: RdbStore_DoubleWrite_Huge_DB_009
 * @tc.desc: test trigger async repair
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_Huge_DB_009, TestSize.Level3)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    LOG_INFO("---- start RdbStore_DoubleWrite_Huge_DB_009 ----");
    InitDb(HAMode::MANUAL_TRIGGER);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    int64_t id = 10;
    int count = 200;
    LOG_INFO("---- step 1: insert huge data ----");
    Insert(id, count, false, HUGE_DATA_SIZE);
    RdbDoubleWriteTest::CheckNumber(store, count);
    RdbDoubleWriteTest::CheckNumber(slaveStore, count);
    LOG_INFO("---- step 2: corrupt master db ----");
    store = nullptr;
    slaveStore = nullptr;
    EXPECT_TRUE(SqliteUtils::CopyFile(DATABASE_NAME + "-dwr", DATABASE_NAME));
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::DATABASE_NAME + "-dwr");
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::SLAVE_DATABASE_NAME + "-dwr");
    LOG_INFO("---- step 3: reopen should give ok ----");
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (errCode != E_SQLITE_BUSY) {
        EXPECT_EQ(errCode, E_OK);
        ASSERT_NE(store, nullptr);
        LOG_INFO("---- step 4: trigger statement should busy ----");
        EXPECT_EQ(store->ExecuteSql("select * from test;"), E_DATABASE_BUSY);
        store = nullptr;
    }
    LOG_INFO("---- step 5: check db count ----");
    RdbDoubleWriteTest::WaitForAsyncRepairFinish();
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    RdbDoubleWriteTest::CheckNumber(store, count);
    LOG_INFO("---- end RdbStore_DoubleWrite_Huge_DB_009 ----");
}

/*
 * @tc.name: RdbStore_Mock_Binlog_001
 * @tc.desc: test call backup and restore when binlog is supported
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_Mock_Binlog_001, TestSize.Level0)
{
    mockHwApi.is_support_binlog = MockSupportBinlog;
    sqlite3_export_hw_symbols = &mockHwApi;
#ifndef CROSS_PLATFORM
    mockKvApi.is_support_binlog = MockSupportBinlogWithParam;
    sqlite3_export_relational_symbols = &mockKvApi;
#endif

    InitDb(HAMode::MANUAL_TRIGGER);
    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
    EXPECT_EQ(store->Restore(std::string(""), {}), E_OK);
}

/*
 * @tc.name: RdbStore_Mock_Binlog_002
 * @tc.desc: test call CheckReplicaIntegrity when binlog is supported
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_Mock_Binlog_002, TestSize.Level0)
{
    mockHwApi.is_support_binlog = MockSupportBinlog;
    sqlite3_export_hw_symbols = &mockHwApi;
#ifndef CROSS_PLATFORM
    mockKvApi.is_support_binlog = MockSupportBinlogWithParam;
    sqlite3_export_relational_symbols = &mockKvApi;
#endif
    InitDb(HAMode::MAIN_REPLICA);
    store = nullptr;
    slaveStore = nullptr;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    EXPECT_EQ(Connection::CheckReplicaIntegrity(config), E_OK);
}

/**
 * @tc.name: CreateReplicaStatement_Test_001
 * @tc.desc: Normal testCase of CreateReplicaStatement.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, CreateReplicaStatement_Test_001, TestSize.Level2)
{
    InitDb();

    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    auto [errCode, readConn] = SqliteConnection::Create(config, false);
    EXPECT_EQ(errCode, SQLITE_OK);
    ASSERT_NE(readConn, nullptr);
    auto [err, statement] = readConn->CreateReplicaStatement("select * from test;", readConn);
    EXPECT_EQ(err, SQLITE_OK);
    EXPECT_NE(statement, nullptr);
    statement = nullptr;
    readConn = nullptr;
}

/**
 * @tc.name: CreateReplicaStatement_Test_002
 * @tc.desc: Abnormal testCase of CreateReplicaStatement.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, CreateReplicaStatement_Test_002, TestSize.Level2)
{
    InitDb();
    SqliteUtils::DeleteFile(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);

    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    auto [errCode, readConn] = SqliteConnection::Create(config, false);
    EXPECT_EQ(errCode, SQLITE_OK);
    ASSERT_NE(readConn, nullptr);
    auto [err, statement] = readConn->CreateReplicaStatement("select * from test;", readConn);
    EXPECT_EQ(err, SQLITE_OK);
    EXPECT_NE(statement, nullptr);
    statement = nullptr;
    readConn = nullptr;
}

/**
 * @tc.name: CreateReplicaStatement_Test_003
 * @tc.desc: Abnormal testCase of CreateReplicaStatement.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, CreateReplicaStatement_Test_003, TestSize.Level2)
{
    InitDb();
    EXPECT_TRUE(SqliteUtils::CopyFile(SLAVE_DATABASE_NAME + "-dwr", SLAVE_DATABASE_NAME));

    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    auto [errCode, readConn] = SqliteConnection::Create(config, false);
    EXPECT_EQ(errCode, SQLITE_OK);
    ASSERT_NE(readConn, nullptr);
    auto [err, statement] = readConn->CreateReplicaStatement("select * from test;", readConn);
    EXPECT_EQ(err, SQLITE_OK);
    EXPECT_NE(statement, nullptr);
}
