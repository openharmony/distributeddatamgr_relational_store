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

#include <iostream>
#include <filesystem>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string>

#include "common.h"
#include "file_ex.h"
#include "logger.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "securec.h"
#include "sqlite3.h"
#include "sqlite_connection.h"
#include "sqlite_utils.h"
#include "sqlite_global_config.h"
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
    static void CheckNumber(
        std::shared_ptr<RdbStore> &store, int num, int errCode = E_OK, const std::string &tableName = "test");
    static bool CheckFolderExist(const std::string &path);
    void RemoveFolder(const std::string &path);
    static void Insert(int64_t start, int count, bool isSlave = false, int dataSize = 0);
    void Update(int64_t start, int count, bool isSlave = false, int dataSize = 0);
    void CheckProcess(std::shared_ptr<RdbStore> &store);
    void DeleteDbFile(const RdbStoreConfig &config);
    void PutValue(std::shared_ptr<RdbStore> &store, char *data, int64_t id, int age);
    static void WaitForBackupFinish(int32_t expectStatus, int maxTimes = 400);
    void TryInterruptBackup();
    void InitDb(HAMode haMode = HAMode::MAIN_REPLICA);
    int64_t GetRestoreTime(HAMode haMode);

    static const std::string DATABASE_NAME;
    static const std::string SLAVE_DATABASE_NAME;
    static const std::string BINLOG_DATABASE_NAME;
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

const std::string RdbDoubleWriteTest::DATABASE_NAME = RDB_TEST_PATH + "dual_write_test.db";
const std::string RdbDoubleWriteTest::SLAVE_DATABASE_NAME = RDB_TEST_PATH + "dual_write_test_slave.db";
const std::string RdbDoubleWriteTest::BINLOG_DATABASE_NAME = RDB_TEST_PATH + "dual_write_test.db_binlog";
std::shared_ptr<RdbStore> RdbDoubleWriteTest::store = nullptr;
std::shared_ptr<RdbStore> RdbDoubleWriteTest::slaveStore = nullptr;
std::shared_ptr<RdbStore> RdbDoubleWriteTest::store3 = nullptr;
const int BLOB_SIZE = 3;
const uint8_t EXPECTED_BLOB_DATA[]{ 1, 2, 3 };
const int CHECKAGE = 18;
const double CHECKCOLUMN = 100.5;
const int CHANGENUM = 12;

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
}

void RdbDoubleWriteTest::TearDown(void)
{
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
}

void RdbDoubleWriteTest::InitDb(HAMode haMode)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    config.SetHaMode(haMode);
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

void RdbDoubleWriteTest::Update(int64_t start, int count, bool isSlave, int dataSize)
{
    ValuesBucket values;
    int64_t id = start;
    int age = 20;
    int ret = E_OK;
    for (int i = 0; i < count; i++) {
        values.Clear();
        values.PutInt("id", id);
        if (dataSize > 0) {
            values.PutString("name", std::string(dataSize, 'a'));
        } else {
            values.PutString("name", std::string("zhangsan"));
        }
        values.PutInt("age", age);
        values.PutDouble("salary", CHECKCOLUMN);
        values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
        if (isSlave) {
            ret = slaveStore->Replace(id, "test", values);
        } else {
            ret = store->Replace(id, "test", values);
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

bool RdbDoubleWriteTest::CheckFolderExist(const std::string &path)
{
    if (access(path.c_str(), F_OK) != 0) {
        return false;
    }
    return true;
}

void RdbDoubleWriteTest::RemoveFolder(const std::string &path)
{
    std::filesystem::path folder(path);
    for (const auto &entry : std::filesystem::directory_iterator(folder)) {
        if (entry.is_directory()) {
            RemoveFolder(entry.path());
        } else {
            std::filesystem::remove(entry.path());
        }
    }
    std::filesystem::remove(folder);
}

typedef int (*GtForkCallbackT)(const char *arg);
static pid_t GtFork(GtForkCallbackT callback, const char *arg)
{
    pid_t pid = fork();
    if (pid == 0) {
        int ret = callback(arg);
        _exit(ret);
    }
    return pid;
}

static int InsertProcess(const char *arg)
{
    std::string test = std::string(arg);
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    int errCode = E_OK;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::store, nullptr);
    int64_t id = 11;
    int count = 1000;
    RdbDoubleWriteTest::Insert(id, count);
    int32_t num = 1010;
    RdbDoubleWriteTest::CheckNumber(RdbDoubleWriteTest::store, num);
    return 0;
}

static int InsertTwoProcess(const char *arg)
{
    std::string test = std::string(arg);
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    int errCode = E_OK;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::store, nullptr);
    bool isBinlogExist = RdbDoubleWriteTest::CheckFolderExist(RdbDoubleWriteTest::BINLOG_DATABASE_NAME);
    EXPECT_TRUE(isBinlogExist);
    int count = 10;
    for (int i = 0; i < count; i++) {
        errCode = RdbDoubleWriteTest::store->Backup(std::string(""), {});
    }
    return 0;
}

static int InsertManualProcess(const char *arg)
{
    std::string test = std::string(arg);
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::store, nullptr);
    int64_t id = 11;
    int count = 1000;
    RdbDoubleWriteTest::Insert(id, count);
    int32_t num = 1010;
    RdbDoubleWriteTest::CheckNumber(RdbDoubleWriteTest::store, num);
    return 0;
}

static int InsertManualTwoProcess(const char *arg)
{
    std::string test = std::string(arg);
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteTest::store, nullptr);
    bool isBinlogExist = RdbDoubleWriteTest::CheckFolderExist(RdbDoubleWriteTest::BINLOG_DATABASE_NAME);
    EXPECT_TRUE(isBinlogExist);
    int count = 10;
    for (int i = 0; i < count; i++) {
        errCode = RdbDoubleWriteTest::store->Backup(std::string(""), {});
    }
    return 0;
}

void RdbDoubleWriteTest::CheckProcess(std::shared_ptr<RdbStore> &store)
{
    int64_t changeId = 2;
    int changeCount = 4;
    Update(changeId, changeCount);
    int deletedRows;
    store->Delete(deletedRows, "test", "id == 8");
    store->Delete(deletedRows, "test", "id == 9");
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);
    std::string sqlCreateIndex = "CREATE INDEX id_index ON test (id);";
    store->ExecuteSql(sqlCreateIndex.c_str());
    ret = store->Commit();
    EXPECT_EQ(ret, E_OK);
    ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);
    changeId = CHANGENUM;
    Update(changeId, changeCount);
    store->Delete(deletedRows, "test", "id == 18");
    store->Delete(deletedRows, "test", "id == 19");
    ret = store->RollBack();
    EXPECT_EQ(ret, E_OK);
}

void RdbDoubleWriteTest::DeleteDbFile(const RdbStoreConfig &config)
{
    std::string dbFile;
    auto errCode = SqliteGlobalConfig::GetDbPath(config, dbFile);
    if (errCode != E_OK || dbFile.empty()) {
        return;
    }
    std::ifstream binFile(dbFile);
    if (binFile.is_open()) {
        std::string content((std::istreambuf_iterator<char>(binFile)), (std::istreambuf_iterator<char>()));
        std::remove(dbFile.c_str());
    }
}

void RdbDoubleWriteTest::PutValue(std::shared_ptr<RdbStore> &store, char *data, int64_t id, int age)
{
    ValuesBucket values;
    values.PutInt("id", id);
    values.PutString("name", std::string(data));
    values.PutInt("age", age);
    values.PutDouble("salary", CHECKCOLUMN);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStore_DoubleWrite_001
 * @tc.desc: test RdbStore doubleWrite
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_001, TestSize.Level1)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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

/**
 * @tc.name: RdbStore_DoubleWrite_003
 * @tc.desc: test RdbStore execute
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_DoubleWrite_003, TestSize.Level1)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    int errCode = E_OK;
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    int errCode = E_OK;
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    int errCode = E_OK;
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    int errCode = E_OK;
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    int errCode = E_OK;
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    InitDb();
    remove(RdbDoubleWriteTest::DATABASE_NAME.c_str());
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
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
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

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_001, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    ASSERT_TRUE(CheckFolderExist(BINLOG_DATABASE_NAME));
    RdbHelper::DeleteRdbStore(config);
    ASSERT_FALSE(CheckFolderExist(BINLOG_DATABASE_NAME));
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_002, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_FALSE(isBinlogExist);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_003, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isSlaveDbFileExist = OHOS::FileExists(SLAVE_DATABASE_NAME);
    ASSERT_TRUE(isSlaveDbFileExist);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_004, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isSlaveDbFileExist = OHOS::FileExists(SLAVE_DATABASE_NAME);
    ASSERT_FALSE(isSlaveDbFileExist);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    isSlaveDbFileExist = OHOS::FileExists(SLAVE_DATABASE_NAME);
    ASSERT_TRUE(isSlaveDbFileExist);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_005, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);
    store = nullptr;
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_006, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_007, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);

    SqliteUtils::SetSlaveInvalid(DATABASE_NAME);
    std::string failureFlagPath = RdbDoubleWriteTest::DATABASE_NAME + +"-slaveFailure";
    bool isFlagFileExists = OHOS::FileExists(failureFlagPath);
    ASSERT_TRUE(isFlagFileExists);
    store = nullptr;
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_008, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);

    SqliteUtils::SetSlaveInvalid(DATABASE_NAME);
    std::string failureFlagPath = RdbDoubleWriteTest::DATABASE_NAME + +"-slaveFailure";
    bool isFlagFileExists = OHOS::FileExists(failureFlagPath);
    ASSERT_TRUE(isFlagFileExists);
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_FALSE(isBinlogExist);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_009, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb();
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    int64_t id = 1;
    int count = 10;
    Insert(id, count);

    store = nullptr;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
    id = 11;
    Insert(id, count);
    store = nullptr;
    DeleteDbFile(config);

    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    WaitForBackupFinish(BACKUP_FINISHED);
    int32_t num = 20;
    RdbDoubleWriteTest::CheckNumber(store, num);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_010, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);

    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
    id = 11;
    Insert(id, count);
    store = nullptr;
    DeleteDbFile(config);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    WaitForBackupFinish(BACKUP_FINISHED);
    int32_t num = 20;
    RdbDoubleWriteTest::CheckNumber(store, num);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_011, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb();
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    int64_t id = 1;
    int count = 10;
    Insert(id, count);

    store = nullptr;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
    id = 11;
    Insert(id, count);
    int32_t num = 20;
    RdbDoubleWriteTest::CheckNumber(store, num);
    CheckProcess(store);

    store = nullptr;
    DeleteDbFile(config);

    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    WaitForBackupFinish(BACKUP_FINISHED);
    num = 18;
    RdbDoubleWriteTest::CheckNumber(store, num);
    RdbDoubleWriteTest::CheckNumber(slaveStore, num);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_012, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);

    store = nullptr;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);
    id = 11;
    Insert(id, count);
    int32_t num = 20;
    RdbDoubleWriteTest::CheckNumber(store, num);
    CheckProcess(store);

    store = nullptr;
    DeleteDbFile(config);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    WaitForBackupFinish(BACKUP_FINISHED);
    num = 18;
    RdbDoubleWriteTest::CheckNumber(store, num);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_013, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    bool isSlaveDbFileExists = OHOS::FileExists(SLAVE_DATABASE_NAME);
    ASSERT_TRUE(isSlaveDbFileExists);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);

    int64_t id = 1;
    int count = 20;
    Insert(id, count);
    CheckProcess(store);

    int64_t num = 18;
    RdbDoubleWriteTest::CheckNumber(store, num);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    RdbDoubleWriteTest::CheckNumber(slaveStore, num);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_014, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    bool isSlaveDbFileExists = OHOS::FileExists(SLAVE_DATABASE_NAME);
    ASSERT_FALSE(isSlaveDbFileExists);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    WaitForBackupFinish(BACKUP_FINISHED);
    isSlaveDbFileExists = OHOS::FileExists(SLAVE_DATABASE_NAME);
    ASSERT_TRUE(isSlaveDbFileExists);
    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);

    int64_t id = 1;
    int count = 20;
    Insert(id, count);
    CheckProcess(store);

    int64_t num = 18;
    RdbDoubleWriteTest::CheckNumber(store, num);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    RdbDoubleWriteTest::CheckNumber(slaveStore, num);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_015, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;
    std::string test = "lisi";
    pid_t pid1 = GtFork(InsertProcess, test.c_str());
    ASSERT_GT(pid1, 0);
    InsertTwoProcess(test.c_str());
    int status;
    waitpid(pid1, &status, 0);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_016, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store->ExecuteSql("DELETE FROM test");
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
    ASSERT_TRUE(CheckFolderExist(BINLOG_DATABASE_NAME));

    RdbStoreConfig slaveConfig(RdbDoubleWriteTest::SLAVE_DATABASE_NAME);
    DoubleWriteTestOpenCallback slaveHelper;
    RdbDoubleWriteTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);

    store = nullptr;
    std::string test = "lisi";
    pid_t pid1 = GtFork(InsertManualProcess, test.c_str());
    ASSERT_GT(pid1, 0);
    InsertManualTwoProcess(test.c_str());
    int status;
    waitpid(pid1, &status, 0);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_017, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;

    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);

    size_t bigSize = 1024 * 1024 * 128;
    char *data = (char *)malloc(bigSize);
    if (data == nullptr) {
        return;
    }
    memset_s(data, bigSize - 1, 'a', bigSize - 1);

    PutValue(store, data, 11, 18);
    PutValue(store, data, 12, 19);

    store = nullptr;
    id = 13;
    for (int i = 0; i < count; i++) {
        config.SetHaMode(HAMode::MAIN_REPLICA);
        RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
        EXPECT_NE(store, nullptr);
        PutValue(store, data, id, CHECKAGE);
        store = nullptr;
        id++;
    }
    free(data);
}

HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_018, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;

    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    DoubleWriteTestOpenCallback helper;
    RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    bool isBinlogExist = CheckFolderExist(BINLOG_DATABASE_NAME);
    ASSERT_TRUE(isBinlogExist);

    size_t bigSize = 1024 * 1024 * 13;
    char *data = (char *)malloc(bigSize);
    if (data == nullptr) {
        return;
    }
    memset_s(data, bigSize - 1, 'a', bigSize - 1);

    store = nullptr;
    id = 11;
    for (int i = 0; i < count; i++) {
        config.SetHaMode(HAMode::MAIN_REPLICA);
        RdbDoubleWriteTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
        EXPECT_NE(store, nullptr);
        PutValue(store, data, id, CHECKAGE);
        store = nullptr;
        id++;
    }
    free(data);
}

static int64_t GetInsertTime(std::shared_ptr<RdbStore> &rdbStore, int repeat, size_t dataSize)
{
    size_t bigSize = dataSize;
    char *data = (char *)malloc(bigSize);
    EXPECT_NE(data, nullptr);
    if (data == nullptr) {
        return -1;
    }
    memset_s(data, bigSize - 1, 'a', bigSize - 1);
    LOG_INFO("---- start insert ----");
    int64_t totalCost = 0;
    for (int64_t id = 0; id < repeat; id++) {
        ValuesBucket values;
        values.PutInt("id", id);
        values.PutString("name", std::string(data));
        values.PutInt("age", id);
        values.PutDouble("salary", CHECKCOLUMN);
        values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
        auto begin = std::chrono::high_resolution_clock::now();
        int ret = rdbStore->Insert(id, "test", values);
        auto stop = std::chrono::high_resolution_clock::now();
        EXPECT_EQ(ret, E_OK);
        totalCost += std::chrono::duration_cast<std::chrono::microseconds>(stop - begin).count();
    }
    free(data);
    return totalCost;
}

static int64_t GetUpdateTime(std::shared_ptr<RdbStore> &rdbStore, int batchSize, int repeat, size_t dataSize)
{
    size_t bigSize = dataSize;
    char *data = (char *)malloc(bigSize);
    EXPECT_NE(data, nullptr);
    if (data == nullptr) {
        return -1;
    }
    memset_s(data, bigSize - 1, 'b', bigSize - 1);
    LOG_INFO("---- start update ----");
    int64_t totalCost = 0;
    for (int i = 0; i < repeat; i++) {
        int start = i * batchSize;
        int end = (i + 1) * batchSize;
        std::string sql = "update test set name = '" + std::string(data) + "' where id >= " + std::to_string(start) +
                          " and id < " + std::to_string(end) + ";";
        auto begin = std::chrono::high_resolution_clock::now();
        int ret = rdbStore->ExecuteSql(sql);
        auto stop = std::chrono::high_resolution_clock::now();
        EXPECT_EQ(ret, E_OK);
        totalCost += std::chrono::duration_cast<std::chrono::microseconds>(stop - begin).count();
    }
    free(data);
    return totalCost;
}

static int64_t GetDeleteTime(std::shared_ptr<RdbStore> &rdbStore, int batchSize, int repeat)
{
    LOG_INFO("---- start delete ----");
    int64_t totalCost = 0;
    for (int i = 0; i < repeat; i++) {
        int start = i * batchSize;
        int end = (i + 1) * batchSize;
        std::string sql =
            "delete from test where id >= " + std::to_string(start) + " and id < " + std::to_string(end) + ";";
        auto begin = std::chrono::high_resolution_clock::now();
        int ret = rdbStore->ExecuteSql(sql);
        auto stop = std::chrono::high_resolution_clock::now();
        EXPECT_EQ(ret, E_OK);
        totalCost += std::chrono::duration_cast<std::chrono::microseconds>(stop - begin).count();
    }
    return totalCost;
}

static int MockSupportBinlogOff(void)
{
    return SQLITE_ERROR;
}

int64_t RdbDoubleWriteTest::GetRestoreTime(HAMode haMode)
{
    InitDb(haMode);
    EXPECT_NE(store, nullptr);
    if (haMode == HAMode::MANUAL_TRIGGER) {
        int errCode = store->Backup(std::string(""), {});
        EXPECT_EQ(errCode, E_OK);
    }
    int id = 1;
    int totalCount = 20000;
    int size = 1024;
    Insert(id, totalCount, size);
    store = nullptr;

    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    DoubleWriteTestOpenCallback helper;
    config.SetHaMode(haMode);
    DeleteDbFile(config);

    int errCode = E_OK;
    auto begin = std::chrono::high_resolution_clock::now();
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    auto stop = std::chrono::high_resolution_clock::now();
    EXPECT_NE(store, nullptr);
    return std::chrono::duration_cast<std::chrono::microseconds>(stop - begin).count();
}

/**
 * @tc.name: RdbStore_Binlog_Performance_001
 * @tc.desc: test performance of insert, update, query and delete in main_replica
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_Performance_001, TestSize.Level1)
{
    LOG_INFO("----RdbStore_Binlog_Performance_001 start----");
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (sqlite3_is_support_binlog == nullptr || sqlite3_is_support_binlog() == SQLITE_ERROR) {
        EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb(HAMode::MAIN_REPLICA);
    EXPECT_NE(store, nullptr);
    if (!CheckFolderExist(BINLOG_DATABASE_NAME)) {
        return;
    }

    int totalCount = 20000;
    int dataSize = 1024;
    int batchSize = 10;
    auto T1 = GetInsertTime(store, totalCount, dataSize);
    auto T2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3 = GetDeleteTime(store, batchSize, totalCount / batchSize);
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    ASSERT_FALSE(CheckFolderExist(BINLOG_DATABASE_NAME));

    InitDb(HAMode::SINGLE);
    EXPECT_NE(store, nullptr);

    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);

    EXPECT_LT(T1, T1_2 * 1.5);
    EXPECT_LT(T2, T2_2 * 1.5);
    EXPECT_LT(T3, T3_2 * 1.5);
    LOG_INFO("----RdbStore_Binlog_Performance_001----, %{public}lld, %{public}lld, %{public}lld", T1, T2, T3);
    LOG_INFO("----RdbStore_Binlog_Performance_001----, %{public}lld, %{public}lld, %{public}lld", T1_2, T2_2, T3_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_002
 * @tc.desc: test performance of insert, update, query and delete in mannual_trigger
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_Performance_002, TestSize.Level1)
{
    LOG_INFO("----RdbStore_Binlog_Performance_002 start----");
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (sqlite3_is_support_binlog == nullptr || sqlite3_is_support_binlog() == SQLITE_ERROR) {
        EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb(HAMode::MANUAL_TRIGGER);
    EXPECT_NE(store, nullptr);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    if (!CheckFolderExist(BINLOG_DATABASE_NAME)) {
        return;
    }

    int totalCount = 20000;
    int dataSize = 200;
    int batchSize = 1;
    auto T1 = GetInsertTime(store, totalCount, dataSize);
    auto T2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3 = GetDeleteTime(store, batchSize, totalCount / batchSize);
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    ASSERT_FALSE(CheckFolderExist(BINLOG_DATABASE_NAME));

    InitDb(HAMode::SINGLE);
    ASSERT_NE(store, nullptr);

    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);

    EXPECT_LT(T1, T1_2 * 1.5);
    EXPECT_LT(T2, T2_2 * 1.5);
    EXPECT_LT(T3, T3_2 * 1.5);
    LOG_INFO("----RdbStore_Binlog_Performance_002----, %{public}lld, %{public}lld, %{public}lld", T1, T2, T3);
    LOG_INFO("----RdbStore_Binlog_Performance_002----, %{public}lld, %{public}lld, %{public}lld", T1_2, T2_2, T3_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_003
 * @tc.desc: test performance of insert, update, query and delete in main_replica with large data
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_Performance_003, TestSize.Level2)
{
    LOG_INFO("----RdbStore_Binlog_Performance_003 start----");
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (sqlite3_is_support_binlog == nullptr || sqlite3_is_support_binlog() == SQLITE_ERROR) {
        EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb(HAMode::MAIN_REPLICA);
    EXPECT_NE(store, nullptr);
    if (!CheckFolderExist(BINLOG_DATABASE_NAME)) {
        return;
    }

    int totalCount = 200;
    int dataSize = 1024 * 1024;
    int batchSize = 10;
    auto T1 = GetInsertTime(store, totalCount, dataSize);
    auto T2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3 = GetDeleteTime(store, batchSize, totalCount / batchSize);
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    ASSERT_FALSE(CheckFolderExist(BINLOG_DATABASE_NAME));

    InitDb(HAMode::SINGLE);
    EXPECT_NE(store, nullptr);

    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);

    EXPECT_LT(T1, T1_2 * 1.5);
    EXPECT_LT(T2, T2_2 * 1.5);
    EXPECT_LT(T3, T3_2 * 1.5);
    LOG_INFO("----RdbStore_Binlog_Performance_003----, %{public}lld, %{public}lld, %{public}lld", T1, T2, T3);
    LOG_INFO("----RdbStore_Binlog_Performance_003----, %{public}lld, %{public}lld, %{public}lld", T1_2, T2_2, T3_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_004
 * @tc.desc: test performance of insert, update, query and delete in mannual_trigger with large data
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_Performance_004, TestSize.Level2)
{
    LOG_INFO("----RdbStore_Binlog_Performance_004 start----");
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (sqlite3_is_support_binlog == nullptr || sqlite3_is_support_binlog() == SQLITE_ERROR) {
        EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
        return;
    }
    if (CheckFolderExist(BINLOG_DATABASE_NAME)) {
        RemoveFolder(BINLOG_DATABASE_NAME);
    }
    InitDb(HAMode::MANUAL_TRIGGER);
    ASSERT_NE(store, nullptr);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    if (!CheckFolderExist(BINLOG_DATABASE_NAME)) {
        return;
    }

    int totalCount = 200;
    int dataSize = 1024 * 1024;
    int batchSize = 10;
    auto T1 = GetInsertTime(store, totalCount, dataSize);
    auto T2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3 = GetDeleteTime(store, batchSize, totalCount / batchSize);
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    ASSERT_FALSE(CheckFolderExist(BINLOG_DATABASE_NAME));

    InitDb(HAMode::SINGLE);
    EXPECT_NE(store, nullptr);

    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);

    EXPECT_LT(T1, T1_2 * 1.5);
    EXPECT_LT(T2, T2_2 * 1.5);
    EXPECT_LT(T3, T3_2 * 1.5);
    LOG_INFO("----RdbStore_Binlog_Performance_004----, %{public}lld, %{public}lld, %{public}lld", T1, T2, T3);
    LOG_INFO("----RdbStore_Binlog_Performance_004----, %{public}lld, %{public}lld, %{public}lld", T1_2, T2_2, T3_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_005
 * @tc.desc: test performance of restore in main_replica
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_Performance_005, TestSize.Level1)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (sqlite3_is_support_binlog == nullptr || sqlite3_is_support_binlog() == SQLITE_ERROR) {
        EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
        return;
    }
    struct sqlite3_api_routines_hw mockApi = *sqlite3_export_hw_symbols;
    mockApi.is_support_binlog = MockSupportBinlogOff;
    auto originalApi = sqlite3_export_hw_symbols;
    sqlite3_export_hw_symbols = &mockApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
    LOG_INFO("----RdbStore_Binlog_Performance_005 binlog off----");
    auto T1 = GetRestoreTime(HAMode::MAIN_REPLICA);

    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    ASSERT_FALSE(CheckFolderExist(BINLOG_DATABASE_NAME));
    sqlite3_export_hw_symbols = originalApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), true);
    LOG_INFO("----RdbStore_Binlog_Performance_005 binlog on----");
    auto T1_2 = GetRestoreTime(HAMode::MAIN_REPLICA);
    EXPECT_GT(T1 * 1.5, T1_2);
    LOG_INFO("----RdbStore_Binlog_Performance_005----, %{public}lld, %{public}lld", T1, T1_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_006
 * @tc.desc: test performance of restore in mannual_trigger
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteTest, RdbStore_Binlog_Performance_006, TestSize.Level1)
{
    RdbStoreConfig config(RdbDoubleWriteTest::DATABASE_NAME);
    if (sqlite3_is_support_binlog == nullptr || sqlite3_is_support_binlog() == SQLITE_ERROR) {
        EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
        return;
    }
    struct sqlite3_api_routines_hw mockApi = *sqlite3_export_hw_symbols;
    mockApi.is_support_binlog = MockSupportBinlogOff;
    auto originalApi = sqlite3_export_hw_symbols;
    sqlite3_export_hw_symbols = &mockApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
    LOG_INFO("----RdbStore_Binlog_Performance_006 binlog off----");
    auto T1 = GetRestoreTime(HAMode::MANUAL_TRIGGER);

    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteTest::DATABASE_NAME);
    ASSERT_FALSE(CheckFolderExist(BINLOG_DATABASE_NAME));
    sqlite3_export_hw_symbols = originalApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), true);
    LOG_INFO("----RdbStore_Binlog_Performance_006 binlog on----");
    auto T1_2 = GetRestoreTime(HAMode::MANUAL_TRIGGER);
    EXPECT_GT(T1 * 1.5, T1_2);
    LOG_INFO("----RdbStore_Binlog_Performance_006----, %{public}lld, %{public}lld", T1, T1_2);
}
