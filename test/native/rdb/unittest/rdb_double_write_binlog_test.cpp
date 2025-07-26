/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CROSS_PLATFORM
#define LOG_TAG "RdbDoubleWriteBinlogTest"
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
#include "relational/relational_store_sqlite_ext.h"
#include "sqlite3.h"
#include "sqlite_connection.h"
#include "sqlite_utils.h"
#include "sqlite_global_config.h"
#include "sys/types.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

class RdbDoubleWriteBinlogTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void CheckNumber(
        std::shared_ptr<RdbStore> &store, int num, int errCode = E_OK, const std::string &tableName = "test");
    static bool CheckFolderExist(const std::string &path);
    void RemoveFolder(const std::string &path);
    static void Insert(int64_t start, int count, bool isSlave = false, int dataSize = 0);
    void Update(int64_t start, int count, bool isSlave = false, int dataSize = 0);
    void CheckProcess(std::shared_ptr<RdbStore> &store);
    void DeleteDbFile(const RdbStoreConfig &config);
    void PutValue(std::shared_ptr<RdbStore> &store, const std::string &data, int64_t id, int age);
    static void WaitForBackupFinish(int32_t expectStatus, int maxTimes = 400);
    static void WaitForBinlogDelete(int maxTimes = 1000);
    void InitDb(HAMode haMode = HAMode::MAIN_REPLICA);
    int64_t GetRestoreTime(HAMode haMode);

    static const std::string databaseName;
    static const std::string slaveDatabaseName;
    static const std::string binlogDatabaseName;
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<RdbStore> slaveStore;

    enum SlaveStatus : uint32_t {
        UNDEFINED,
        DB_NOT_EXITS,
        BACKING_UP,
        BACKUP_INTERRUPT,
        BACKUP_FINISHED,
    };
};

const std::string RdbDoubleWriteBinlogTest::databaseName = RDB_TEST_PATH + "dual_write_binlog_test.db";
const std::string RdbDoubleWriteBinlogTest::slaveDatabaseName = RDB_TEST_PATH + "dual_write_binlog_test_slave.db";
const std::string RdbDoubleWriteBinlogTest::binlogDatabaseName = RDB_TEST_PATH + "dual_write_binlog_test.db_binlog";
std::shared_ptr<RdbStore> RdbDoubleWriteBinlogTest::store = nullptr;
std::shared_ptr<RdbStore> RdbDoubleWriteBinlogTest::slaveStore = nullptr;

const int CHECKAGE = 18;
const double CHECKCOLUMN = 100.5;
const int CHANGENUM = 12;
const int BINLOG_DELETE_PER_WAIT_TIME = 100000; // 100000us = 100ms

class DoubleWriteBinlogTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string createTableTest;
};

const std::string DoubleWriteBinlogTestOpenCallback::createTableTest =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");

int DoubleWriteBinlogTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(DoubleWriteBinlogTestOpenCallback::createTableTest);
}

int DoubleWriteBinlogTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbDoubleWriteBinlogTest::SetUpTestCase(void)
{
}

void RdbDoubleWriteBinlogTest::TearDownTestCase(void)
{
}

void RdbDoubleWriteBinlogTest::SetUp(void)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (!SqliteConnection::IsSupportBinlog(config)) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
}

void RdbDoubleWriteBinlogTest::TearDown(void)
{
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
}

void RdbDoubleWriteBinlogTest::InitDb(HAMode haMode)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    config.SetHaMode(haMode);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbDoubleWriteBinlogTest::store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    DoubleWriteBinlogTestOpenCallback slaveHelper;
    RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    ASSERT_NE(RdbDoubleWriteBinlogTest::slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
}

void RdbDoubleWriteBinlogTest::Insert(int64_t start, int count, bool isSlave, int dataSize)
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

void RdbDoubleWriteBinlogTest::Update(int64_t start, int count, bool isSlave, int dataSize)
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

void RdbDoubleWriteBinlogTest::WaitForBackupFinish(int32_t expectStatus, int maxTimes)
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

void RdbDoubleWriteBinlogTest::WaitForBinlogDelete(int maxTimes)
{
    int waitTimes = 0;
    while (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName) && waitTimes < maxTimes) {
        usleep(BINLOG_DELETE_PER_WAIT_TIME);
        waitTimes++;
        LOG_INFO("---- Binlog replay in progress, waiting for finish");
        RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    }
    EXPECT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
}

void RdbDoubleWriteBinlogTest::CheckNumber(
    std::shared_ptr<RdbStore> &store, int num, int errCode, const std::string &tableName)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM " + tableName);
    ASSERT_NE(resultSet, nullptr);
    int countNum;
    int ret = resultSet->GetRowCount(countNum);
    EXPECT_EQ(ret, errCode);
    EXPECT_EQ(num, countNum);
}

bool RdbDoubleWriteBinlogTest::CheckFolderExist(const std::string &path)
{
    if (access(path.c_str(), F_OK) != 0) {
        return false;
    }
    return true;
}

void RdbDoubleWriteBinlogTest::RemoveFolder(const std::string &path)
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
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    int errCode = E_OK;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    int64_t id = 11;
    int count = 1000;
    RdbDoubleWriteBinlogTest::Insert(id, count);
    int32_t num = 1010;
    RdbDoubleWriteBinlogTest::CheckNumber(RdbDoubleWriteBinlogTest::store, num);
    return 0;
}

static int InsertTwoProcess(const char *arg)
{
    std::string test = std::string(arg);
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    int errCode = E_OK;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    bool isBinlogExist = RdbDoubleWriteBinlogTest::CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    EXPECT_TRUE(isBinlogExist);
    int count = 10;
    for (int i = 0; i < count; i++) {
        errCode = RdbDoubleWriteBinlogTest::store->Backup(std::string(""), {});
    }
    return 0;
}

static int InsertManualProcess(const char *arg)
{
    std::string test = std::string(arg);
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    int64_t id = 11;
    int count = 1000;
    RdbDoubleWriteBinlogTest::Insert(id, count);
    int32_t num = 1010;
    RdbDoubleWriteBinlogTest::CheckNumber(RdbDoubleWriteBinlogTest::store, num);
    return 0;
}

static int InsertManualTwoProcess(const char *arg)
{
    std::string test = std::string(arg);
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    bool isBinlogExist = RdbDoubleWriteBinlogTest::CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    EXPECT_TRUE(isBinlogExist);
    int count = 10;
    for (int i = 0; i < count; i++) {
        errCode = RdbDoubleWriteBinlogTest::store->Backup(std::string(""), {});
    }
    return 0;
}

void RdbDoubleWriteBinlogTest::CheckProcess(std::shared_ptr<RdbStore> &store)
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

void RdbDoubleWriteBinlogTest::DeleteDbFile(const RdbStoreConfig &config)
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

void RdbDoubleWriteBinlogTest::PutValue(std::shared_ptr<RdbStore> &store, const std::string &data, int64_t id, int age)
{
    ValuesBucket values;
    values.PutInt("id", id);
    values.PutString("name", data);
    values.PutInt("age", age);
    values.PutDouble("salary", CHECKCOLUMN);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_001, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    ASSERT_TRUE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
    store = nullptr;
    RdbHelper::DeleteRdbStore(config);
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_002, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_FALSE(isBinlogExist);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_003, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isSlaveDbFileExist = OHOS::FileExists(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    ASSERT_TRUE(isSlaveDbFileExist);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_004, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isSlaveDbFileExist = OHOS::FileExists(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    ASSERT_FALSE(isSlaveDbFileExist);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    isSlaveDbFileExist = OHOS::FileExists(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    ASSERT_TRUE(isSlaveDbFileExist);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_005, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);
    store = nullptr;
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_006, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    DoubleWriteBinlogTestOpenCallback slaveHelper;
    RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
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
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_007, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);

    SqliteUtils::SetSlaveInvalid(RdbDoubleWriteBinlogTest::databaseName);
    std::string failureFlagPath = RdbDoubleWriteBinlogTest::databaseName + +"-slaveFailure";
    bool isFlagFileExists = OHOS::FileExists(failureFlagPath);
    ASSERT_TRUE(isFlagFileExists);
    store = nullptr;
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_008, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    DoubleWriteBinlogTestOpenCallback slaveHelper;
    RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);

    SqliteUtils::SetSlaveInvalid(RdbDoubleWriteBinlogTest::databaseName);
    std::string failureFlagPath = RdbDoubleWriteBinlogTest::databaseName + +"-slaveFailure";
    bool isFlagFileExists = OHOS::FileExists(failureFlagPath);
    ASSERT_TRUE(isFlagFileExists);
    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_FALSE(isBinlogExist);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_009, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb();
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    int64_t id = 1;
    int count = 10;
    Insert(id, count);

    store = nullptr;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
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
    RdbDoubleWriteBinlogTest::CheckNumber(store, num);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_010, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    DoubleWriteBinlogTestOpenCallback slaveHelper;
    RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
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
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
    id = 11;
    Insert(id, count);
    store = nullptr;
    DeleteDbFile(config);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    WaitForBackupFinish(BACKUP_FINISHED);
    int32_t num = 20;
    RdbDoubleWriteBinlogTest::CheckNumber(store, num);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_011, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb();
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    int64_t id = 1;
    int count = 10;
    Insert(id, count);

    store = nullptr;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
    id = 11;
    Insert(id, count);
    int32_t num = 20;
    RdbDoubleWriteBinlogTest::CheckNumber(store, num);
    CheckProcess(store);

    store = nullptr;
    DeleteDbFile(config);

    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    WaitForBackupFinish(BACKUP_FINISHED);
    num = 18;
    RdbDoubleWriteBinlogTest::CheckNumber(store, num);
    RdbDoubleWriteBinlogTest::CheckNumber(slaveStore, num);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_012, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    RdbStoreConfig slaveConfig(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    DoubleWriteBinlogTestOpenCallback slaveHelper;
    RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    store->ExecuteSql("DELETE FROM test");
    slaveStore->ExecuteSql("DELETE FROM test");
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    Insert(id, count, true);

    store = nullptr;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);
    id = 11;
    Insert(id, count);
    int32_t num = 20;
    RdbDoubleWriteBinlogTest::CheckNumber(store, num);
    CheckProcess(store);

    store = nullptr;
    DeleteDbFile(config);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    WaitForBackupFinish(BACKUP_FINISHED);
    num = 18;
    RdbDoubleWriteBinlogTest::CheckNumber(store, num);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_013, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    bool isSlaveDbFileExists = OHOS::FileExists(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    ASSERT_TRUE(isSlaveDbFileExists);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);

    int64_t id = 1;
    int count = 20;
    Insert(id, count);
    CheckProcess(store);

    int64_t num = 18;
    RdbDoubleWriteBinlogTest::CheckNumber(store, num);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    RdbStoreConfig slaveConfig(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    DoubleWriteBinlogTestOpenCallback slaveHelper;
    RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    RdbDoubleWriteBinlogTest::CheckNumber(slaveStore, num);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_014, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    bool isSlaveDbFileExists = OHOS::FileExists(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    ASSERT_FALSE(isSlaveDbFileExists);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    WaitForBackupFinish(BACKUP_FINISHED);
    isSlaveDbFileExists = OHOS::FileExists(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    ASSERT_TRUE(isSlaveDbFileExists);
    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);

    int64_t id = 1;
    int count = 20;
    Insert(id, count);
    CheckProcess(store);

    int64_t num = 18;
    RdbDoubleWriteBinlogTest::CheckNumber(store, num);
    errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    RdbStoreConfig slaveConfig(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    DoubleWriteBinlogTestOpenCallback slaveHelper;
    RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);
    RdbDoubleWriteBinlogTest::CheckNumber(slaveStore, num);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_015, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
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

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_016, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    int errCode = E_OK;
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store->ExecuteSql("DELETE FROM test");
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
    ASSERT_TRUE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));

    RdbStoreConfig slaveConfig(RdbDoubleWriteBinlogTest::slaveDatabaseName);
    DoubleWriteBinlogTestOpenCallback slaveHelper;
    RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    EXPECT_NE(slaveStore, nullptr);

    store = nullptr;
    std::string test = "lisi";
    pid_t pid1 = GtFork(InsertManualProcess, test.c_str());
    ASSERT_GT(pid1, 0);
    InsertManualTwoProcess(test.c_str());
    int status;
    waitpid(pid1, &status, 0);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_017, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;

    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);

    size_t bigSize = 1024 * 1024 * 128;
    std::string data(bigSize, 'a');
    PutValue(store, data, 11, 18);
    PutValue(store, data, 12, 19);

    store = nullptr;
    id = 13;
    for (int i = 0; i < count; i++) {
        config.SetHaMode(HAMode::MAIN_REPLICA);
        RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
        EXPECT_NE(store, nullptr);
        PutValue(store, data, id, CHECKAGE);
        store = nullptr;
        id++;
    }
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_018, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;

    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    bool isBinlogExist = CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    ASSERT_TRUE(isBinlogExist);

    size_t bigSize = 1024 * 1024 * 13;
    std::string data(bigSize, 'a');

    store = nullptr;
    id = 11;
    for (int i = 0; i < count; i++) {
        config.SetHaMode(HAMode::MAIN_REPLICA);
        RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
        EXPECT_NE(store, nullptr);
        PutValue(store, data, id, CHECKAGE);
        store = nullptr;
        id++;
    }
}

static int64_t GetInsertTime(std::shared_ptr<RdbStore> &rdbStore, int repeat, size_t dataSize)
{
    size_t bigSize = dataSize;
    std::string data(bigSize, 'a');
    
    LOG_INFO("---- start insert ----");
    int64_t totalCost = 0;
    for (int64_t id = 0; id < repeat; id++) {
        ValuesBucket values;
        values.PutInt("id", id);
        values.PutString("name", data);
        values.PutInt("age", id);
        values.PutDouble("salary", CHECKCOLUMN);
        values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
        auto begin = std::chrono::high_resolution_clock::now();
        int ret = rdbStore->Insert(id, "test", values);
        auto stop = std::chrono::high_resolution_clock::now();
        EXPECT_EQ(ret, E_OK);
        totalCost += std::chrono::duration_cast<std::chrono::microseconds>(stop - begin).count();
    }
    return totalCost;
}

static int64_t GetUpdateTime(std::shared_ptr<RdbStore> &rdbStore, int batchSize, int repeat, size_t dataSize)
{
    size_t bigSize = dataSize;
    std::string data(bigSize, 'b');
    LOG_INFO("---- start update ----");
    int64_t totalCost = 0;
    for (int i = 0; i < repeat; i++) {
        int start = i * batchSize;
        int end = (i + 1) * batchSize;
        std::string sql = "update test set name = '" + data + "' where id >= " + std::to_string(start) +
                          " and id < " + std::to_string(end) + ";";
        auto begin = std::chrono::high_resolution_clock::now();
        int ret = rdbStore->ExecuteSql(sql);
        auto stop = std::chrono::high_resolution_clock::now();
        EXPECT_EQ(ret, E_OK);
        totalCost += std::chrono::duration_cast<std::chrono::microseconds>(stop - begin).count();
    }
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

static int MockSupportBinlogOff(const char *name)
{
    return SQLITE_ERROR;
}

int64_t RdbDoubleWriteBinlogTest::GetRestoreTime(HAMode haMode)
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

    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    DoubleWriteBinlogTestOpenCallback helper;
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
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_001, TestSize.Level1)
{
    LOG_INFO("----RdbStore_Binlog_Performance_001 start----");
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb(HAMode::MAIN_REPLICA);
    EXPECT_NE(store, nullptr);
    if (!CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
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
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));

    InitDb(HAMode::SINGLE);
    EXPECT_NE(store, nullptr);

    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);

    EXPECT_LT(T1, T1_2 * 1.8);
    EXPECT_LT(T2, T2_2 * 1.8);
    EXPECT_LT(T3, T3_2 * 1.8);
    LOG_INFO("----RdbStore_Binlog_Performance_001----, %{public}" PRId64 ", %{public}" PRId64 ", %{public}" PRId64 ",",
        T1, T2, T3);
    LOG_INFO("----RdbStore_Binlog_Performance_001----, %{public}" PRId64 ", %{public}" PRId64 ", %{public}" PRId64 ",",
        T1_2, T2_2, T3_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_002
 * @tc.desc: test performance of insert, update, query and delete in mannual_trigger
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_002, TestSize.Level1)
{
    LOG_INFO("----RdbStore_Binlog_Performance_002 start----");
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb(HAMode::MANUAL_TRIGGER);
    EXPECT_NE(store, nullptr);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    if (!CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
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
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));

    InitDb(HAMode::SINGLE);
    ASSERT_NE(store, nullptr);

    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);

    EXPECT_LT(T1, T1_2 * 1.8);
    EXPECT_LT(T2, T2_2 * 1.8);
    EXPECT_LT(T3, T3_2 * 1.8);
    LOG_INFO("----RdbStore_Binlog_Performance_002----, %{public}" PRId64 ", %{public}" PRId64 ", %{public}" PRId64 ",",
        T1, T2, T3);
    LOG_INFO("----RdbStore_Binlog_Performance_002----, %{public}" PRId64 ", %{public}" PRId64 ", %{public}" PRId64 ",",
        T1_2, T2_2, T3_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_003
 * @tc.desc: test performance of insert, update, query and delete in main_replica with large data
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_003, TestSize.Level2)
{
    LOG_INFO("----RdbStore_Binlog_Performance_003 start----");
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb(HAMode::MAIN_REPLICA);
    EXPECT_NE(store, nullptr);
    if (!CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
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
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));

    InitDb(HAMode::SINGLE);
    EXPECT_NE(store, nullptr);

    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);

    EXPECT_LT(T1, T1_2 * 1.8);
    EXPECT_LT(T2, T2_2 * 1.8);
    EXPECT_LT(T3, T3_2 * 1.8);
    LOG_INFO("----RdbStore_Binlog_Performance_003----, %{public}" PRId64 ", %{public}" PRId64 ", %{public}" PRId64 ",",
        T1, T2, T3);
    LOG_INFO("----RdbStore_Binlog_Performance_003----, %{public}" PRId64 ", %{public}" PRId64 ", %{public}" PRId64 ",",
        T1_2, T2_2, T3_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_004
 * @tc.desc: test performance of insert, update, query and delete in mannual_trigger with large data
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_004, TestSize.Level2)
{
    LOG_INFO("----RdbStore_Binlog_Performance_004 start----");
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb(HAMode::MANUAL_TRIGGER);
    ASSERT_NE(store, nullptr);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    if (!CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
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
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));

    InitDb(HAMode::SINGLE);
    EXPECT_NE(store, nullptr);

    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);

    EXPECT_LT(T1, T1_2 * 1.8);
    EXPECT_LT(T2, T2_2 * 1.8);
    EXPECT_LT(T3, T3_2 * 1.8);
    LOG_INFO("----RdbStore_Binlog_Performance_004----, %{public}" PRId64 ", %{public}" PRId64 ", %{public}" PRId64 ",",
        T1, T2, T3);
    LOG_INFO("----RdbStore_Binlog_Performance_004----, %{public}" PRId64 ", %{public}" PRId64 ", %{public}" PRId64 ",",
        T1_2, T2_2, T3_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_005
 * @tc.desc: test performance of restore in main_replica
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_005, TestSize.Level1)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    struct sqlite3_api_routines_relational mockApi = *sqlite3_export_relational_symbols;
    mockApi.is_support_binlog = MockSupportBinlogOff;
    auto originalApi = sqlite3_export_relational_symbols;
    sqlite3_export_relational_symbols = &mockApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
    LOG_INFO("----RdbStore_Binlog_Performance_005 binlog off----");
    auto T1 = GetRestoreTime(HAMode::MAIN_REPLICA);

    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
    sqlite3_export_relational_symbols = originalApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), true);
    LOG_INFO("----RdbStore_Binlog_Performance_005 binlog on----");
    auto T1_2 = GetRestoreTime(HAMode::MAIN_REPLICA);
    EXPECT_GT(T1 * 1.8, T1_2);
    LOG_INFO("----RdbStore_Binlog_Performance_005----, %{public}" PRId64 ", %{public}" PRId64 ",", T1, T1_2);
}

/**
 * @tc.name: RdbStore_Binlog_Performance_006
 * @tc.desc: test performance of restore in mannual_trigger
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_006, TestSize.Level1)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    struct sqlite3_api_routines_relational mockApi = *sqlite3_export_relational_symbols;
    mockApi.is_support_binlog = MockSupportBinlogOff;
    auto originalApi = sqlite3_export_relational_symbols;
    sqlite3_export_relational_symbols = &mockApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
    LOG_INFO("----RdbStore_Binlog_Performance_006 binlog off----");
    auto T1 = GetRestoreTime(HAMode::MANUAL_TRIGGER);

    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
    sqlite3_export_relational_symbols = originalApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), true);
    LOG_INFO("----RdbStore_Binlog_Performance_006 binlog on----");
    auto T1_2 = GetRestoreTime(HAMode::MANUAL_TRIGGER);
    EXPECT_GT(T1 * 1.8, T1_2);
    LOG_INFO("----RdbStore_Binlog_Performance_006----, %{public}" PRId64 ", %{public}" PRId64 ",", T1, T1_2);
}
#endif // CROSS_PLATFORM
