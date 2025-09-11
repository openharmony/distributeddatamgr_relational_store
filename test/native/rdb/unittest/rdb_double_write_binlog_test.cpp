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
#include "acl.h"
#include "common.h"
#include "file_ex.h"
#include "logger.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_security_manager.h"
#include "relational/relational_store_sqlite_ext.h"
#include "sqlite3.h"
#include "sqlite_connection.h"
#include "sqlite_utils.h"
#include "sqlite_global_config.h"
#include "sys/types.h"
#include "rdb_platform.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;
using namespace OHOS::DATABASE_UTILS;
constexpr int32_t SERVICE_GID = 3012;

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
    static void InsertNativeConn(sqlite3 *db, int64_t start, int count, int dataSize = 0);
    void Update(int64_t start, int count, bool isSlave = false, int dataSize = 0);
    void CheckProcess(std::shared_ptr<RdbStore> &store);
    void DeleteDbFile(const RdbStoreConfig &config);
    void PutValue(std::shared_ptr<RdbStore> &store, const std::string &data, int64_t id, int age);
    static void WaitForBackupFinish(int32_t expectStatus, int maxTimes = 4000);
    static void WaitForBinlogDelete(int maxTimes = 1000);
    static void WaitForBinlogReplayFinish();
    static void WaitForAsyncRepairFinish(int maxTimes = 400);
    void InitDb(HAMode mode = HAMode::MAIN_REPLICA, bool isOpenSlave = true);
    int64_t GetRestoreTime(HAMode haMode, bool isOpenSlave = true);

    static const std::string databaseName;
    static const std::string slaveDatabaseName;
    static const std::string binlogDatabaseName;
    static const std::string binlogFirstFile;
    static const std::string binlogSecondFile;
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<RdbStore> slaveStore;
    static const std::string insertSql;

    enum SlaveStatus : uint32_t {
        UNDEFINED,
        BACKING_UP,
        BACKUP_INTERRUPT,
        BACKUP_FINISHED,
        DB_CLOSING,
    };
};

const std::string RdbDoubleWriteBinlogTest::databaseName = RDB_TEST_PATH + "dual_write_binlog_test.db";
const std::string RdbDoubleWriteBinlogTest::slaveDatabaseName = RDB_TEST_PATH + "dual_write_binlog_test_slave.db";
const std::string RdbDoubleWriteBinlogTest::binlogDatabaseName = RDB_TEST_PATH + "dual_write_binlog_test.db_binlog";
const std::string RdbDoubleWriteBinlogTest::binlogFirstFile =
    RdbDoubleWriteBinlogTest::binlogDatabaseName + "/binlog_default.00000";
const std::string RdbDoubleWriteBinlogTest::binlogSecondFile =
    RdbDoubleWriteBinlogTest::binlogDatabaseName + "/binlog_default.00001";
std::shared_ptr<RdbStore> RdbDoubleWriteBinlogTest::store = nullptr;
std::shared_ptr<RdbStore> RdbDoubleWriteBinlogTest::slaveStore = nullptr;
const std::string RdbDoubleWriteBinlogTest::insertSql = "INSERT INTO test(id, name, age, salary, blobType) VALUES"
                                                        "(?,?,?,?,?)";

static const int CHECKAGE = 18;
static const double CHECKCOLUMN = 100.5;
static const int CHANGENUM = 12;
static const int BINLOG_DELETE_PER_WAIT_TIME = 100000; // 100000us = 100ms
static const int BINLOG_REPLAY_WAIT_TIME = 2; // 2s
static const int BINLOG_FILE_SIZE = 4 * 1024 * 1024; // 4MB
static const int SIZE_MB = 1024 * 1024; // 1MB

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
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testInfo = test->current_test_info();
    ASSERT_NE(testInfo, nullptr);
    LOG_INFO("---- double writebinlog test: %{public}s.%{public}s run start.",
        testInfo->test_case_name(), testInfo->name());
}

void RdbDoubleWriteBinlogTest::TearDown(void)
{
    store = nullptr;
    slaveStore = nullptr;
    WaitForBinlogReplayFinish();
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    std::string lockCompressName = RdbDoubleWriteBinlogTest::slaveDatabaseName + "-lockcompress";
    bool isLockCompressFileExist = OHOS::FileExists(lockCompressName);
    ASSERT_FALSE(isLockCompressFileExist);
    WaitForBinlogDelete();
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testInfo = test->current_test_info();
    ASSERT_NE(testInfo, nullptr);
    LOG_INFO("---- double writebinlog test: %{public}s.%{public}s run end.",
        testInfo->test_case_name(), testInfo->name());
}

void RdbDoubleWriteBinlogTest::InitDb(HAMode mode, bool isOpenSlave)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    config.SetHaMode(mode);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    store->ExecuteSql("DELETE FROM test");

    if (isOpenSlave) {
        RdbStoreConfig slaveConfig(RdbDoubleWriteBinlogTest::slaveDatabaseName);
        DoubleWriteBinlogTestOpenCallback slaveHelper;
        RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
        ASSERT_NE(RdbDoubleWriteBinlogTest::slaveStore, nullptr);
        slaveStore->ExecuteSql("DELETE FROM test");
    }
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

void RdbDoubleWriteBinlogTest::InsertNativeConn(sqlite3 *db, int64_t start, int count, int dataSize)
{
    int64_t id = start;
    sqlite3_stmt *stat = nullptr;
    EXPECT_EQ(sqlite3_prepare_v2(db, RdbDoubleWriteBinlogTest::insertSql.c_str(), -1, &stat, nullptr), SQLITE_OK);
    for (int i = 0; i < count; i++) {
        // bind parameters, 1 is the sequence number of field
        sqlite3_bind_int(stat, 1, id);
        std::string nameStr;
        if (dataSize > 0) {
            nameStr = std::string(dataSize, 'a');
        } else {
            nameStr = std::string("zhangsan");
        }
        // bind parameters, 2 is the sequence number of field
        sqlite3_bind_text(stat, 2, nameStr.c_str(), -1, SQLITE_STATIC);
        // bind parameters, 3 is the sequence number of field
        sqlite3_bind_int(stat, 3, CHECKAGE);
        // bind parameters, 4 is the sequence number of field
        sqlite3_bind_double(stat, 4, CHECKCOLUMN);
        uint8_t blob[] = { 1, 2, 3 };
        // bind parameters, 5 is the sequence number of field
        sqlite3_bind_blob(stat, 5, blob, sizeof(blob), nullptr);
        EXPECT_EQ(sqlite3_step(stat), SQLITE_DONE);
        sqlite3_reset(stat);
        id++;
    }
    sqlite3_finalize(stat);
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

void RdbDoubleWriteBinlogTest::WaitForBinlogReplayFinish()
{
    sleep(BINLOG_REPLAY_WAIT_TIME);
}

void RdbDoubleWriteBinlogTest::WaitForAsyncRepairFinish(int maxTimes)
{
    LOG_INFO("---- start wait for async finish----");
    sleep(1);
    int tryTimes = 0;
    auto keyFiles = RdbSecurityManager::KeyFiles(databaseName + "-async.restore");
    while (keyFiles.Lock(false) != E_OK && (++tryTimes <= maxTimes)) {
        sleep(1);
    }
    LOG_INFO("---- end wait for async finish ----, %{public}d", tryTimes);
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
    std::string lockCompressName = RdbDoubleWriteBinlogTest::slaveDatabaseName + "-lockcompress";
    bool isLockCompressFileExist = OHOS::FileExists(lockCompressName);
    ASSERT_TRUE(isLockCompressFileExist);
    RdbHelper::DeleteRdbStore(config);
    isLockCompressFileExist = OHOS::FileExists(lockCompressName);
    ASSERT_FALSE(isLockCompressFileExist);
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
    store->ExecuteSql("DELETE FROM test");

    // open slave for conflict by compress
    sqlite3 *db = nullptr;
    int rc = sqlite3_open_v2(RdbDoubleWriteBinlogTest::slaveDatabaseName.c_str(),
        &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    EXPECT_EQ(rc, SQLITE_OK);
    EXPECT_NE(db, nullptr);
    sqlite3_close_v2(db);

    int64_t id = 1;
    int count = 10;
    Insert(id, count);
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
    store->ExecuteSql("DELETE FROM test");

    // open slave for conflict by compress
    sqlite3 *db = nullptr;
    int rc = sqlite3_open_v2(RdbDoubleWriteBinlogTest::slaveDatabaseName.c_str(),
        &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
    EXPECT_EQ(rc, SQLITE_OK);
    EXPECT_NE(db, nullptr);
    sqlite3_close_v2(db);

    int64_t id = 1;
    int count = 10;
    Insert(id, count);

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
    InitDb(HAMode::MAIN_REPLICA, false);
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
    WaitForBinlogReplayFinish();
    store = nullptr;
    DeleteDbFile(config);

    config.SetHaMode(HAMode::MAIN_REPLICA);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    WaitForBackupFinish(BACKUP_FINISHED);
    WaitForBinlogReplayFinish();
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
    store->ExecuteSql("DELETE FROM test");

    int64_t id = 1;
    int count = 10;
    Insert(id, count);

    // open slave for conflict by compress
    sqlite3 *db = nullptr;
    int rc = sqlite3_open_v2(RdbDoubleWriteBinlogTest::slaveDatabaseName.c_str(),
        &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "compressvfs");
    EXPECT_EQ(rc, SQLITE_OK);
    EXPECT_NE(db, nullptr);
    const char *ddl = DoubleWriteBinlogTestOpenCallback::createTableTest.c_str();
    EXPECT_EQ(sqlite3_exec(db, ddl, nullptr, nullptr, nullptr), SQLITE_OK);
    InsertNativeConn(db, id, count);
    sqlite3_close_v2(db);

    store = nullptr;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    WaitForBinlogReplayFinish();
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
    InitDb(HAMode::MAIN_REPLICA, false);
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    int64_t id = 1;
    int count = 10;
    Insert(id, count);

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
    WaitForBinlogReplayFinish();
    num = 18;
    RdbDoubleWriteBinlogTest::CheckNumber(store, num);
}

HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_012, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }

    InitDb(HAMode::MAIN_REPLICA, false);
    int64_t id = 1;
    int count = 10;
    Insert(id, count);

    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    DoubleWriteBinlogTestOpenCallback helper;
    int errCode = E_OK;
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

static int Callback(void *data, int argc, char **argv, char **azColName)
{
    int64_t *count = (int64_t *)data;
    if (argc > 0 && argv[0] != nullptr) {
        *count = atoi(argv[0]);
    }
    return 0;
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

    // open slave for conflict by compress
    sqlite3 *db = nullptr;
    int rc = sqlite3_open_v2(RdbDoubleWriteBinlogTest::slaveDatabaseName.c_str(),
        &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "compressvfs");
    EXPECT_EQ(rc, SQLITE_OK);
    EXPECT_NE(db, nullptr);

    count = 0;
    rc = sqlite3_exec(db, "SELECT COUNT(1) FROM test;", Callback, &count, nullptr);
    EXPECT_EQ(rc, SQLITE_OK);
    EXPECT_EQ(count, num);
    sqlite3_close_v2(db);
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

    // open slave for conflict by compress
    sqlite3 *db = nullptr;
    int rc = sqlite3_open_v2(RdbDoubleWriteBinlogTest::slaveDatabaseName.c_str(),
        &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, "compressvfs");
    EXPECT_EQ(rc, SQLITE_OK);
    EXPECT_NE(db, nullptr);
    count = 0;
    rc = sqlite3_exec(db, "SELECT COUNT(1) FROM test;", Callback, &count, nullptr);
    EXPECT_EQ(rc, SQLITE_OK);
    EXPECT_EQ(count, num);
    sqlite3_close_v2(db);
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
    WaitForBinlogReplayFinish();
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
    WaitForBinlogReplayFinish();
}

/**
 * @tc.name: RdbStore_Binlog_019
 * @tc.desc: open MAIN_REPLICA db when replica is invalid,
 *           then batch insert new data and test main and replica are the same
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_019, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;
    slaveStore = nullptr;
    SqliteUtils::SetSlaveInvalid(RdbDoubleWriteBinlogTest::databaseName);

    LOG_INFO("---- open db when slave is invalid to trigger backup");
    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    WaitForBinlogReplayFinish();
    LOG_INFO("---- insert after backup after wait");
    int totalCount = count;
    id += totalCount;
    count = 1000; // 1000 is one batch
    Insert(id, count);
    totalCount += count;
    EXPECT_TRUE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
    EXPECT_FALSE(SqliteUtils::IsSlaveInvalid(RdbDoubleWriteBinlogTest::databaseName));
    RdbDoubleWriteBinlogTest::CheckNumber(store, totalCount);
    store = nullptr;
    SqliteUtils::DeleteFile(databaseName);
    LOG_INFO("---- check for data count after restore");
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    RdbDoubleWriteBinlogTest::CheckNumber(store, totalCount);
}

static int MockCleanBinlog(sqlite3* db, BinlogFileCleanModeE mode)
{
    return SQLITE_ERROR;
}

static int MockSupportBinlogOff(const char *name)
{
    return SQLITE_ERROR;
}
/**
 * @tc.name: RdbStore_Binlog_020
 * @tc.desc: test backup when binlog clean failed will mark slave invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_020, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    
    LOG_INFO("---- let binlog clean return ERROR");
    auto originalApi = sqlite3_export_extra_symbols;
    struct sqlite3_api_routines_extra mockApi = *sqlite3_export_extra_symbols;
    mockApi.clean_binlog = MockCleanBinlog;
    sqlite3_export_extra_symbols = &mockApi;

    LOG_INFO("---- binlog clean failed should mark invalid");
    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
    EXPECT_TRUE(SqliteUtils::IsSlaveInvalid(RdbDoubleWriteBinlogTest::databaseName));
    sqlite3_export_extra_symbols = originalApi;
}

/**
 * @tc.name: RdbStore_Binlog_021
 * @tc.desc: test delete rdb store will work if binlog is not supported
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_021, TestSize.Level0)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
    InitDb();
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;
    slaveStore = nullptr;
    
    LOG_INFO("---- let support binlog becomes off");
    struct sqlite3_api_routines_relational mockApi = *sqlite3_export_relational_symbols;
    mockApi.is_support_binlog = MockSupportBinlogOff;
    auto originalApi = sqlite3_export_relational_symbols;
    sqlite3_export_relational_symbols = &mockApi;

    LOG_INFO("---- rdb delete store should return ok");
    EXPECT_EQ(RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName), E_OK);
    sqlite3_export_relational_symbols = originalApi;
}

/**
 * @tc.name: RdbStore_Binlog_022
 * @tc.desc: test exist slaveFailure flag but slave db integrity check ok
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_022, TestSize.Level0)
{
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
    int errCode = E_OK;
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    store->ExecuteSql("DELETE FROM test");

    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    store = nullptr;
    slaveStore = nullptr;

    LOG_INFO("---- Create flag file:-slaveFailure, simulate main db lost");
    EXPECT_EQ(SqliteUtils::SetSlaveInvalid(RdbDoubleWriteBinlogTest::databaseName), E_OK);
    EXPECT_TRUE(SqliteUtils::DeleteFile(databaseName));

    LOG_INFO("---- Reopen db, restore from slave");
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    bool isDbFileExist = OHOS::FileExists(RdbDoubleWriteBinlogTest::databaseName);
    ASSERT_TRUE(isDbFileExist);
    RdbDoubleWriteBinlogTest::CheckNumber(RdbDoubleWriteBinlogTest::store, count);
}

/**
 * @tc.name: RdbStore_Binlog_023
 * @tc.desc: test setacl when open binlog
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_023, TestSize.Level0)
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
    config.SetSearchable(true);
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

    bool ret = SqliteUtils::HasAccessAcl(std::string(RdbDoubleWriteBinlogTest::databaseName), SERVICE_GID);
    EXPECT_EQ(ret, true);
    ret = SqliteUtils::HasAccessAcl(std::string(RdbDoubleWriteBinlogTest::databaseName) + "-dwr", SERVICE_GID);
    EXPECT_EQ(ret, true);
    ret = SqliteUtils::HasAccessAcl(std::string(RdbDoubleWriteBinlogTest::databaseName) + "-shm", SERVICE_GID);
    EXPECT_EQ(ret, true);
    ret = SqliteUtils::HasAccessAcl(std::string(RdbDoubleWriteBinlogTest::databaseName) + "-wal", SERVICE_GID);
    EXPECT_EQ(ret, true);
    ret = SqliteUtils::HasAccessAcl(std::string(RdbDoubleWriteBinlogTest::binlogDatabaseName), SERVICE_GID);
    EXPECT_EQ(ret, true);
    ret = SqliteUtils::HasDefaultAcl(std::string(RdbDoubleWriteBinlogTest::binlogDatabaseName), SERVICE_GID);
    EXPECT_EQ(ret, true);

    WaitForBinlogReplayFinish();
}

/**
 * @tc.name: RdbStore_Binlog_024
 * @tc.desc: test binlog will replay and clean after re-open
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_024, TestSize.Level0)
{
    ASSERT_FALSE(CheckFolderExist(binlogDatabaseName));
    int errCode = E_OK;
    RdbStoreConfig config(databaseName);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    store->ExecuteSql("DELETE FROM test");
    LOG_INFO("---- step1 close db and binlog should be created");
    store = nullptr;
    ASSERT_TRUE(CheckFolderExist(binlogDatabaseName));
    ASSERT_TRUE(CheckFolderExist(binlogFirstFile));

    LOG_INFO("---- step2 Reopen db and insert large data");
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    WaitForBinlogReplayFinish();
    int64_t id = 1;
    int count = 3;
    Insert(id, count, false, BINLOG_FILE_SIZE);
    store = nullptr;

    LOG_INFO("---- step3 binlog should be replayed");
    WaitForBinlogReplayFinish();
    ASSERT_FALSE(CheckFolderExist(binlogFirstFile));
}

/**
 * @tc.name: RdbStore_Binlog_025
 * @tc.desc: test restore when restoring mark exists but no one is restoring
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_025, TestSize.Level0)
{
    ASSERT_FALSE(CheckFolderExist(binlogDatabaseName));
    int errCode = E_OK;
    RdbStoreConfig config(databaseName);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteBinlogTestOpenCallback helper;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    store->ExecuteSql("DELETE FROM test");
    LOG_INFO("---- step1 insert 1.2 GB data");
    int64_t id = 1;
    int count = 1200; // data size
    Insert(id, count, false, SIZE_MB);
    CheckNumber(store, count);
    store = nullptr;
    LOG_INFO("---- step2 create restoring mark and corrupt db");
    WaitForBinlogReplayFinish();
    SqliteUtils::DeleteFile(databaseName);
    EXPECT_EQ(SqliteUtils::SetSlaveRestoring(databaseName), E_OK);
    EXPECT_TRUE(SqliteUtils::IsSlaveRestoring(databaseName));
    LOG_INFO("---- step3 open should trigger restore");
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbDoubleWriteBinlogTest::store, nullptr);
    WaitForAsyncRepairFinish();
    CheckNumber(store, count);
}

/**
 * @tc.name: RdbStore_Binlog_026
 * @tc.desc: test after binlog is turned off, main and replica is the same
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_026, TestSize.Level0)
{
    LOG_INFO("---- step1 open db with binlog enabled");
    RdbStoreConfig config(databaseName);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    DoubleWriteBinlogTestOpenCallback helper;
    int errCode = E_OK;
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    store->ExecuteSql("DELETE FROM test");
    LOG_INFO("---- step2 insert data");
    int64_t id = 1;
    int count = 20; // data size
    Insert(id, count);
    CheckNumber(store, count);
    LOG_INFO("---- step3 close db and turn off binlog");
    store = nullptr;
    WaitForBinlogReplayFinish();
    struct sqlite3_api_routines_relational mockApi = *sqlite3_export_relational_symbols;
    mockApi.is_support_binlog = MockSupportBinlogOff;
    auto originalApi = sqlite3_export_relational_symbols;
    sqlite3_export_relational_symbols = &mockApi;
    LOG_INFO("---- step4 open db with binlog turned off");
    RdbDoubleWriteBinlogTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    WaitForBackupFinish(BACKUP_FINISHED);
    LOG_INFO("---- step5 check replica count");
    RdbStoreConfig slaveConfig(slaveDatabaseName);
    DoubleWriteBinlogTestOpenCallback slaveHelper;
    RdbDoubleWriteBinlogTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
    ASSERT_NE(slaveStore, nullptr);
    CheckNumber(slaveStore, count);
    sqlite3_export_relational_symbols = originalApi;
}

/**
 * @tc.name: RdbStore_Binlog_027
 * @tc.desc: test binlog will not replay if replica is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_027, TestSize.Level0)
{
    LOG_INFO("---- step1 open db and binlog should be created");
    ASSERT_FALSE(CheckFolderExist(binlogDatabaseName));
    InitDb(HAMode::MAIN_REPLICA, false);
    ASSERT_NE(store, nullptr);
    ASSERT_TRUE(CheckFolderExist(binlogDatabaseName));
    EXPECT_TRUE(CheckFolderExist(binlogFirstFile));
    LOG_INFO("---- step2 insert data, first file should be replayed and second is left");
    int64_t id = 1;
    int count = 2;
    Insert(id, count, false, BINLOG_FILE_SIZE);
    WaitForBinlogReplayFinish();
    EXPECT_FALSE(CheckFolderExist(binlogFirstFile));
    EXPECT_TRUE(CheckFolderExist(binlogSecondFile));
    LOG_INFO("---- step3 insert data when invalid, binlog should not be replayed");
    SqliteUtils::SetSlaveInvalid(databaseName);
    id += count;
    Insert(id, count, false, BINLOG_FILE_SIZE);
    EXPECT_TRUE(CheckFolderExist(binlogSecondFile));
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

int64_t RdbDoubleWriteBinlogTest::GetRestoreTime(HAMode haMode, bool isOpenSlave)
{
    InitDb(haMode, isOpenSlave);
    EXPECT_NE(store, nullptr);
    if (haMode == HAMode::MANUAL_TRIGGER) {
        int errCode = store->Backup(std::string(""), {});
        EXPECT_EQ(errCode, E_OK);
    }
    int id = 1;
    int totalCount = 20000;
    int size = 1024;
    Insert(id, totalCount, false, size);
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
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_001, TestSize.Level2)
{
    LOG_INFO("----RdbStore_Binlog_Performance_001 start----");
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb(HAMode::SINGLE);
    EXPECT_NE(store, nullptr);
    if (!CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        return;
    }
 
    int totalCount = 20000;
    int dataSize = 1024;
    int batchSize = 10;
    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));

    InitDb(HAMode::MAIN_REPLICA);
    EXPECT_NE(store, nullptr);

    auto T1 = GetInsertTime(store, totalCount, dataSize);
    auto T2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3 = GetDeleteTime(store, batchSize, totalCount / batchSize);

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
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_002, TestSize.Level2)
{
    LOG_INFO("----RdbStore_Binlog_Performance_002 start----");
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    if (CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        RemoveFolder(RdbDoubleWriteBinlogTest::binlogDatabaseName);
    }
    InitDb(HAMode::SINGLE);
    ASSERT_NE(store, nullptr);

    int totalCount = 20000;
    int dataSize = 200;
    int batchSize = 1;
    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);

    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));

    InitDb(HAMode::MANUAL_TRIGGER);
    EXPECT_NE(store, nullptr);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    if (!CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        return;
    }

    auto T1 = GetInsertTime(store, totalCount, dataSize);
    auto T2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3 = GetDeleteTime(store, batchSize, totalCount / batchSize);

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
    InitDb(HAMode::SINGLE);
    EXPECT_NE(store, nullptr);

    int totalCount = 200;
    int dataSize = 1024 * 1024;
    int batchSize = 10;
    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));

    InitDb(HAMode::MAIN_REPLICA);
    EXPECT_NE(store, nullptr);
    if (!CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        return;
    }

    auto T1 = GetInsertTime(store, totalCount, dataSize);
    auto T2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3 = GetDeleteTime(store, batchSize, totalCount / batchSize);

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
    InitDb(HAMode::SINGLE);
    EXPECT_NE(store, nullptr);

    int totalCount = 200;
    int dataSize = 1024 * 1024;
    int batchSize = 10;
    auto T1_2 = GetInsertTime(store, totalCount, dataSize);
    auto T2_2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3_2 = GetDeleteTime(store, batchSize, totalCount / batchSize);
    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));

    InitDb(HAMode::MANUAL_TRIGGER);
    ASSERT_NE(store, nullptr);
    int errCode = store->Backup(std::string(""), {});
    EXPECT_EQ(errCode, E_OK);
    if (!CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName)) {
        return;
    }

    auto T1 = GetInsertTime(store, totalCount, dataSize);
    auto T2 = GetUpdateTime(store, batchSize, totalCount / batchSize, dataSize);
    auto T3 = GetDeleteTime(store, batchSize, totalCount / batchSize);

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
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_005, TestSize.Level3)
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
HWTEST_F(RdbDoubleWriteBinlogTest, RdbStore_Binlog_Performance_006, TestSize.Level3)
{
    RdbStoreConfig config(RdbDoubleWriteBinlogTest::databaseName);
    struct sqlite3_api_routines_relational mockApi = *sqlite3_export_relational_symbols;
    mockApi.is_support_binlog = MockSupportBinlogOff;
    auto originalApi = sqlite3_export_relational_symbols;
    sqlite3_export_relational_symbols = &mockApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), false);
    LOG_INFO("----RdbStore_Binlog_Performance_006 binlog off----");
    auto T1 = GetRestoreTime(HAMode::MANUAL_TRIGGER, false);

    store = nullptr;
    slaveStore = nullptr;
    RdbHelper::DeleteRdbStore(RdbDoubleWriteBinlogTest::databaseName);
    WaitForBinlogDelete();
    ASSERT_FALSE(CheckFolderExist(RdbDoubleWriteBinlogTest::binlogDatabaseName));
    sqlite3_export_relational_symbols = originalApi;
    EXPECT_EQ(SqliteConnection::IsSupportBinlog(config), true);
    LOG_INFO("----RdbStore_Binlog_Performance_006 binlog on----");
    auto T1_2 = GetRestoreTime(HAMode::MANUAL_TRIGGER, false);
    EXPECT_GT(T1 * 1.8, T1_2);
    LOG_INFO("----RdbStore_Binlog_Performance_006----, %{public}" PRId64 ", %{public}" PRId64 ",", T1, T1_2);
}
