/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define LOG_TAG "RdbReplicaPathTest"
#include <gtest/gtest.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "common.h"
#include "file_ex.h"
#include "logger.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_platform.h"
#include "sqlite_utils.h"
#include "task_executor.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

static const int CHECKAGE = 18;
static const double CHECKCOLUMN = 100.5;
static const int BINLOG_DELETE_PER_WAIT_TIME = 100000; // 100000us = 100ms
static const int BINLOG_REPLAY_WAIT_TIME = 2; // 2s

class ReplicaPathTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string createTableTest;
};

const std::string ReplicaPathTestOpenCallback::createTableTest =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");

int ReplicaPathTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(ReplicaPathTestOpenCallback::createTableTest);
}

int ReplicaPathTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

class RdbReplicaPathTest : public testing::Test {
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
    static void WaitForBackupFinish(int32_t expectStatus, int maxTimes = 4000);
    static void WaitForBinlogDelete(int maxTimes = 1000);
    static void WaitForBinlogReplayFinish();
    void InitDb(HAMode mode = HAMode::MAIN_REPLICA, bool isOpenSlave = true, bool isSearchable = false);

    static const std::string databaseName;
    static const std::string slaveDatabaseName;
    static const std::string binlogDatabaseName;
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<RdbStore> slaveStore;
};

const std::string RdbReplicaPathTest::databaseName = RDB_TEST_PATH + "dual_write_binlog_test.db";
const std::string RdbReplicaPathTest::slaveDatabaseName = RDB_TEST_PATH + "dual_write_binlog_test_slave.db";
const std::string RdbReplicaPathTest::binlogDatabaseName = RDB_TEST_PATH + "dual_write_binlog_test.db_binlog";
std::shared_ptr<RdbStore> RdbReplicaPathTest::store = nullptr;
std::shared_ptr<RdbStore> RdbReplicaPathTest::slaveStore = nullptr;

void RdbReplicaPathTest::SetUpTestCase(void)
{
}

void RdbReplicaPathTest::TearDownTestCase(void)
{
}

void RdbReplicaPathTest::SetUp(void)
{
    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    if (!SqliteUtils::IsSupportBinlog(config)) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testInfo = test->current_test_info();
    ASSERT_NE(testInfo, nullptr);
    LOG_INFO("---- replica path test: %{public}s.%{public}s run start.",
        testInfo->test_case_name(), testInfo->name());
}

void RdbReplicaPathTest::TearDown(void)
{
    store = nullptr;
    slaveStore = nullptr;
    TaskExecutor::GetInstance().Stop();
    RdbHelper::DeleteRdbStore(RdbReplicaPathTest::databaseName);
    std::string lockCompressName = RdbReplicaPathTest::slaveDatabaseName + "-lockcompress";
    bool isLockCompressFileExist = OHOS::FileExists(lockCompressName);
    ASSERT_FALSE(isLockCompressFileExist);
    WaitForBinlogDelete();
    testing::UnitTest *test = testing::UnitTest::GetInstance();
    ASSERT_NE(test, nullptr);
    const testing::TestInfo *testInfo = test->current_test_info();
    ASSERT_NE(testInfo, nullptr);
    LOG_INFO("---- replica path test: %{public}s.%{public}s run end.",
        testInfo->test_case_name(), testInfo->name());
}

void RdbReplicaPathTest::InitDb(HAMode mode, bool isOpenSlave, bool isSearchable)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    config.SetHaMode(mode);
    config.SetSearchable(isSearchable);
    ReplicaPathTestOpenCallback helper;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbReplicaPathTest::store, nullptr);
    store->ExecuteSql("DELETE FROM test");

    if (isOpenSlave) {
        RdbStoreConfig slaveConfig(RdbReplicaPathTest::slaveDatabaseName);
        ReplicaPathTestOpenCallback slaveHelper;
        RdbReplicaPathTest::slaveStore = RdbHelper::GetRdbStore(slaveConfig, 1, slaveHelper, errCode);
        ASSERT_NE(RdbReplicaPathTest::slaveStore, nullptr);
        slaveStore->ExecuteSql("DELETE FROM test");
    }
}

void RdbReplicaPathTest::Insert(int64_t start, int count, bool isSlave, int dataSize)
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

void RdbReplicaPathTest::WaitForBackupFinish(int32_t expectStatus, int maxTimes)
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

void RdbReplicaPathTest::WaitForBinlogDelete(int maxTimes)
{
    int waitTimes = 0;
    while (CheckFolderExist(RdbReplicaPathTest::binlogDatabaseName) && waitTimes < maxTimes) {
        usleep(BINLOG_DELETE_PER_WAIT_TIME);
        waitTimes++;
        LOG_INFO("---- Binlog replay in progress, waiting for finish");
        RdbHelper::DeleteRdbStore(RdbReplicaPathTest::databaseName);
    }
    EXPECT_FALSE(CheckFolderExist(RdbReplicaPathTest::binlogDatabaseName));
}

void RdbReplicaPathTest::WaitForBinlogReplayFinish()
{
    sleep(BINLOG_REPLAY_WAIT_TIME);
}

void RdbReplicaPathTest::CheckNumber(
    std::shared_ptr<RdbStore> &store, int num, int errCode, const std::string &tableName)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM " + tableName);
    ASSERT_NE(resultSet, nullptr);
    int countNum;
    int ret = resultSet->GetRowCount(countNum);
    EXPECT_EQ(ret, errCode);
    EXPECT_EQ(num, countNum);
}

bool RdbReplicaPathTest::CheckFolderExist(const std::string &path)
{
    if (access(path.c_str(), F_OK) != 0) {
        return false;
    }
    return true;
}

void RdbReplicaPathTest::RemoveFolder(const std::string &path)
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

/**
 * @tc.name: RdbStore_ReplicaPath_001
 * @tc.desc: Test in REPLICA mode, reopen the database with ReplicaPath as path A
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_001, TestSize.Level0)
{
    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    EXPECT_TRUE(config.GetReplicaPath().empty());
    EXPECT_EQ(SqliteUtils::GetSlavePath(config), SqliteUtils::GetSlavePath(config.GetPath()));
    EXPECT_EQ(SqliteUtils::GetSlavePath(config), RdbReplicaPathTest::slaveDatabaseName);
    int errCode = E_OK;
    ReplicaPathTestOpenCallback helper;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_TRUE(store->IsSlaveAvailable());
}

/**
 * @tc.name: RdbStore_ReplicaPath_002
 * @tc.desc: Test in REPLICA mode, reopen the database with ReplicaPath as path A
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_002, TestSize.Level0)
{
    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    std::string customSlaveDir = RDB_TEST_PATH + "custom_slave_dir_002";
    std::string expectedSlaveFile = customSlaveDir + "/dual_write_binlog_test_slave.db";
    if (CheckFolderExist(customSlaveDir)) {
        RemoveFolder(customSlaveDir);
    }
    std::error_code ec;
    std::filesystem::create_directories(customSlaveDir, ec);
    ASSERT_TRUE(std::filesystem::is_directory(customSlaveDir));

    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetReplicaPath(customSlaveDir);
    int errCode = E_OK;
    ReplicaPathTestOpenCallback helper;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(SqliteUtils::GetSlavePath(config), expectedSlaveFile);

    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    RdbReplicaPathTest::CheckNumber(store, count);

    LOG_INFO("---- reopen and verify slave generated at the custom dir");
    store = nullptr;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(access(expectedSlaveFile.c_str(), F_OK), 0);
    EXPECT_TRUE(store->IsSlaveAvailable());
    std::string binlogNewPath = customSlaveDir + "/dual_write_binlog_test.db_binlog";
    ASSERT_TRUE(CheckFolderExist(binlogNewPath));
    RdbReplicaPathTest::CheckNumber(store, count);

    store = nullptr;
    RemoveFolder(customSlaveDir);
}

/**
 * @tc.name: RdbStore_ReplicaPath_003
 * @tc.desc: Test ReplicaPath from empty to patch A in REPLICA mode
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_003, TestSize.Level0)
{
    std::string customSlaveDir = RDB_TEST_PATH + "custom_slave_dir_003";
    std::string expectedSlaveFile = customSlaveDir + "/dual_write_binlog_test_slave.db";
    if (CheckFolderExist(customSlaveDir)) {
        RemoveFolder(customSlaveDir);
    }
    std::error_code ec;
    std::filesystem::create_directories(customSlaveDir, ec);

    LOG_INFO("---- step1 open MAIN_REPLICA with the legacy default slave path and insert rows");
    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    int errCode = E_OK;
    ReplicaPathTestOpenCallback helper;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbReplicaPathTest::store, nullptr);
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    ASSERT_TRUE(OHOS::FileExists(RdbReplicaPathTest::slaveDatabaseName));
    store = nullptr;

    LOG_INFO("---- step2 reopen MAIN_REPLICA with a custom slave dir;");
    config.SetReplicaPath(customSlaveDir);
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(RdbReplicaPathTest::store, nullptr);
    WaitForBackupFinish(BACKUP_FINISHED);
    ASSERT_FALSE(OHOS::FileExists(RdbReplicaPathTest::slaveDatabaseName));
    ASSERT_TRUE(OHOS::FileExists(expectedSlaveFile));
    EXPECT_TRUE(store->IsSlaveAvailable());
    EXPECT_FALSE(store->IsSlaveDiffFromMaster());
    ASSERT_FALSE(CheckFolderExist(binlogDatabaseName));
    std::string binlogNewPath = customSlaveDir + "/dual_write_binlog_test.db_binlog";
    ASSERT_TRUE(CheckFolderExist(binlogNewPath));
    RdbReplicaPathTest::CheckNumber(store, count);

    store = nullptr;
    RemoveFolder(customSlaveDir);
}

/**
 * @tc.name: RdbStore_ReplicaPath_004
 * @tc.desc: Test ReplicaPath from path A to path B in REPLICA mode
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_004, TestSize.Level0)
{
    std::string dirA = RDB_TEST_PATH + "custom_slave_dirA_004";
    std::string dirB = RDB_TEST_PATH + "custom_slave_dirB_004";
    std::string expectedSlaveA = dirA + "/dual_write_binlog_test_slave.db";
    std::string expectedSlaveB = dirB + "/dual_write_binlog_test_slave.db";
    if (CheckFolderExist(dirA)) {
        RemoveFolder(dirA);
    }
    if (CheckFolderExist(dirB)) {
        RemoveFolder(dirB);
    }
    std::error_code ec;
    std::filesystem::create_directories(dirA, ec);
    std::filesystem::create_directories(dirB, ec);

    LOG_INFO("---- step1: open with custom slave dir A and insert data");
    int errCode = E_OK;
    ReplicaPathTestOpenCallback helper;
    RdbStoreConfig configA(RdbReplicaPathTest::databaseName);
    configA.SetHaMode(HAMode::MAIN_REPLICA);
    configA.SetReplicaPath(dirA);
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(configA, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    store->ExecuteSql("DELETE FROM test");
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    RdbReplicaPathTest::CheckNumber(store, count);
    EXPECT_TRUE(store->IsSlaveAvailable());
    ASSERT_TRUE(OHOS::FileExists(expectedSlaveA));
    store = nullptr;

    RdbStoreConfig configB(RdbReplicaPathTest::databaseName);
    configB.SetHaMode(HAMode::MAIN_REPLICA);
    configB.SetReplicaPath(dirB);
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(configB, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

    ASSERT_TRUE(OHOS::FileExists(expectedSlaveA));
    ASSERT_TRUE(OHOS::FileExists(expectedSlaveB));
    EXPECT_TRUE(store->IsSlaveAvailable());
    EXPECT_FALSE(SqliteUtils::IsSlaveInvalid(RdbReplicaPathTest::databaseName));
    std::string binlogNewPathA = dirA + "/dual_write_binlog_test.db_binlog";
    ASSERT_TRUE(CheckFolderExist(binlogNewPathA));
    std::string binlogNewPathB = dirB + "/dual_write_binlog_test.db_binlog";
    ASSERT_TRUE(CheckFolderExist(binlogNewPathB));
    RdbReplicaPathTest::CheckNumber(store, count);

    store = nullptr;
    RemoveFolder(dirA);
    RemoveFolder(dirB);
}

/**
 * @tc.name: RdbStore_ReplicaPath_005
 * @tc.desc: Test ReplicaPath from path A to empty in REPLICA mode
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_005, TestSize.Level0)
{
    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    std::string customSlaveDirA = RDB_TEST_PATH + "custom_slave_dir_a_005";
    std::string expectedSlaveA = customSlaveDirA + "/dual_write_binlog_test_slave.db";
    if (CheckFolderExist(customSlaveDirA)) {
        RemoveFolder(customSlaveDirA);
    }
    std::error_code ec;
    std::filesystem::create_directories(customSlaveDirA, ec);

    LOG_INFO("---- step1 open with SetReplicaPath(dirA) and insert data ----");
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetReplicaPath(customSlaveDirA);
    int errCode = E_OK;
    ReplicaPathTestOpenCallback helper;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    EXPECT_TRUE(store->IsSlaveAvailable());
    ASSERT_TRUE(OHOS::FileExists(expectedSlaveA));

    LOG_INFO("---- step2 clear custom slave path (legacy default), reopen ----");
    store = nullptr;
    RdbStoreConfig config2(RdbReplicaPathTest::databaseName);
    config2.SetHaMode(HAMode::MAIN_REPLICA);
    ReplicaPathTestOpenCallback helper2;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config2, 1, helper2, errCode);
    ASSERT_NE(store, nullptr);

    EXPECT_TRUE(OHOS::FileExists(expectedSlaveA));
    ASSERT_TRUE(OHOS::FileExists(RdbReplicaPathTest::slaveDatabaseName));
    EXPECT_TRUE(store->IsSlaveAvailable());
    RdbReplicaPathTest::CheckNumber(store, count);
    ASSERT_TRUE(CheckFolderExist(binlogDatabaseName));
    std::string binlogNewPath = customSlaveDirA + "/dual_write_binlog_test.db_binlog";
    ASSERT_TRUE(CheckFolderExist(binlogNewPath));
    RemoveFolder(customSlaveDirA);
}

/**
 * @tc.name: RdbStore_ReplicaPath_006
 * @tc.desc: illegal slave dir (parent dir absent) degrades to master-only open
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_006, TestSize.Level0)
{
    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    std::string illegalSlaveDir = RDB_TEST_PATH + "no_such_dir_xyz/slave_dir_006";
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetReplicaPath(illegalSlaveDir);

    int errCode = E_OK;
    ReplicaPathTestOpenCallback helper;
    LOG_INFO("RdbStore_ReplicaPath_006 open master with illegal slave dir");
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    EXPECT_FALSE(store->IsSlaveAvailable());
    EXPECT_TRUE(store->IsSlaveDiffFromMaster());
    ASSERT_TRUE(SqliteUtils::IsSlaveInvalid(RdbReplicaPathTest::databaseName));

    // master RW still normal
    int64_t id = 1;
    int count = 10;
    Insert(id, count);
    CheckNumber(store, count);

    EXPECT_NE(access((illegalSlaveDir + "/dual_write_binlog_test_slave.db").c_str(), F_OK), 0);
    EXPECT_NE(store->Backup(std::string(""), {}), E_OK);
}

/**
 * @tc.name: RdbStore_ReplicaPath_007
 * @tc.desc: SINGLE mode: replicaPath config does not affect open; slave never available and no slave file at custom dir
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_007, TestSize.Level0)
{
    std::string customSlaveDir = RDB_TEST_PATH + "custom_slave_dir_single_007";
    std::string expectedSlaveFile = customSlaveDir + "/dual_write_binlog_test_slave.db";
    if (CheckFolderExist(customSlaveDir)) {
        RemoveFolder(customSlaveDir);
    }
    std::error_code ec;
    std::filesystem::create_directories(customSlaveDir, ec);

    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    config.SetHaMode(HAMode::SINGLE);
    config.SetReplicaPath(customSlaveDir);
    int errCode = E_OK;
    ReplicaPathTestOpenCallback helper;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_FALSE(store->IsSlaveAvailable());
    EXPECT_NE(access(expectedSlaveFile.c_str(), F_OK), 0);
    store = nullptr;
    RemoveFolder(customSlaveDir);
}

/**
 * @tc.name: RdbStore_ReplicaPath_008
 * @tc.desc: Test trigger mode, replicate Path from empty to path A
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_008, TestSize.Level0)
{
    InitDb(HAMode::MANUAL_TRIGGER, false, false);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
    ASSERT_TRUE(CheckFolderExist(binlogDatabaseName));
    store = nullptr;

    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    std::string customSlaveDirA = RDB_TEST_PATH + "custom_slave_dir_a_008";
    std::string expectedSlaveA = customSlaveDirA + "/dual_write_binlog_test_slave.db";
    if (CheckFolderExist(customSlaveDirA)) {
        RemoveFolder(customSlaveDirA);
    }
    std::error_code ec;
    std::filesystem::create_directories(customSlaveDirA, ec);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    config.SetReplicaPath(customSlaveDirA);
    int errCode = E_OK;
    ReplicaPathTestOpenCallback helper;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    LOG_INFO("---- step3 assert slave file exists and slave is available");
    ASSERT_TRUE(OHOS::FileExists(RdbReplicaPathTest::slaveDatabaseName));
    ASSERT_FALSE(OHOS::FileExists(expectedSlaveA));
    ASSERT_FALSE(store->IsSlaveAvailable());
    EXPECT_TRUE(store->IsSlaveDiffFromMaster());
    ASSERT_TRUE(CheckFolderExist(binlogDatabaseName));
    std::string binlogNewPath = customSlaveDirA + "/dual_write_binlog_test.db_binlog";
    ASSERT_FALSE(CheckFolderExist(binlogNewPath));

    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
    ASSERT_FALSE(OHOS::FileExists(RdbReplicaPathTest::slaveDatabaseName));
    ASSERT_TRUE(OHOS::FileExists(expectedSlaveA));
    ASSERT_TRUE(store->IsSlaveAvailable());
    EXPECT_FALSE(store->IsSlaveDiffFromMaster());
    ASSERT_FALSE(CheckFolderExist(binlogDatabaseName));
    ASSERT_TRUE(CheckFolderExist(binlogNewPath));

    store = nullptr;
    RemoveFolder(customSlaveDirA);
}

/**
 * @tc.name: RdbStore_ReplicaPath_010
 * @tc.desc: Test trigger mode, replicate Path from path A to empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_010, TestSize.Level0)
{
    RdbStoreConfig config(RdbReplicaPathTest::databaseName);
    std::string customSlaveDirA = RDB_TEST_PATH + "custom_slave_dir_a_010";
    std::string expectedSlaveA = customSlaveDirA + "/dual_write_binlog_test_slave.db";
    if (CheckFolderExist(customSlaveDirA)) {
        RemoveFolder(customSlaveDirA);
    }
    std::error_code ec;
    std::filesystem::create_directories(customSlaveDirA, ec);
    config.SetHaMode(HAMode::MANUAL_TRIGGER);
    config.SetReplicaPath(customSlaveDirA);
    int errCode = E_OK;
    ReplicaPathTestOpenCallback helper;
    RdbReplicaPathTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_FALSE(OHOS::FileExists(expectedSlaveA));
    EXPECT_FALSE(store->IsSlaveAvailable());

    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
    EXPECT_TRUE(OHOS::FileExists(expectedSlaveA));
    EXPECT_TRUE(store->IsSlaveAvailable());
    store = nullptr;

    InitDb(HAMode::MANUAL_TRIGGER, false, false);
    ASSERT_NE(store, nullptr);
    EXPECT_TRUE(OHOS::FileExists(expectedSlaveA));
    EXPECT_FALSE(store->IsSlaveAvailable());

    EXPECT_EQ(store->Backup(std::string(""), {}), E_OK);
    EXPECT_TRUE(OHOS::FileExists(expectedSlaveA));
    EXPECT_TRUE(store->IsSlaveAvailable());
    ASSERT_TRUE(OHOS::FileExists(RdbReplicaPathTest::slaveDatabaseName));
    store = nullptr;
    RemoveFolder(customSlaveDirA);
}

/**
 * @tc.name: RdbStore_ReplicaPath_012
 * @tc.desc: Test the content of the failure file
 * @tc.type: FUNC
 */
HWTEST_F(RdbReplicaPathTest, RdbStore_ReplicaPath_012, TestSize.Level0)
{
    EXPECT_TRUE(SqliteUtils::IsValidReplicaPath(RDB_TEST_PATH));
    EXPECT_TRUE(SqliteUtils::IsValidReplicaPath(""));
    EXPECT_FALSE(SqliteUtils::IsValidReplicaPath("relative/dir"));
    EXPECT_FALSE(SqliteUtils::IsValidReplicaPath(RDB_TEST_PATH + "no_such_dir_012"));
    std::string aFile = RDB_TEST_PATH + "not_a_dir_012.db";
    SqliteUtils::DeleteFile(aFile);
    std::ofstream f(aFile);
    ASSERT_TRUE(f.is_open());
    f << "x";
    f.close();
    EXPECT_FALSE(SqliteUtils::IsValidReplicaPath(aFile));
    EXPECT_TRUE(SqliteUtils::IsValidReplicaPath(RDB_TEST_PATH + "/"));
    SqliteUtils::DeleteFile(aFile);

    EXPECT_EQ(SqliteUtils::SetSlaveInvalid(RdbReplicaPathTest::databaseName,
        SqliteUtils::SlaveInvalidReason::PREPARE_FAILED), E_OK);
    std::string failureFlagPath = RdbReplicaPathTest::databaseName + "-slaveFailure";
    std::ifstream failureFile(failureFlagPath);
    ASSERT_TRUE(failureFile.is_open());
    std::string firstLine;
    std::string secondLine;
    std::getline(failureFile, firstLine);
    std::getline(failureFile, secondLine);
    failureFile.close();
    EXPECT_FALSE(firstLine.empty());
    EXPECT_EQ(secondLine, std::string("prepare_failed"));
    SqliteUtils::DeleteFile(failureFlagPath);
}
