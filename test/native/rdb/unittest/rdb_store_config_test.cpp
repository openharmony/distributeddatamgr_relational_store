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
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "sqlite_global_config.h"
#include "unistd.h"
using namespace testing::ext;
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using RdbConfig = OHOS::NativeRdb::RdbStoreConfig;

class RdbStoreConfigTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

class ConfigTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string ConfigTestOpenCallback::CREATE_TABLE_TEST =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");

int ConfigTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int ConfigTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

class ConfigTestVisitorOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

int ConfigTestVisitorOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int ConfigTestVisitorOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStoreConfigTest::SetUpTestCase(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + "config_test.db");
}

void RdbStoreConfigTest::TearDownTestCase(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + "config_test.db");
}

void RdbStoreConfigTest::SetUp(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + "config_test.db");
}

void RdbStoreConfigTest::TearDown(void)
{
    RdbHelper::ClearCache();
    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + "config_test.db");
}

/**
 * @tc.name: RdbStoreConfig_001
 * @tc.desc: test RdbStoreConfig
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_001, TestSize.Level1)
{
    int errCode = E_OK;
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    ConfigTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

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

    ret = access(dbPath.c_str(), F_OK);
    EXPECT_EQ(ret, 0);

    int currentVersion;
    ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, currentVersion);

    store = nullptr;
    RdbHelper::ClearCache();
    ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    StorageMode mode = config.GetStorageMode();
    StorageMode targeMode = StorageMode::MODE_DISK;
    EXPECT_EQ(mode, targeMode);
    store = nullptr;
}

/**
 * @tc.name: RdbStoreConfig_002
 * @tc.desc: test RdbStoreConfig
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_002, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config("", StorageMode::MODE_MEMORY);
    ConfigTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

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

    int currentVersion;
    ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, currentVersion);

    store->SetVersion(5);
    ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(5, currentVersion);

    store->SetVersion(2147483647);
    ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2147483647, currentVersion);

    store->SetVersion(-2147483648);
    ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(-2147483648, currentVersion);

    std::string journalMode;
    ret = store->ExecuteAndGetString(journalMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(journalMode, "memory");

    StorageMode mode = config.GetStorageMode();
    StorageMode targeMode = StorageMode::MODE_MEMORY;
    EXPECT_EQ(mode, targeMode);
    store = nullptr;
}

/**
 * @tc.name: RdbStoreConfig_003
 * @tc.desc: test RdbStoreConfig
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_003, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config("", StorageMode::MODE_DISK, false);
    ConfigTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_INVALID_FILE_PATH);
}

/**
 * @tc.name: RdbStoreConfig_004
 * @tc.desc: test RdbStoreConfig
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_004, TestSize.Level1)
{
    int errCode = E_OK;
    const std::string dbPath = "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    ConfigTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_INVALID_FILE_PATH);
}

/**
 * @tc.name: RdbStoreConfig_005
 * @tc.desc: test RdbStoreConfig journalMode
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_005, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    std::string journalMode = config.GetJournalMode();
    EXPECT_EQ(journalMode, "WAL");
    ConfigTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    std::string currentMode;
    int ret = store->ExecuteAndGetString(currentMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentMode, "wal");
    store = nullptr;
}

/**
 * @tc.name: RdbStoreConfig_006
 * @tc.desc: test RdbStoreConfig journalMode
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_006, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    config.SetJournalMode(JournalMode::MODE_DELETE);
    std::string journalMode = config.GetJournalMode();
    EXPECT_EQ(journalMode, "DELETE");
    ConfigTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    std::string currentMode;
    int ret = store->ExecuteAndGetString(currentMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentMode, "delete");
    store = nullptr;
}

/**
 * @tc.name: RdbStoreConfig_007
 * @tc.desc: test RdbStoreConfig journalMode
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_007, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    config.SetJournalMode(JournalMode::MODE_TRUNCATE);
    std::string journalMode = config.GetJournalMode();
    EXPECT_EQ(journalMode, "TRUNCATE");
    ConfigTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    std::string currentMode;
    int ret = store->ExecuteAndGetString(currentMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentMode, "truncate");
    store = nullptr;
}

/**
 * @tc.name: RdbStoreConfig_008
 * @tc.desc: test RdbStoreConfig journalMode
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_008, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    config.SetJournalMode(JournalMode::MODE_PERSIST);
    std::string journalMode = config.GetJournalMode();
    EXPECT_EQ(journalMode, "PERSIST");
    ConfigTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    std::string currentMode;
    int ret = store->ExecuteAndGetString(currentMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentMode, "persist");
    store = nullptr;
}

/**
 * @tc.name: RdbStoreConfig_009
 * @tc.desc: test RdbStoreConfig journalMode
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_009, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    config.SetJournalMode(JournalMode::MODE_MEMORY);
    std::string journalMode = config.GetJournalMode();
    EXPECT_EQ(journalMode, "MEMORY");
    ConfigTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    std::string currentMode;
    int ret = store->ExecuteAndGetString(currentMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentMode, "memory");
    store = nullptr;
}
/**
 * @tc.name: RdbStoreConfig_010
 * @tc.desc: test RdbStoreConfig journalMode
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_010, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    config.SetJournalMode(JournalMode::MODE_WAL);
    std::string journalMode = config.GetJournalMode();
    EXPECT_EQ(journalMode, "WAL");
    ConfigTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    std::string currentMode;
    int ret = store->ExecuteAndGetString(currentMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentMode, "wal");
    store = nullptr;
}

/**
 * @tc.name: RdbStoreConfig_011
 * @tc.desc: test RdbStoreConfig journalMode
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_011, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    config.SetJournalMode(JournalMode::MODE_OFF);
    std::string journalMode = config.GetJournalMode();
    EXPECT_EQ(journalMode, "OFF");
    ConfigTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    std::string currentMode;
    int ret = store->ExecuteAndGetString(currentMode, "PRAGMA journal_mode");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentMode, "off");
}

/**
 * @tc.name: RdbStoreConfig_012
 * @tc.desc: test RdbStoreConfig interfaces: SetSecurityLevel/GetSecurityLevel
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_012, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    config.SetSecurityLevel(SecurityLevel::S2);
    SecurityLevel retSecurityLevel = config.GetSecurityLevel();
    EXPECT_EQ(SecurityLevel::S2, retSecurityLevel);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    config.SetSecurityLevel(SecurityLevel::LAST);
    retSecurityLevel = config.GetSecurityLevel();
    EXPECT_EQ(SecurityLevel::LAST, retSecurityLevel);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_013
 * @tc.desc: test RdbStoreConfig interfaces: SetCreateNecessary/IsCreateNecessary
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_013, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    bool createNecessary = true;
    config.SetCreateNecessary(createNecessary);
    bool retCreateNecessary = config.IsCreateNecessary();
    EXPECT_EQ(createNecessary, retCreateNecessary);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    createNecessary = false;
    config.SetCreateNecessary(createNecessary);
    retCreateNecessary = config.IsCreateNecessary();
    EXPECT_EQ(createNecessary, retCreateNecessary);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_014
 * @tc.desc: test RdbStoreConfig interfaces: SetReadOnly/IsReadOnly
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_014, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    bool readOnly = true;
    config.SetReadOnly(readOnly);
    bool retReadOnly = config.IsReadOnly();
    EXPECT_EQ(readOnly, retReadOnly);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(store, nullptr);
    store = nullptr;
    RdbHelper::DeleteRdbStore(dbPath);

    readOnly = false;
    config.SetReadOnly(readOnly);
    retReadOnly = config.IsReadOnly();
    EXPECT_EQ(readOnly, retReadOnly);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    // open the read only db failed, when the file is not exists;
    store = nullptr;
    readOnly = true;
    config.SetReadOnly(readOnly);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);

    // open the read only db success, when the file is exists;
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_015
 * @tc.desc: test RdbStoreConfig interfaces: SetStorageMode/GetStorageMode
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_015, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    StorageMode storageMode = StorageMode::MODE_DISK;
    config.SetStorageMode(storageMode);
    StorageMode retStorageMode = config.GetStorageMode();
    EXPECT_EQ(storageMode, retStorageMode);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    storageMode = StorageMode::MODE_MEMORY;
    config.SetStorageMode(storageMode);
    retStorageMode = config.GetStorageMode();
    EXPECT_EQ(storageMode, retStorageMode);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_016
 * @tc.desc: test RdbStoreConfig interfaces: SetDatabaseFileType/GetDatabaseFileType
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_016, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    DatabaseFileType databaseFileType = DatabaseFileType::NORMAL;
    config.SetDatabaseFileType(databaseFileType);
    std::string retDatabaseFileType = config.GetDatabaseFileType();
    EXPECT_EQ("db", retDatabaseFileType);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    databaseFileType = DatabaseFileType::BACKUP;
    config.SetDatabaseFileType(databaseFileType);
    retDatabaseFileType = config.GetDatabaseFileType();
    EXPECT_EQ("backup", retDatabaseFileType);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    databaseFileType = DatabaseFileType::CORRUPT;
    config.SetDatabaseFileType(databaseFileType);
    retDatabaseFileType = config.GetDatabaseFileType();
    EXPECT_EQ("corrupt", retDatabaseFileType);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_017
 * @tc.desc: test RdbStoreConfig interfaces: SetDistributedType/GetDistributedType
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_017, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    DistributedType distributedType = DistributedType::RDB_DEVICE_COLLABORATION;
    config.SetDistributedType(distributedType);
    DistributedType retDistributedType = config.GetDistributedType();
    EXPECT_EQ(distributedType, retDistributedType);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    distributedType = DistributedType::RDB_DISTRIBUTED_TYPE_MAX;
    config.SetDistributedType(distributedType);
    retDistributedType = config.GetDistributedType();
    EXPECT_NE(distributedType, retDistributedType);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_018
 * @tc.desc: test RdbStoreConfig interfaces: SetModuleName/GetModuleName
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_018, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    std::string moduleName = "phone";
    config.SetModuleName(moduleName);
    std::string retModuleName = config.GetModuleName();
    EXPECT_EQ(moduleName, retModuleName);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_019
 * @tc.desc: test RdbStoreConfig interfaces: SetModuleName/GetModuleName
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_019, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    std::string serviceName = "com.ohos.config.test";
    config.SetServiceName(serviceName);
    std::string retServiceName = config.GetBundleName();
    EXPECT_EQ(serviceName, retServiceName);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_020
 * @tc.desc: test RdbStoreConfig interfaces: GetSyncModeValue
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_020, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    std::string syncMode = config.GetSyncModeValue(SyncMode::MODE_OFF);
    EXPECT_EQ(syncMode, "MODE_OFF");
    syncMode = OHOS::NativeRdb::RdbStoreConfig::GetSyncModeValue(SyncMode::MODE_NORMAL);
    EXPECT_EQ(syncMode, "MODE_NORMAL");
    syncMode = config.GetSyncModeValue(SyncMode::MODE_FULL);
    EXPECT_EQ(syncMode, "MODE_FULL");
    syncMode = config.GetSyncModeValue(SyncMode::MODE_EXTRA);
    EXPECT_EQ(syncMode, "MODE_EXTRA");
}

/**
 * @tc.name: RdbStoreConfig_021
 * @tc.desc: test RdbStoreConfig interfaces: SetAutoCheck/IsAutoCheck
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_021, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    bool autoCheck = true;
    config.SetAutoCheck(autoCheck);
    bool retAutoCheck = config.IsAutoCheck();
    EXPECT_EQ(autoCheck, retAutoCheck);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_022
 * @tc.desc: test RdbStoreConfig interfaces: SetJournalSize/GetJournalSize
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_022, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    static constexpr int journalSize = 2 * 1024 * 1024;
    config.SetJournalSize(journalSize);
    int retJournalSize = config.GetJournalSize();
    EXPECT_EQ(journalSize, retJournalSize);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    config.SetJournalSize(0);
    retJournalSize = config.GetJournalSize();
    EXPECT_EQ(0, retJournalSize);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_023
 * @tc.desc: test RdbStoreConfig interfaces: SetJournalSize/GetJournalSize
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_023, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    static constexpr int pageSize = 4 * 1024;
    config.SetPageSize(pageSize);
    int retPageSize = config.GetPageSize();
    EXPECT_EQ(pageSize, retPageSize);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    config.SetPageSize(0);
    retPageSize = config.GetPageSize();
    EXPECT_EQ(0, retPageSize);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_024
 * @tc.desc: test RdbStoreConfig interfaces: SetEncryptAlgo/GetEncryptAlgo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_024, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    EncryptAlgo encryptAlgo = EncryptAlgo::AES_256_GCM;
    config.SetEncryptAlgo(encryptAlgo);
    EncryptAlgo retEncryptAlgo = config.GetEncryptAlgo();
    EXPECT_EQ(encryptAlgo, retEncryptAlgo);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: RdbStoreConfig_025
 * @tc.desc: test RdbStoreConfig interfaces: SetReadConSize/GetReadConSize
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_025, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    static constexpr int readConSize = 4;
    int retReadConSize = config.GetReadConSize();
    EXPECT_EQ(readConSize, retReadConSize);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    auto ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    config.SetReadConSize(20);
    retReadConSize = config.GetReadConSize();
    EXPECT_EQ(20, retReadConSize);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    config.SetReadConSize(0);
    retReadConSize = config.GetReadConSize();
    EXPECT_EQ(0, retReadConSize);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    config.SetReadConSize(1);
    retReadConSize = config.GetReadConSize();
    EXPECT_EQ(1, retReadConSize);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    store = nullptr;
    ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);

    config.SetReadConSize(64);
    retReadConSize = config.GetReadConSize();
    EXPECT_EQ(64, retReadConSize);
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStoreConfig_026
 * @tc.desc: test RdbStoreConfig interfaces: SetReadConSize/GetReadConSize
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_026, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    static constexpr int readConSize = 10;
    config.SetReadConSize(readConSize);
    int retReadConSize = config.GetReadConSize();
    EXPECT_EQ(readConSize, retReadConSize);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

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

    std::vector<std::shared_ptr<ResultSet>> resultSets;
    for (int i = 0; i < readConSize; ++i) {
        auto resultSet = store->QueryByStep("SELECT * FROM test");
        EXPECT_NE(resultSet, nullptr);
        EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
        resultSets.push_back(resultSet);
    }
    for (const auto &resultSet : resultSets) {
        EXPECT_EQ(E_OK, resultSet->Close());
    }
    store = nullptr;
}

/**
 * @tc.name: RdbStoreConfig_027
 * @tc.desc: test RdbStoreConfig interfaces: SetDataGroupId/GetDataGroupId
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_027, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    std::string dataGroupId = "123456";
    config.SetDataGroupId(dataGroupId);
    EXPECT_EQ(dataGroupId, config.GetDataGroupId());
}

/**
 * @tc.name: RdbStoreConfig_028
 * @tc.desc: test RdbStoreConfig interfaces: SetDataGroupId/SetAutoClean
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_028, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    bool autoClean = false;
    config.SetAutoClean(autoClean);
    EXPECT_EQ(autoClean, config.GetAutoClean());
}

/**
 * @tc.name: RdbStoreConfig_029
 * @tc.desc: test RdbStoreConfig interfaces: SetModuleName/GetModuleName
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_029, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test_29.db";
    RdbStoreConfig config(dbPath);

    std::string bundleName = "com.ohos.config.test30";
    config.SetBundleName(bundleName);
    config.SetSecurityLevel(SecurityLevel::S2);
    config.SetArea(0);
    config.SetEncryptStatus(false);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    store = nullptr;

    auto invalidConfig = config;
    invalidConfig.SetSecurityLevel(SecurityLevel::S1);
    store = RdbHelper::GetRdbStore(invalidConfig, 1, helper, errCode);
    EXPECT_EQ(errCode, E_CONFIG_INVALID_CHANGE);
    EXPECT_EQ(store, nullptr);
    store = nullptr;

    RdbHelper::DeleteRdbStore(dbPath);
}

/**
 * @tc.name: RdbStoreConfig_030
 * @tc.desc: test RdbStoreConfig interfaces: SetReadTime/GetReadTime
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_030, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    int timeout = 10;
    config.SetReadTime(timeout);
    EXPECT_EQ(timeout, config.GetReadTime());

    // 0 is used to test the situation when outTime is less than MIN_TIMEOUT.
    timeout = 0;
    config.SetReadTime(timeout);
    EXPECT_EQ(1, config.GetReadTime());

    // 301 is used to test the situation when outTime is greater than MAX_TIMEOUT.
    timeout = 301;
    config.SetReadTime(timeout);
    EXPECT_EQ(300, config.GetReadTime());
}

/**
 * @tc.name: RdbStoreConfig_031
 * @tc.desc: test RdbStoreConfig interfaces: SetDataGroupId/SetAutoClean
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_031, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    bool allowRebuild = false;
    config.SetAllowRebuild(allowRebuild);
    EXPECT_EQ(allowRebuild, config.GetAllowRebuild());

    allowRebuild = true;
    config.SetAllowRebuild(allowRebuild);
    EXPECT_EQ(allowRebuild, config.GetAllowRebuild());
}

/**
 * @tc.name: RdbStoreConfig_032
 * @tc.desc: test RdbStoreConfig interfaces: SetWriteTime/GetWriteTime
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_032, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    int timeout = 10;
    config.SetWriteTime(timeout);
    EXPECT_EQ(timeout, config.GetWriteTime());

    // 0 is used to test the situation when outTime is less than MIN_TIMEOUT.
    timeout = 0;
    config.SetWriteTime(timeout);
    EXPECT_EQ(1, config.GetWriteTime());

    // 301 is used to test the situation when outTime is greater than MAX_TIMEOUT.
    timeout = 301;
    config.SetWriteTime(timeout);
    EXPECT_EQ(300, config.GetWriteTime());
}

/**
 * @tc.name: RdbStoreConfig_033
 * @tc.desc: test RdbStoreConfig SetSecurityLevel S2->S1
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_033, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test_33.db";
    RdbStoreConfig config(dbPath);

    std::string bundleName = "com.ohos.config.test33";
    config.SetBundleName(bundleName);
    config.SetSecurityLevel(SecurityLevel::S2);

    ConfigTestOpenCallback helper;
    int errCode = E_ERROR;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    store = nullptr;

    auto invalidConfig = config;
    invalidConfig.SetSecurityLevel(SecurityLevel::S1);
    store = RdbHelper::GetRdbStore(invalidConfig, 1, helper, errCode);
    EXPECT_EQ(errCode, E_CONFIG_INVALID_CHANGE);
    EXPECT_EQ(store, nullptr);
    store = nullptr;

    RdbHelper::DeleteRdbStore(dbPath);
}

/**
 * @tc.name: RdbStoreConfig_034
 * @tc.desc: test RdbStoreConfig GetCheckpointSize
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_034, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    ssize_t walSize = config.GetWalLimitSize();
    ssize_t checkpointSize = config.GetCheckpointSize();
    ssize_t startCheckpointSize = config.GetStartCheckpointSize();
    EXPECT_EQ(walSize, GlobalExpr::DB_WAL_DEFAULT_SIZE);
    EXPECT_EQ(checkpointSize, GlobalExpr::DB_WAL_WARNING_SIZE);
    EXPECT_EQ(startCheckpointSize, GlobalExpr::DB_WAL_SIZE_LIMIT_MIN);
}
/**
 * @tc.name: RdbStoreConfig_035
 * @tc.desc: test RdbStoreConfig GetPromiseInfo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_035, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);
    PromiseInfo expectedInfo;
    expectedInfo.user_ = "zhangsan";
    expectedInfo.tokenIds_ = { 1, 2, 3 };
    expectedInfo.uids_ = { 4, 5, 6 };
    expectedInfo.permissionNames_ = { "lisi", "wangwu" };

    config.SetPromiseInfo(expectedInfo);
    const PromiseInfo &actualInfo = config.GetPromiseInfo();

    EXPECT_EQ(actualInfo.user_, expectedInfo.user_);

    EXPECT_EQ(actualInfo.tokenIds_.size(), expectedInfo.tokenIds_.size());
    for (size_t i = 0; i < expectedInfo.tokenIds_.size(); ++i) {
        EXPECT_EQ(actualInfo.tokenIds_[i], expectedInfo.tokenIds_[i]);
    }

    EXPECT_EQ(actualInfo.uids_.size(), expectedInfo.uids_.size());
    for (size_t i = 0; i < expectedInfo.uids_.size(); ++i) {
        EXPECT_EQ(actualInfo.uids_[i], expectedInfo.uids_[i]);
    }

    EXPECT_EQ(actualInfo.permissionNames_.size(), expectedInfo.permissionNames_.size());
    for (size_t i = 0; i < expectedInfo.permissionNames_.size(); ++i) {
        EXPECT_EQ(actualInfo.permissionNames_[i], expectedInfo.permissionNames_[i]);
    }
}

/**
 * @tc.name: RdbStoreConfigVisitor_001
 * @tc.desc: test RdbStoreConfigVisitor
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfigVisitor_001, TestSize.Level1)
{
    int errCode = E_OK;
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath, StorageMode::MODE_DISK, false);
    ConfigTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

    const std::string visitorDir = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig visitorConfig("", StorageMode::MODE_DISK, true);
    ConfigTestVisitorOpenCallback visitorHelper;
    visitorConfig.SetRoleType(OHOS::NativeRdb::VISITOR);
    visitorConfig.SetVisitorDir(visitorDir);
    visitorConfig.SetCreateNecessary(false);
    std::shared_ptr<RdbStore> visitorStore = RdbHelper::GetRdbStore(visitorConfig, 1, visitorHelper, errCode);
    EXPECT_NE(visitorStore, nullptr);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(visitorDir, visitorConfig.GetVisitorDir());

    int64_t id;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = visitorStore->Insert(id, "test", values);
    EXPECT_NE(ret, E_OK);

    store = nullptr;
    visitorStore = nullptr;
    ret = RdbHelper::DeleteRdbStore(dbPath);
    EXPECT_EQ(ret, E_OK);
}

/* *
 * @tc.name: RdbStoreConfigSetCollatorLocales_001
 * @tc.desc: test RdbStoreConfigSetCollatorLocales
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_036, TestSize.Level2)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    int errCode = E_OK;
    RdbStoreConfig config(dbPath);
    config.SetCollatorLocales("zh_CN");
    EXPECT_EQ(config.GetCollatorLocales(), "zh_CN");
    ConfigTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);
    ASSERT_NE(nullptr, store);
    store->ExecuteSql("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                    "data2 INTEGER);");
    int64_t id;
    ValuesBucket valuesBucket;
    valuesBucket.PutString("data1", "张三");
    valuesBucket.PutInt("data2", 20);
    errCode = store->Insert(id, "test1", valuesBucket);

    ValuesBucket valuesBucket1;
    valuesBucket1.PutString("data1", "李四");
    valuesBucket1.PutInt("data2", 20);
    errCode = store->Insert(id, "test1", valuesBucket1);

    std::vector<std::string> columns;
    AbsRdbPredicates predicates("test1");
    predicates.OrderByAsc("data1 COLLATE LOCALES");
    std::shared_ptr<ResultSet> resultSet = store->Query(predicates, columns);
    ASSERT_NE(nullptr, store);
    std::string strValue;
    resultSet->GoToNextRow();
    resultSet->GetString(1, strValue);
    EXPECT_EQ(strValue, "李四");

    resultSet->GoToNextRow();
    resultSet->GetString(1, strValue);
    EXPECT_EQ(strValue, "张三");
}
 
/* *
* @tc.name: RdbStoreConfigSetCollatorLocales_002
* @tc.desc: test RdbStoreConfigSetCollatorLocales_002
* @tc.type: FUNC
*/
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_037, TestSize.Level2)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    int errCode = E_OK;
    RdbStoreConfig config(dbPath);
    config.SetCollatorLocales("");
    ConfigTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);
    ASSERT_NE(nullptr, store);
    store->ExecuteSql("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                    "data2 INTEGER);");
    int64_t id;
    ValuesBucket valuesBucket;
    valuesBucket.PutString("data1", "张三");
    valuesBucket.PutInt("data2", 20);
    errCode = store->Insert(id, "test1", valuesBucket);

    ValuesBucket valuesBucket1;
    valuesBucket1.PutString("data1", "李四");
    valuesBucket1.PutInt("data2", 20);
    errCode = store->Insert(id, "test1", valuesBucket1);

    std::vector<std::string> columns;
    AbsRdbPredicates predicates("test1");
    predicates.OrderByAsc("data1 COLLATE LOCALES");
    std::shared_ptr<ResultSet> resultSet = store->Query(predicates, columns);
    ASSERT_NE(resultSet, nullptr);
    std::string strValue;
    errCode = resultSet->GoToNextRow();
    EXPECT_EQ(errCode, E_SQLITE_ERROR);
}

/* *
 * @tc.name: RdbStoreConfigSetCollatorLocales_003
 * @tc.desc: test RdbStoreConfigSetCollatorLocales
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_038, TestSize.Level2)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    int errCode = E_OK;
    RdbStoreConfig config(dbPath);
    ConfigTestOpenCallback helper;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(E_OK, errCode);
    ASSERT_NE(nullptr, store);
    store->ExecuteSql("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                    "data2 INTEGER);");
    int64_t id;
    ValuesBucket valuesBucket;
    valuesBucket.PutString("data1", "张三");
    valuesBucket.PutInt("data2", 20);
    errCode = store->Insert(id, "test1", valuesBucket);

    ValuesBucket valuesBucket1;
    valuesBucket1.PutString("data1", "李四");
    valuesBucket1.PutInt("data2", 20);
    errCode = store->Insert(id, "test1", valuesBucket1);

    std::vector<std::string> columns;
    AbsRdbPredicates predicates("test1");
    predicates.OrderByAsc("data1 COLLATE LOCALES");
    std::shared_ptr<ResultSet> resultSet = store->Query(predicates, columns);
    ASSERT_NE(resultSet, nullptr);
    std::string strValue;
    errCode = resultSet->GoToNextRow();
    EXPECT_EQ(errCode, E_SQLITE_ERROR);

    RdbHelper::ClearCache();
    RdbStoreConfig config1(dbPath);
    config1.SetVisitorDir(dbPath);
    config1.SetCollatorLocales("zh_CN");
    ConfigTestOpenCallback helper1;
    std::shared_ptr<RdbStore> store1 = RdbHelper::GetRdbStore(config1, 1, helper1, errCode);
    EXPECT_EQ(E_OK, errCode);
    ASSERT_NE(nullptr, store1);

    std::vector<std::string> columns1;
    AbsRdbPredicates predicates1("test1");
    predicates1.OrderByAsc("data1 COLLATE LOCALES");
    std::shared_ptr<ResultSet> resultSet1 = store1->Query(predicates1, columns);
    ASSERT_NE(nullptr, resultSet1);
    std::string strValue1;
    resultSet1->GoToNextRow();
    resultSet1->GetString(1, strValue1);
    EXPECT_EQ(strValue1, "李四");

    resultSet1->GoToNextRow();
    resultSet1->GetString(1, strValue1);
    EXPECT_EQ(strValue1, "张三");
}

/* *
 * @tc.name: RdbStoreConfigGetEnableSemanticIndex_001
 * @tc.desc: test RdbStoreConfigGetEnableSemanticIndex
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_039, TestSize.Level2)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    bool ret = config.GetEnableSemanticIndex();
    EXPECT_EQ(ret, false);
}

/* *
 * @tc.name: RdbStoreConfigSetEnableSemanticIndex_002
 * @tc.desc: test RdbStoreConfigSetEnableSemanticIndex
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_040, TestSize.Level2)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    bool enableSemanticIndex = true;
    config.SetEnableSemanticIndex(enableSemanticIndex);
    EXPECT_EQ(enableSemanticIndex, config.GetEnableSemanticIndex());

    enableSemanticIndex = false;
    config.SetEnableSemanticIndex(enableSemanticIndex);
    EXPECT_EQ(enableSemanticIndex, config.GetEnableSemanticIndex());
}

/* *
 * @tc.name: RdbStoreConfigSetTransactionTime_001
 * @tc.desc: test RdbStoreConfigSetTransactionTime
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreConfigTest, RdbStoreConfig_041, TestSize.Level2)
{
    const std::string dbPath = RDB_TEST_PATH + "config_test.db";
    RdbStoreConfig config(dbPath);

    // set transactionTime_ to 0
    int transactionTime = 0;
    config.SetTransactionTime(transactionTime);
    EXPECT_EQ(RdbConfig::MIN_TIMEOUT, config.GetTransactionTime());

    // set transactionTime_ to 400
    transactionTime = 400;
    config.SetTransactionTime(transactionTime);
    EXPECT_EQ(RdbConfig::MAX_TIMEOUT, config.GetTransactionTime());

    // set transactionTime_ to 200
    transactionTime = 200;
    config.SetTransactionTime(transactionTime);
    EXPECT_EQ(transactionTime, config.GetTransactionTime());

    // set transactionTime_ to 1
    transactionTime = 1;
    config.SetTransactionTime(transactionTime);
    EXPECT_EQ(transactionTime, config.GetTransactionTime());

    // set transactionTime_ to 300
    transactionTime = 300;
    config.SetTransactionTime(transactionTime);
    EXPECT_EQ(transactionTime, config.GetTransactionTime());
}
