/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <fstream>
#include <map>
#include <string>
#include "acl.h"
#include "block_data.h"
#include "common.h"
#include "file_ex.h"
#include "grd_api_manager.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_impl.h"
#include "rdb_platform.h"
#include "sqlite_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DATABASE_UTILS;
constexpr int32_t SERVICE_GID = 3012;

class RdbStoreBackupRestoreTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
    }
    static void TearDownTestCase()
    {
    }
    void SetUp();
    void TearDown();
    void CorruptDoubleWriteStore();
    void CheckAccess(const std::string &dbPath);
    std::shared_ptr<RdbStore> InitStore(HAMode mode = HAMode::SINGLE, bool preData = true, bool encrypt = false);
    std::shared_ptr<RdbStore> InitStoreV2(bool isReadOnly = false, StorageMode storageMode = StorageMode::MODE_DISK,
        HAMode mode = HAMode::SINGLE, int32_t dbType = DB_SQLITE);

    static constexpr char DATABASE_NAME[] = "/data/test/backup_restore_test.db";
    static constexpr char slaveDataBaseName[] = "/data/test/backup_restore_test_slave.db";
    static constexpr char BACKUP_DATABASE_NAME[] = "/data/test/backup_restore_test_backup.db";
};

class RdbStoreBackupRestoreTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string RdbStoreBackupRestoreTestOpenCallback::CREATE_TABLE_TEST =
    std::string("CREATE TABLE IF NOT EXISTS test ") + std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                  "name TEXT NOT NULL, age INTEGER, salary "
                                                                  "REAL, blobType BLOB)");

int RdbStoreBackupRestoreTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbStoreBackupRestoreTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}
void RdbStoreBackupRestoreTest::SetUp(void)
{
    RdbHelper::ClearCache();
    int errocode = RdbHelper::DeleteRdbStore(DATABASE_NAME);
    EXPECT_EQ(E_OK, errocode);
    errocode = RdbHelper::DeleteRdbStore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(E_OK, errocode);
}
void RdbStoreBackupRestoreTest::TearDown(void)
{
    RdbHelper::ClearCache();
    int errocode = RdbHelper::DeleteRdbStore(DATABASE_NAME);
    EXPECT_EQ(E_OK, errocode);
    errocode = RdbHelper::DeleteRdbStore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(E_OK, errocode);
}
void RdbStoreBackupRestoreTest::CorruptDoubleWriteStore(void)
{
    std::fstream file(DATABASE_NAME, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open() == true);
    const int seekPosition = 30;
    file.seekp(seekPosition, std::ios::beg);
    ASSERT_TRUE(file.good() == true);
    const int bytesToWrite = 2;
    char bytes[bytesToWrite] = { 0x6, 0x6 };
    file.write(bytes, bytesToWrite);
    ASSERT_TRUE(file.good() == true);
    file.close();
}

void RdbStoreBackupRestoreTest::CheckAccess(const std::string &dbPath)
{
    bool ret = SqliteUtils::HasAccessAcl(dbPath, SERVICE_GID);
    EXPECT_EQ(ret, true);
    ret = SqliteUtils::HasAccessAcl(dbPath + "-dwr", SERVICE_GID);
    EXPECT_EQ(ret, true);
    ret = SqliteUtils::HasAccessAcl(dbPath + "-shm", SERVICE_GID);
    EXPECT_EQ(ret, true);
    ret = SqliteUtils::HasAccessAcl(dbPath + "-wal", SERVICE_GID);
    EXPECT_EQ(ret, true);
}

std::shared_ptr<RdbStore> RdbStoreBackupRestoreTest::InitStore(HAMode mode, bool preData, bool encrypt)
{
    char databaseName[] = "/data/test/new_backup_test.db";
    RdbStoreConfig config(databaseName);
    config.SetHaMode(mode);
    config.SetEncryptStatus(encrypt);
    RdbStoreBackupRestoreTestOpenCallback callback;
    int code = E_ERROR;
    auto store = RdbHelper::GetRdbStore(config, 1, callback, code);
    EXPECT_EQ(code, E_OK) << "GetRdbStore failed, code:" << code;
    if (store == nullptr || code != E_OK) {
        return nullptr;
    }
    if (!preData) {
        return store;
    }
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18); // age is 18
    values.PutDouble("salary", 100.5); // salary is 100.5
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    auto [errCode, id] = store->Insert("test", values);
    EXPECT_EQ(errCode, E_OK) << "Insert failed, code:" << errCode;
    EXPECT_GT(id, -1) << "Insert failed, id:" << id;
    if (errCode != E_OK || id < 0) {
        return nullptr;
    }
    return store;
}

std::shared_ptr<RdbStore> RdbStoreBackupRestoreTest::InitStoreV2(
    bool isReadOnly, StorageMode storageMode, HAMode mode, int32_t dbType)
{
    char databaseName[] = "/data/test/new_backup_test.db";
    RdbStoreConfig config(databaseName);
    config.SetReadOnly(isReadOnly);
    config.SetStorageMode(storageMode);
    config.SetHaMode(mode);
    config.SetDBType(dbType);
    RdbStoreBackupRestoreTestOpenCallback callback;
    int code = E_ERROR;
    auto store = RdbHelper::GetRdbStore(config, 0, callback, code);
    EXPECT_EQ(code, E_OK) << "GetRdbStore failed, code:" << code;
    if (store == nullptr || code != E_OK) {
        return nullptr;
    }
    return store;
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_017
 * @tc.desc: restore from backup & check acl access
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_017, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(false);
    config.SetSearchable(true);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    RdbStoreBackupRestoreTest::CheckAccess(std::string(RdbStoreBackupRestoreTest::DATABASE_NAME));

    int ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    RdbStoreConfig backupConfig(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME);
    backupConfig.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback backupHelper;
    auto backupStore = RdbHelper::GetRdbStore(backupConfig, 1, backupHelper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(backupStore, nullptr);
    backupStore = nullptr;

    struct stat fileStat;
    std::string walFilePath = std::string(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME) + "-wal";
    EXPECT_EQ(stat(walFilePath.c_str(), &fileStat), 0);

    ret = store->Restore(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    RdbStoreBackupRestoreTest::CheckAccess(std::string(RdbStoreBackupRestoreTest::DATABASE_NAME));

    ret = stat(walFilePath.c_str(), &fileStat);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, 2);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME);
}