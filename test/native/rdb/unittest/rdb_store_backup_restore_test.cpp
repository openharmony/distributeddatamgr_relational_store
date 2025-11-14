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
 * @tc.name: Rdb_BackupRestoreTest_001
 * @tc.desc: backup and restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_001, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

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

    ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    int deletedRows = 0;
    ret = store->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, deletedRows);

    ret = store->Restore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_002
 * @tc.desc: backup and restore for broken original and broken backup db
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_002, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(DATABASE_NAME);
    config.SetEncryptStatus(true);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

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

    ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);
    store = nullptr;

    std::ofstream fsDb(DATABASE_NAME, std::ios_base::binary | std::ios_base::out);
    fsDb.seekp(64);
    fsDb.write("hello", 5);
    fsDb.close();
    std::ofstream fsBackupDb(BACKUP_DATABASE_NAME, std::ios_base::binary | std::ios_base::out);
    fsBackupDb.seekp(64);
    fsBackupDb.write("hello", 5);
    fsBackupDb.close();

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_SQLITE_CORRUPT);
    RdbHelper::DeleteRdbStore(DATABASE_NAME);

    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);

    ret = store->Restore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_SQLITE_CORRUPT);

    ret = store->ExecuteSql(RdbStoreBackupRestoreTestOpenCallback::CREATE_TABLE_TEST);
    EXPECT_EQ(ret, E_OK);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_003
 * @tc.desc: backup and restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_003, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetAllowRebuild(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

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

    ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    int deletedRows = 0;
    ret = store->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, deletedRows);

    ret = store->Restore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_004
 * @tc.desc: hamode is replica, backup and deletestore and restore, after restore can insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_004, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    int64_t id;
    ValuesBucket values;

    values.Put("id", 1);
    values.Put("name", std::string("zhangsan"));
    values.Put("age", 18);
    values.Put("salary", 100.5);
    values.Put("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    ret = RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    ret = store->Restore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_005
 * @tc.desc: hamode is replica , backup and restore for broken original db, and after restore can insert
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_005, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    int64_t id;
    ValuesBucket values;

    values.Put("id", 1);
    values.Put("name", std::string("zhangsan"));
    values.Put("age", 18);
    values.Put("salary", 100.5);
    values.Put("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    store = nullptr;
    CorruptDoubleWriteStore();
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_EQ(errCode, E_OK);

    int deletedRows = 0;
    ret = store->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, deletedRows);

    ret = store->Restore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_006
 * @tc.desc: hamode is replica , backup and restore, aftre restore ,store can insert data and delete data and query
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_006, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    int64_t id;
    ValuesBucket values;

    values.Put("id", 1);
    values.Put("name", std::string("zhangsan"));
    values.Put("age", 18);
    values.Put("salary", 100.5);
    values.Put("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    int deletedRows = 0;
    ret = store->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, deletedRows);

    ret = store->Restore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    deletedRows = 0;
    ret = store->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, deletedRows);
    resultSet = store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_007
 * @tc.desc: hamode is replica , deletestore , cannot backup and restore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_007, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    int64_t id;
    ValuesBucket values;

    values.Put("id", 1);
    values.Put("name", std::string("zhangsan"));
    values.Put("age", 18);
    values.Put("salary", 100.5);
    values.Put("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = RdbHelper::DeleteRdbStore(DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_DB_NOT_EXIST);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_008
 * @tc.desc: hamode is replica , backup and restore, check slavestore and backupstore
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_008, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(true);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    int64_t id;
    ValuesBucket values;

    values.Put("id", 1);
    values.Put("name", std::string("zhangsan"));
    values.Put("age", 18);
    values.Put("salary", 100.5);
    values.Put("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    int deletedRows = 0;
    ret = store->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, deletedRows);

    ret = store->Restore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    EXPECT_EQ(0, access(BACKUP_DATABASE_NAME, F_OK));
    EXPECT_EQ(0, access(slaveDataBaseName, F_OK));
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_009
 * @tc.desc: sql func empty param test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_009, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    auto res = store->ExecuteSql("SELECT import_db_from_path()");

    EXPECT_EQ(res, E_SQLITE_ERROR);

    auto [code, result] = store->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_010
 * @tc.desc: source db empty path test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_010, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    auto res = store->ExecuteSql("SELECT import_db_from_path('')");

    EXPECT_EQ(res, E_SQLITE_CANTOPEN);

    auto [code, result] = store->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_011
 * @tc.desc: souce db not exist test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_011, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    auto res = store->ExecuteSql("SELECT import_db_from_path('/path/not_exist.db')");

    EXPECT_EQ(res, E_SQLITE_CANTOPEN);

    auto [code, result] = store->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_012
 * @tc.desc: source db corrupt test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_012, TestSize.Level2)
{
    int errCode = E_OK;
    std::string destDbPath = "/data/test/dest.db";
    std::string sourceDbPath = "/data/test/source.db";

    RdbStoreConfig config(destDbPath);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto dest = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(dest, nullptr);

    RdbStoreConfig sourceConfig(sourceDbPath);
    sourceConfig.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper1;
    auto source = RdbHelper::GetRdbStore(sourceConfig, 1, helper1, errCode);
    source = nullptr;

    std::fstream sourceFile(sourceDbPath, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(sourceFile.is_open());
    sourceFile.seekp(0x0f40, std::ios::beg);
    std::vector<char> buffer(32, 0xFF);
    sourceFile.write(buffer.data(), buffer.size());
    sourceFile.close();

    auto res = dest->ExecuteSql("SELECT import_db_from_path('" + sourceDbPath + "')");

    EXPECT_EQ(res, E_SQLITE_CORRUPT);

    auto [code, result] = dest->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    dest = nullptr;
    RdbHelper::DeleteRdbStore(destDbPath);
    RdbHelper::DeleteRdbStore(sourceDbPath);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_013
 * @tc.desc: import from source db test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_013, TestSize.Level2)
{
    int errCode = E_OK;
    std::string destDbPath = "/data/test/dest.db";
    std::string sourceDbPath = "/data/test/source.db";

    RdbStoreConfig config(destDbPath);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto dest = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(dest, nullptr);

    RdbStoreConfig sourceConfig(sourceDbPath);
    sourceConfig.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper1;
    auto source = RdbHelper::GetRdbStore(sourceConfig, 1, helper1, errCode);

    for (uint i = 0; i < 100; i++) {
        std::vector<ValuesBucket> valuesBuckets;

        for (uint j = 0; j < 100; j++) {
            ValuesBucket value;

            value.Put("name", "zhangsan");
            value.PutString("name", "zhangSan");
            valuesBuckets.push_back(std::move(value));
        }

        int64_t insertRowCount;
        int error = source->BatchInsert(insertRowCount, "test", valuesBuckets);
        EXPECT_EQ(error, E_OK);
    }
    source = nullptr;
    EXPECT_EQ(E_OK, dest->ExecuteSql("SELECT import_db_from_path('" + sourceDbPath + "')"));

    auto resultSet = dest->QuerySql("SELECT * FROM test");
    int rowCount;
    EXPECT_EQ(E_OK, resultSet->GetRowCount(rowCount));

    EXPECT_EQ(rowCount, 10000);

    auto [code, result] = dest->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    dest = nullptr;
    RdbHelper::DeleteRdbStore(destDbPath);
    RdbHelper::DeleteRdbStore(sourceDbPath);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_014
 * @tc.desc: sql func empty param test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_014, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);

    auto res = store->ExecuteSql("SELECT import_db_from_path");

    EXPECT_EQ(res, E_SQLITE_ERROR);

    auto [code, result] = store->Execute("pragma integrity_check");
    std::string val;
    result.GetString(val);
    EXPECT_EQ(E_OK, code);
    EXPECT_EQ("ok", val);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_015
 * @tc.desc: restore wal file exist test
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_015, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);
    
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
    ret = stat(walFilePath.c_str(), &fileStat);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(errno, 2);

    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_016
 * @tc.desc: restore wal file not empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_016, TestSize.Level2)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbStoreBackupRestoreTest::DATABASE_NAME);
    config.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);
    
    int ret = store->Backup(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_OK);

    RdbStoreConfig backupConfig(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME);
    backupConfig.SetEncryptStatus(false);
    RdbStoreBackupRestoreTestOpenCallback backupHelper;
    auto backupStore = RdbHelper::GetRdbStore(backupConfig, 1, backupHelper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(backupStore, nullptr);
    
    int64_t id;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = backupStore->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    struct stat fileStat;
    std::string walFilePath = std::string(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME) + "-wal";
    EXPECT_EQ(stat(walFilePath.c_str(), &fileStat), 0);
    EXPECT_NE(fileStat.st_size, 0);

    ret = store->Restore(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_SQLITE_CORRUPT);

    backupStore = nullptr;
    store = nullptr;
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME);
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

/* *
 * @tc.name: Rdb_BackupRestoreTest_018
 * @tc.desc: 1. create MAIN_REPLICA db
 *           2. create MANUAL_TRIGGER db and write some data
 *           3. backup to replica db
 *           4. query data from main db
 *           5. create MAIN_REPLICA db
 *           6. delete data from main db
 *           7. create MANUAL_TRIGGER db
 *           8. restore from replica db
 *           9. query data from main db
 *           10. compare data
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_018, TestSize.Level2)
{
    auto store = InitStore(HAMode::MAIN_REPLICA, false);
    ASSERT_NE(store, nullptr);
    store = nullptr;
    store = InitStore(HAMode::MANUAL_TRIGGER);
    ASSERT_NE(store, nullptr);

    int code = store->Backup();
    EXPECT_EQ(code, E_OK);

    auto resultSet = store->QuerySql("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    code = resultSet->GoToFirstRow();
    EXPECT_EQ(code, E_OK);
    RowEntity rowEntityBeforeRestore;
    code = resultSet->GetRow(rowEntityBeforeRestore);
    EXPECT_EQ(code, E_OK);

    store = nullptr;
    store = InitStore(HAMode::SINGLE, false);
    ASSERT_NE(store, nullptr);

    AbsRdbPredicates predicates("test");
    auto [ret, results] = store->Delete(predicates);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(results.changed, 1);

    store = nullptr;
    store = InitStore(HAMode::MANUAL_TRIGGER, false);
    ASSERT_NE(store, nullptr);

    resultSet = store->QuerySql("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int count = -1;
    code = resultSet->GetRowCount(count);
    EXPECT_EQ(count, 0);

    code = store->Restore("");
    EXPECT_EQ(code, E_OK);
    resultSet = store->QuerySql("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    code = resultSet->GoToFirstRow();
    EXPECT_EQ(code, E_OK);
    RowEntity rowEntityAfterRestore;
    code = resultSet->GetRow(rowEntityAfterRestore);
    EXPECT_EQ(code, E_OK);

    EXPECT_EQ(rowEntityBeforeRestore.Get(), rowEntityAfterRestore.Get());

    store = nullptr;
    char databaseName[] = "/data/test/new_backup_test.db";
    RdbHelper::DeleteRdbStore(databaseName);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_019
 * @tc.desc: 1. create MAIN_REPLICA db
 *           2. create MANUAL_TRIGGER db and write some data
 *           3. insert 1g data
 *           4. async thread performs backup
 *           5. wait for integrity verification to begin
 *           6. main thread preforms InterruptBackup
 *           7. confirm that asynchronous backup has been interrupted
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_019, TestSize.Level2)
{
    auto store = InitStore(HAMode::MAIN_REPLICA, false);
    ASSERT_NE(store, nullptr);
    store = nullptr;
    store = InitStore(HAMode::MANUAL_TRIGGER);
    ASSERT_NE(store, nullptr);

    const uint32_t count = 1024;
    ValuesBucket values;
    values.PutString("name", std::string(1024 * 1024, 'a')); // 1MB
    values.PutInt("age", 18); // age is 18
    values.PutDouble("salary", 100.5); // salary is 100.5
    values.PutBlob("blobType", std::vector<uint8_t>(1024, 1));
    ValuesBuckets valuesBuckets;
    for (auto i = 0; i < count; i++) {
        valuesBuckets.Put(values);
    }
    auto [code, changedRows] = store->BatchInsert("test", valuesBuckets);  // 1G data
    EXPECT_EQ(code, E_OK) << "BatchInsert failed, code:" << code;
    EXPECT_EQ(changedRows, 1024) << "BatchInsert failed, changedRows:" << changedRows;

    std::shared_ptr<OHOS::BlockData<bool, std::chrono::milliseconds>> blockData =
        std::make_shared<OHOS::BlockData<bool, std::chrono::milliseconds>>(50, false);
    int backupCode = E_INVALID_ARGS;
    std::thread thread([store, blockData, &backupCode]() {
        blockData->SetValue(true);
        backupCode = store->Backup();
        blockData->SetValue(true);
    });
    ASSERT_TRUE(blockData->GetValue());
    blockData->Clear(false);
    ASSERT_FALSE(blockData->GetValue()); // Wait for 50ms for integrity verification to begin
    code = store->InterruptBackup();
    EXPECT_EQ(code, E_OK); // Without interrupting the backup process, return to E-CANCEL
    ASSERT_TRUE(blockData->GetValue());  // return promptly after interruption
    thread.join();
    EXPECT_EQ(backupCode, E_SQLITE_INTERRUPT);
    store = nullptr;
    char databaseName[] = "/data/test/new_backup_test.db";
    RdbHelper::DeleteRdbStore(databaseName);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_020
 * @tc.desc: Abnormal backup test cases, SINGLE and readOnly is not support
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_020, TestSize.Level0)
{
    auto store = InitStoreV2();
    ASSERT_NE(store, nullptr);
    int code = store->Backup();
    EXPECT_EQ(code, E_NOT_SUPPORT); // SINGLE is not support

    store = nullptr;
    store = InitStoreV2(true);
    code = store->Backup();
    EXPECT_EQ(code, E_NOT_SUPPORT); // readOnly is not support
    store = nullptr;
    char databaseName[] = "/data/test/new_backup_test.db";
    RdbHelper::DeleteRdbStore(databaseName);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_021
 * @tc.desc: Abnormal backup test cases, MODE_MEMORY is not support
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_021, TestSize.Level0)
{
    auto store = InitStoreV2(false, StorageMode::MODE_MEMORY);
    ASSERT_NE(store, nullptr);
    int code = store->Backup();
    EXPECT_EQ(code, E_NOT_SUPPORT); // MODE_MEMORY is not support
    store = nullptr;
    char databaseName[] = "/data/test/new_backup_test.db";
    RdbHelper::DeleteRdbStore(databaseName);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_022
 * @tc.desc: Abnormal backup test cases, DB_VECTOR is not support
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_022, TestSize.Level0)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    auto store = InitStoreV2(false, StorageMode::MODE_DISK, HAMode::SINGLE, DB_VECTOR);
    ASSERT_NE(store, nullptr);
    int code = store->Backup();
    EXPECT_EQ(code, E_NOT_SUPPORT);
    char databaseName[] = "/data/test/new_backup_test.db";
    store = nullptr;
    RdbHelper::DeleteRdbStore(databaseName);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_023
 * @tc.desc: Abnormal backup test cases, Backup is not supported when the standby database does not exist
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_023, TestSize.Level0)
{
    auto store = InitStore(HAMode::MANUAL_TRIGGER);
    ASSERT_NE(store, nullptr);

    int code = store->Backup();
    EXPECT_EQ(code, E_NOT_SUPPORT);

    store = nullptr;
    char databaseName[] = "/data/test/new_backup_test.db";
    RdbHelper::DeleteRdbStore(databaseName);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_024
 * @tc.desc: 1. create MAIN_REPLICA db
 *           2. create MANUAL_TRIGGER db and write some data
 *           3. delete db
 *           4. create slave db
 *           5. main db backup
 *           6. delete slave db
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_024, TestSize.Level0)
{
    auto store = InitStore(HAMode::MAIN_REPLICA, false);
    ASSERT_NE(store, nullptr);
    store = nullptr;
    store = InitStore(HAMode::MANUAL_TRIGGER);
    ASSERT_NE(store, nullptr);
    char databaseName[] = "/data/test/new_backup_test.db";
    RdbHelper::DeleteRdbStore(databaseName);

    char databaseSalveName[] = "/data/test/new_backup_test_slave.db";
    RdbStoreConfig config(databaseSalveName);
    config.SetHaMode(HAMode::SINGLE);
    RdbStoreBackupRestoreTestOpenCallback callback;
    int code = E_ERROR;
    auto salveStore = RdbHelper::GetRdbStore(config, 1, callback, code);
    ASSERT_NE(salveStore, nullptr);
    EXPECT_EQ(code, E_OK) << "GetRdbStore failed, code:" << code;

    code = store->Backup();
    EXPECT_EQ(code, E_ALREADY_CLOSED);
    salveStore = nullptr;
    RdbHelper::DeleteRdbStore(databaseSalveName);
}

/* *
 * @tc.name: Rdb_BackupRestoreTest_025
 * @tc.desc: 1. create MAIN_REPLICA db
 *           2. create MANUAL_TRIGGER db and write some data
 *           3. start thread to batchinsert 1000 rows
 *           4. backup to replica db
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_025, TestSize.Level0)
{
    auto store = InitStore(HAMode::MAIN_REPLICA, false);
    ASSERT_NE(store, nullptr);
    store = nullptr;
    store = InitStore(HAMode::MANUAL_TRIGGER);
    ASSERT_NE(store, nullptr);
    const uint32_t count = 1000;
    ValuesBucket values;
    values.PutString("name", std::string(1024 * 1024, 'a')); // 1MB
    values.PutInt("age", 18); // age is 18
    values.PutDouble("salary", 100.5); // salary is 100.5
    values.PutBlob("blobType", std::vector<uint8_t>(1024, 1));
    ValuesBuckets valuesBuckets;
    for (auto i = 0; i < count; i++) {
        valuesBuckets.Put(values);
    }

    std::shared_ptr<OHOS::BlockData<bool, std::chrono::milliseconds>> blockData =
        std::make_shared<OHOS::BlockData<bool, std::chrono::milliseconds>>(0, false);

    std::thread thread([store, valuesBuckets, blockData]() {
        blockData->SetValue(true);
        auto [code, changedRows] = store->BatchInsert("test", valuesBuckets);
        EXPECT_EQ(code, E_OK) << "BatchInsert failed, code:" << code;
        EXPECT_EQ(changedRows, 1000) << "BatchInsert failed, changedRows:" << changedRows;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(5)); // Sleep 5 milliseconds
    ASSERT_TRUE(blockData->GetValue());
    int code = store->Backup();
    EXPECT_EQ(code, E_DATABASE_BUSY);
    thread.join();
    store = nullptr;
    char databaseName[] = "/data/test/new_backup_test.db";
    RdbHelper::DeleteRdbStore(databaseName);
}

/**
 * @tc.name: Rdb_BackupRestoreTest_026
 * @tc.desc: 1.create MAIN_REPLICA db
 *           2.create MANUAL_TRIGGER db
 *           3.batchinsert 100 rows
 *           4.corrupt db
 *           5.backup to replica db
 *           6.delete db
 * @tc.type: FUNC
 */
HWTEST_F(RdbStoreBackupRestoreTest, Rdb_BackupRestoreTest_026, TestSize.Level0)
{
    auto store = InitStore(HAMode::MAIN_REPLICA, false);
    ASSERT_NE(store, nullptr);
    store = nullptr;
    store = InitStore(HAMode::MANUAL_TRIGGER, false);
    ASSERT_NE(store, nullptr);

    const uint32_t count = 100;
    ValuesBucket values;
    values.PutString("name", std::string(10, 'a'));
    values.PutInt("age", 18); // age is 18
    values.PutDouble("salary", 100.5); // salary is 100.5
    values.PutBlob("blobType", std::vector<uint8_t>(1024, 1));
    ValuesBuckets valuesBuckets;
    for (auto i = 0; i < count; i++) {
        valuesBuckets.Put(values);
    }
    auto [code, changedRows] = store->BatchInsert("test", valuesBuckets);  // 1G data
    EXPECT_EQ(code, E_OK) << "BatchInsert failed, code:" << code;
    EXPECT_EQ(changedRows, 100) << "BatchInsert failed, changedRows:" << changedRows;

    store = nullptr;
    char databaseName[] = "/data/test/new_backup_test.db";
    std::fstream file(databaseName, std::ios::in | std::ios::out | std::ios::binary);
    ASSERT_TRUE(file.is_open());

    file.seekp(0x2000, std::ios::beg);
    ASSERT_TRUE(file.good());

    char bytes[128];
    std::fill_n(bytes, 128, 0xff); // fill 128 bytes with 0xff
    file.write(bytes, 128);
    file.flush();
    file.close();

    store = InitStore(HAMode::MANUAL_TRIGGER, false);
    ASSERT_NE(store, nullptr);

    int errCode = store->Backup();
    EXPECT_EQ(errCode, E_SQLITE_CORRUPT);

    RdbHelper::DeleteRdbStore(databaseName);
}