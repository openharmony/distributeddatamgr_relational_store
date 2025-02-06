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
#include "rdb_store_impl.h"

#include <gtest/gtest.h>

#include <map>
#include <string>
#include <fstream>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbStoreBackupRestoreTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
    void CheckResultSet(std::shared_ptr<RdbStore> &store);
    void CheckAge(std::shared_ptr<ResultSet> &resultSet);
    void CheckSalary(std::shared_ptr<ResultSet> &resultSet);
    void CheckBlob(std::shared_ptr<ResultSet> &resultSet);

    static constexpr char DATABASE_NAME[] = "/data/test/backup_restore_test.db";
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

void RdbStoreBackupRestoreTest::CheckResultSet(std::shared_ptr<RdbStore> &store)
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

    CheckAge(resultSet);
    CheckSalary(resultSet);
    CheckBlob(resultSet);

    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);

    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
}

void RdbStoreBackupRestoreTest::CheckAge(std::shared_ptr<ResultSet> &resultSet)
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
    // 18: age is 18
    EXPECT_EQ(18, intVal);
}

void RdbStoreBackupRestoreTest::CheckSalary(std::shared_ptr<ResultSet> &resultSet)
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
    // 100.5: salary is 100.5
    EXPECT_EQ(100.5, dVal);
}

void RdbStoreBackupRestoreTest::CheckBlob(std::shared_ptr<ResultSet> &resultSet)
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
    // 3: blob size
    EXPECT_EQ(3, static_cast<int>(blob.size()));
    // 1: blob[0] is 1
    EXPECT_EQ(1, blob[0]);
    // 2: blob[1] is 2
    EXPECT_EQ(2, blob[1]);
    // 3: blob[2] is 3
    EXPECT_EQ(3, blob[2]);
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

    CheckResultSet(store);

    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME);
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

    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbHelper::DeleteRdbStore(BACKUP_DATABASE_NAME);
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
 
    CheckResultSet(store);
 
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::DATABASE_NAME);
    RdbHelper::DeleteRdbStore(RdbStoreBackupRestoreTest::BACKUP_DATABASE_NAME);
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
