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

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_impl.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

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
    void CheckResultSet(std::shared_ptr<RdbStore> &store);
    void CheckAge(std::shared_ptr<ResultSet> &resultSet);
    void CheckSalary(std::shared_ptr<ResultSet> &resultSet);
    void CheckBlob(std::shared_ptr<ResultSet> &resultSet);

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
    EXPECT_EQ(ret, E_OK);

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);

    values.Clear();
    values.Put("id", 2);
    values.Put("name", std::string("lisa"));
    values.Put("age", 19);
    values.Put("salary", 101);
    values.Put("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(2, id);

    resultSet = store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "lisa" });
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
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
    EXPECT_EQ(errCode, E_OK);

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
    EXPECT_NE(0, access(BACKUP_DATABASE_NAME, F_OK));
    EXPECT_NE(0, access(slaveDataBaseName, F_OK));

    ret = store->Restore(BACKUP_DATABASE_NAME);
    EXPECT_EQ(ret, E_INVALID_FILE_PATH);

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE name = ?", std::vector<std::string>{ "zhangsan" });
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_SQLITE_IOERR);
    ret = resultSet->Close();
    EXPECT_EQ(ret, E_OK);
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