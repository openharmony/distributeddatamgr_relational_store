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

#include "rdb_helper.h"

#include <gtest/gtest.h>

#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class OpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return E_OK;
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

class RdbHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void InitDb();

    static const std::string rdbStorePath;
    static std::shared_ptr<RdbStore> store;
};
const std::string RdbHelperTest::rdbStorePath = RDB_TEST_PATH + std::string("rdbhelper.db");
std::shared_ptr<RdbStore> RdbHelperTest::store = nullptr;

void RdbHelperTest::SetUpTestCase(void)
{
}

void RdbHelperTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(rdbStorePath);
}

void RdbHelperTest::SetUp(void)
{
}

void RdbHelperTest::TearDown(void)
{
}

class RdbHelperTestWrongSqlOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string WRONG_SQL_TEST;
};

class RdbHelperTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

void RdbHelperTest::InitDb()
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbHelperTest::rdbStorePath);
    RdbHelperTestOpenCallback helper;
    RdbHelperTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

const std::string RdbHelperTestWrongSqlOpenCallback::WRONG_SQL_TEST = "CREATE TABL IF NOT EXISTS test "
                                                                      "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                      "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                                      "blobType BLOB)";
const std::string RdbHelperTestOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                                                 "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                 "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                                 "blobType BLOB)";

int RdbHelperTestWrongSqlOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(WRONG_SQL_TEST);
}

int RdbHelperTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbHelperTestWrongSqlOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int RdbHelperTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

/**
 * @tc.name: DeleteDatabaseCache_001
 * @tc.desc: delete db cache
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbHelperTest, DeleteDatabaseCache_001, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbHelperTest::rdbStorePath);
    RdbHelperTestWrongSqlOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(rdbStore, nullptr);
}

/**
 * @tc.name: DeleteDatabase_001
 * @tc.desc: delete db file
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_001, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config1(RdbHelperTest::rdbStorePath);
    RdbStoreConfig config2("test");
    RdbStoreConfig config3("");
    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config1, 1, helper, errCode);
    EXPECT_NE(rdbStore, nullptr);
    int ret1 = RdbHelper::DeleteRdbStore(config1);
    EXPECT_EQ(ret1, E_OK);
    int ret2 = RdbHelper::DeleteRdbStore(config2);
    EXPECT_EQ(ret2, E_INVALID_FILE_PATH);
    int ret3 = RdbHelper::DeleteRdbStore(config3);
    EXPECT_EQ(ret3, E_INVALID_FILE_PATH);
}

/**
 * @tc.name: DeleteDatabase_002
 * @tc.desc: DeleteRdbStore if the dbFile is not exists
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_002, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbHelperTest::rdbStorePath);
    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(rdbStore, nullptr);

    remove(rdbStorePath.c_str());

    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);
    std::string shmFileName = rdbStorePath + "-shm";
    std::string walFileName = rdbStorePath + "-wal";
    EXPECT_NE(access(shmFileName.c_str(), F_OK), 0);
    EXPECT_NE(access(walFileName.c_str(), F_OK), 0);
}

/**
 * @tc.name: DeleteDatabase_003
 * @tc.desc: DeleteRdbStore if the dbFile is not exists
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_003, TestSize.Level1)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbHelperTest::rdbStorePath);
    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(rdbStore, nullptr);

    remove(rdbStorePath.c_str());

    int ret = RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(ret, E_OK);
    std::string shmFileName = rdbStorePath + "-shm";
    std::string walFileName = rdbStorePath + "-wal";
    EXPECT_NE(access(shmFileName.c_str(), F_OK), 0);
    EXPECT_NE(access(walFileName.c_str(), F_OK), 0);
}

/**
 * @tc.name: DeleteDatabase_004
 * @tc.desc: Update after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_004, TestSize.Level0)
{
    InitDb();
    int64_t id;
    int changedRows;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 19);
    values.PutDouble("salary", 200.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    ret = store->Update(changedRows, "test", values, "id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_005
 * @tc.desc: Insert after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_005, TestSize.Level0)
{
    InitDb();
    int64_t id;
    ValuesBucket values;

    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_006
 * @tc.desc: BatchInsert after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_006, TestSize.Level0)
{
    InitDb();
    int64_t id;
    ValuesBucket values;

    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });

    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 10; i++) {
        valuesBuckets.push_back(values);
    }
    ret = store->BatchInsert(id, "test", valuesBuckets);
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_007
 * @tc.desc: Delete after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_007, TestSize.Level0)
{
    InitDb();
    int64_t id;
    int deletedRows;
    ValuesBucket values;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);

    ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    ret = store->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_008
 * @tc.desc: QuerySql after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_008, TestSize.Level0)
{
    InitDb();
    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test WHERE id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(resultSet, nullptr);
}

/**
 * @tc.name: DeleteDatabase_009
 * @tc.desc: QueryByStep after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_009, TestSize.Level0)
{
    InitDb();
    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT * FROM test WHERE id = ?", std::vector<std::string>{ "1" });
    EXPECT_EQ(resultSet, nullptr);
}

/**
 * @tc.name: DeleteDatabase_010
 * @tc.desc: Restore after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_010, TestSize.Level0)
{
    InitDb();
    int ret = store->Backup("backup.db");
    EXPECT_EQ(ret, E_OK);

    ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    ret = store->Restore("backup.db");
    EXPECT_EQ(ret, E_ALREADY_CLOSED);

    RdbHelper::DeleteRdbStore(RDB_TEST_PATH + std::string("backup.db"));
}

/**
 * @tc.name: DeleteDatabase_011
 * @tc.desc: Backup after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_011, TestSize.Level0)
{
    InitDb();
    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    ret = store->Backup("backup.db");
    EXPECT_EQ(ret, E_DB_NOT_EXIST);
}

/**
 * @tc.name: DeleteDatabase_012
 * @tc.desc: CleanDirtyData after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_012, TestSize.Level0)
{
    InitDb();
    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    uint64_t cursor = UINT64_MAX;
    ret = store->CleanDirtyData("test", cursor);
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_013
 * @tc.desc: ExecuteSql after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_013, TestSize.Level0)
{
    InitDb();
    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    ret = store->ExecuteSql(RdbHelperTestOpenCallback::CREATE_TABLE_TEST);
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_014
 * @tc.desc: Execute after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_014, TestSize.Level0)
{
    InitDb();
    int ret1 = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret1, E_OK);

    auto [ret2, outValue] = store->Execute(RdbHelperTestOpenCallback::CREATE_TABLE_TEST);
    EXPECT_EQ(ret2, E_ALREADY_CLOSED);

    auto [code, result] = store->ExecuteExt(RdbHelperTestOpenCallback::CREATE_TABLE_TEST);
    EXPECT_EQ(code, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_015
 * @tc.desc: BeginTransaction after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_015, TestSize.Level0)
{
    InitDb();
    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_016
 * @tc.desc: Attach after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_016, TestSize.Level0)
{
    InitDb();
    int ret = 0;
    std::string attachPath = RDB_TEST_PATH + std::string("attached.db");
    RdbStoreConfig attachedConfig(attachPath);
    RdbHelperTestOpenCallback attachedHelper;
    std::shared_ptr<RdbStore> attachedStore = RdbHelper::GetRdbStore(attachedConfig, 1, attachedHelper, ret);
    EXPECT_NE(attachedStore, nullptr);

    ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    int busyTimeout = 2;
    std::string attachedName = "attached";
    auto err = store->Attach(attachedConfig, attachedName, busyTimeout);
    EXPECT_EQ(err.first, E_ALREADY_CLOSED);

    RdbHelper::DeleteRdbStore(attachPath);
}

/**
 * @tc.name: DeleteDatabase_017
 * @tc.desc: Detach after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_017, TestSize.Level0)
{
    InitDb();
    int ret = 0;
    std::string attachPath = RDB_TEST_PATH + std::string("attached.db");
    RdbStoreConfig attachedConfig(attachPath);
    RdbHelperTestOpenCallback attachedHelper;
    std::shared_ptr<RdbStore> attachedStore = RdbHelper::GetRdbStore(attachedConfig, 1, attachedHelper, ret);
    EXPECT_NE(attachedStore, nullptr);

    int busyTimeout = 2;
    std::string attachedName = "attached";
    auto err = store->Attach(attachedConfig, attachedName, busyTimeout);
    EXPECT_EQ(err.first, E_OK);

    ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    err = store->Detach(attachedName);
    EXPECT_EQ(err.first, E_ALREADY_CLOSED);

    RdbHelper::DeleteRdbStore(attachPath);
}

/**
 * @tc.name: DeleteDatabase_018
 * @tc.desc: CreateTransaction after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_018, TestSize.Level0)
{
    InitDb();
    int err = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(err, E_OK);

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_ALREADY_CLOSED);
    ASSERT_EQ(transaction, nullptr);
}

/**
 * @tc.name: DeleteDatabase_019
 * @tc.desc: BeginTrans after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_019, TestSize.Level0)
{
    InitDb();
    int err = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(err, E_OK);

    auto ret = store->BeginTrans();
    ASSERT_EQ(ret.first, E_NOT_SUPPORT);
}

/**
 * @tc.name: DeleteDatabase_020
 * @tc.desc: Commit after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_020, TestSize.Level0)
{
    InitDb();
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    ret = store->Commit();
    ASSERT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_021
 * @tc.desc: GetModifyTime after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_021, TestSize.Level0)
{
    InitDb();
    store->ExecuteSql("CREATE TABLE naturalbase_rdb_aux_rdbstoreimpltest_integer_log "
                       "(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER, data_key INTEGER, "
                       "data3 FLOAT, data4 BLOB, data5 BOOLEAN);");
    int64_t rowId;
    ValuesBucket valuesBucket;
    valuesBucket.PutInt("data_key", ValueObject(2));
    int errorCode = store->Insert(rowId, "naturalbase_rdb_aux_rdbstoreimpltest_integer_log", valuesBucket);
    EXPECT_EQ(E_OK, errorCode);
    EXPECT_EQ(1, rowId);

    errorCode = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(errorCode, E_OK);

    std::vector<RdbStore::PRIKey> PKey = { 1 };
    std::map<RdbStore::PRIKey, RdbStore::Date> result =
        store->GetModifyTime("rdbstoreimpltest_integer", "ROWID", PKey);
    int size = result.size();
    EXPECT_EQ(0, size);
}

/**
 * @tc.name: DeleteDatabase_022
 * @tc.desc: RollBack after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_022, TestSize.Level0)
{
    InitDb();
    int ret = store->BeginTransaction();
    EXPECT_EQ(ret, E_OK);

    ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    ret = store->RollBack();
    ASSERT_EQ(ret, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_023
 * @tc.desc: Transaction insert after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_023, TestSize.Level0)
{
    InitDb();
    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    int err = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(err, E_OK);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);
}

/**
 * @tc.name: DeleteDatabase_024
 * @tc.desc: BatchInsert after deleteRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, DeleteDatabase_024, TestSize.Level0)
{
    InitDb();
    ValuesBuckets rows;

    int ret = RdbHelper::DeleteRdbStore(RdbHelperTest::rdbStorePath);
    EXPECT_EQ(ret, E_OK);

    for (int32_t i = 0; i < 10; i++) {
        ValuesBucket row;
        row.Put("id", i);
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto result = store->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(result.first, E_ALREADY_CLOSED);
}

/**
 * @tc.name: getrdbstore_001
 * @tc.desc: get db file with a invalid path
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, GetDatabase_001, TestSize.Level0)
{
    int errCode = E_OK;
    RdbStoreConfig config("/invalid/invalid/test.db");
    OpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(store, nullptr);
    EXPECT_EQ(errCode, E_INVALID_FILE_PATH);
}

HWTEST_F(RdbHelperTest, GetDatabase_002, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase.db";
    RdbStoreConfig config(dbPath);
    std::string bundleName = "com.ohos.config.GetDatabase";
    config.SetBundleName(bundleName);
    config.SetArea(1);
    config.SetEncryptStatus(true);

    RdbHelper::DeleteRdbStore(config);

    int errCode = E_OK;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore1, nullptr);

    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore2, nullptr);

    EXPECT_EQ(rdbStore1, rdbStore2);
}

HWTEST_F(RdbHelperTest, GetDatabase_003, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase.db";
    RdbStoreConfig config(dbPath);
    std::string bundleName = "com.ohos.config.GetDatabase";
    config.SetBundleName(bundleName);
    config.SetArea(1);
    config.SetEncryptStatus(true);

    RdbHelper::DeleteRdbStore(config);

    // Ensure that the database returns OK when it is successfully opened
    int errCode = E_ERROR;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore1, nullptr);

    config.SetEncryptStatus(false);
    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    // Ensure that the database can be opened after the encryption parameters are changed
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore2, nullptr);

    // Ensure that two databases will not be opened after the encrypt parameters are changed
    EXPECT_EQ(rdbStore1, rdbStore2);
}

HWTEST_F(RdbHelperTest, GetDatabase_004, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase.db";
    RdbStoreConfig config(dbPath);
    std::string bundleName = "com.ohos.config.GetDatabase";
    config.SetBundleName(bundleName);
    config.SetArea(1);
    config.SetEncryptStatus(true);

    RdbHelper::DeleteRdbStore(config);

    int errCode = E_OK;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore1, nullptr);

    config.SetVisitorDir(dbPath);
    config.SetRoleType(RoleType::VISITOR_WRITE);
    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(errCode, E_OK);
    EXPECT_EQ(rdbStore2, nullptr);
}

HWTEST_F(RdbHelperTest, GetDatabase_005, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetSubUserDatabase.db";
    RdbStoreConfig config(dbPath);
    config.SetName("RdbStoreConfig_test.db");
    std::string bundleName = "com.ohos.config.TestSubUser";
    config.SetBundleName(bundleName);
    config.SetSubUser(100);
    auto subUser = config.GetSubUser();
    EXPECT_EQ(subUser, 100);
    int errCode = E_OK;
 
    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore1, nullptr);
 
    int ret = RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: GetDatabase_006
 * @tc.desc: Insert after GetRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, GetDatabase_006, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase1.db";
    RdbStoreConfig config(dbPath);
    config.SetName("RdbStoreConfig_test.db");
    std::string bundleName = "com.ohos.config.TestSubUser";
    config.SetBundleName(bundleName);
    config.SetSubUser(100);
    auto subUser = config.GetSubUser();
    EXPECT_EQ(subUser, 100);
    int errCode = E_OK;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore1, nullptr);
    rdbStore1->ExecuteSql("CREATE TABLE IF NOT EXISTS test "
                          "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, age INTEGER, salary "
                          "REAL, blobType BLOB);");

    int64_t id;
    ValuesBucket values;
    int deletedRows;

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    values.PutDouble("salary", 100.5);
    values.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    int ret = rdbStore1->Insert(id, "test", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    ret = rdbStore1->Delete(deletedRows, "test", "id = 1", std::vector<std::string>());
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(deletedRows, 1);

    ret = RdbHelper::DeleteRdbStore(config);
    EXPECT_EQ(ret, E_OK);
}

/**
 * @tc.name: GetDatabase_007
 * @tc.desc: Insert after GetRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, GetDatabase_007, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase_007.db";
    RdbStoreConfig config(dbPath);
    config.SetStorageMode(StorageMode::MODE_MEMORY);

    RdbHelper::DeleteRdbStore(config);

    // Ensure that the database returns OK when it is successfully opened
    int errCode = E_ERROR;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore1, nullptr);

    RdbHelper::DeleteRdbStore(dbPath);
    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    // Ensure that the database can be opened after the encryption parameters are changed
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore2, nullptr);

    // Ensure that two databases not equal
    EXPECT_NE(rdbStore1, rdbStore2);
}

/**
 * @tc.name: GetDatabase_008
 * @tc.desc: Use the config of the new version to open the database, and then use the config of the old version to open the database. The error code 14800017 is expected to be reported
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, GetDatabase_008, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase_008.db";
    RdbStoreConfig config(dbPath);
    config.SetVersion(ConfigVersion::INVALID_CONFIG_CHANGE_NOT_ALLOWED);
    config.SetSecurityLevel(SecurityLevel::S1);
    RdbHelper::DeleteRdbStore(config);

    int errCode = E_ERROR;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore1, nullptr);

    RdbStoreConfig changedConfig(dbPath);
    changedConfig.SetVersion(ConfigVersion::DEFAULT_VERSION);
    changedConfig.SetSecurityLevel(SecurityLevel::S2);

    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(changedConfig, 1, helper, errCode);
    EXPECT_EQ(errCode, E_CONFIG_INVALID_CHANGE);
}

/**
 * @tc.name: GetDatabase_009
 * @tc.desc: Use the config of the old version to open the database, and then use the config of the new version to open the database. The error code 14800017 is expected to be reported
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, GetDatabase_009, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase_009.db";
    RdbStoreConfig config(dbPath);
    config.SetVersion(ConfigVersion::DEFAULT_VERSION);
    config.SetSecurityLevel(SecurityLevel::S1);
    RdbHelper::DeleteRdbStore(config);

    int errCode = E_ERROR;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore1, nullptr);

    RdbStoreConfig changedConfig(dbPath);
    changedConfig.SetVersion(ConfigVersion::INVALID_CONFIG_CHANGE_NOT_ALLOWED);
    changedConfig.SetSecurityLevel(SecurityLevel::S2);

    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(changedConfig, 1, helper, errCode);
    EXPECT_EQ(errCode, E_CONFIG_INVALID_CHANGE);
}

/**
 * @tc.name: GetDatabase_010
 * @tc.desc: The config configuration of the memory database is changed
 * @tc.type: FUNC
 */
HWTEST_F(RdbHelperTest, GetDatabase_010, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "GetDatabase_010.db";
    RdbStoreConfig config(dbPath);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    config.SetPageSize(1024);
    RdbHelper::DeleteRdbStore(config);

    int errCode = E_ERROR;

    RdbHelperTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore1 = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore1, nullptr);

    RdbStoreConfig changedConfig(dbPath);
    changedConfig.SetStorageMode(StorageMode::MODE_MEMORY);
    changedConfig.SetPageSize(2048);

    std::shared_ptr<RdbStore> rdbStore2 = RdbHelper::GetRdbStore(changedConfig, 1, helper, errCode);
    EXPECT_EQ(errCode, E_CONFIG_INVALID_CHANGE);
}