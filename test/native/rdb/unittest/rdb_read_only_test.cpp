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
#include "grd_api_manager.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace Test {
class RdbReadOnlyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string READONLY_DATABASE_NAME;
    static const std::string READONLY_DATABASE_NAME_18; // for testcase 18
    static const std::string READONLY_DATABASE_BAK_NAME;
    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> readOnlyStore;
};

const std::string RdbReadOnlyTest::DATABASE_NAME = RDB_TEST_PATH + "database.db";
const std::string RdbReadOnlyTest::READONLY_DATABASE_NAME = RDB_TEST_PATH + "readOnly.db";
const std::string RdbReadOnlyTest::READONLY_DATABASE_NAME_18 = RDB_TEST_PATH + "readOnly1.db";
const std::string RdbReadOnlyTest::READONLY_DATABASE_BAK_NAME = RDB_TEST_PATH + "readOnlyBak.db";
std::shared_ptr<RdbStore> RdbReadOnlyTest::readOnlyStore = nullptr;

class ReadOnlyTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string ReadOnlyTestOpenCallback::CREATE_TABLE_TEST =
    "CREATE TABLE IF NOT EXISTS test "
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER, salary REAL, blobType BLOB)";

int ReadOnlyTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int ReadOnlyTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbReadOnlyTest::SetUpTestCase(void)
{
    int errCode = E_ERROR;
    RdbHelper::DeleteRdbStore(READONLY_DATABASE_NAME);
    RdbStoreConfig config(READONLY_DATABASE_NAME);
    config.SetBundleName("com.example.readOnly.rdb");
    ReadOnlyTestOpenCallback helper;
    // user_version is 1
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store);
    EXPECT_EQ(E_OK, errCode);

    int64_t id;
    ValuesBucket values;
    values.PutString("name", "zhangSan");
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(E_OK, ret);
    // id is 1
    EXPECT_EQ(1, id);

    RdbHelper::ClearCache();

    RdbStoreConfig config1(READONLY_DATABASE_NAME);
    config1.SetBundleName("com.example.readOnly.rdb");
    config1.SetReadOnly(true);
    ReadOnlyTestOpenCallback helper1;
    // user_version is 1
    readOnlyStore = RdbHelper::GetRdbStore(config1, 1, helper1, errCode);
    EXPECT_NE(nullptr, readOnlyStore);
    EXPECT_EQ(E_OK, errCode);
}

void RdbReadOnlyTest::TearDownTestCase(void)
{
    readOnlyStore = nullptr;
    EXPECT_EQ(E_OK, RdbHelper::DeleteRdbStore(RdbReadOnlyTest::DATABASE_NAME));
    EXPECT_EQ(E_OK, RdbHelper::DeleteRdbStore(RdbReadOnlyTest::READONLY_DATABASE_NAME));
    EXPECT_EQ(E_OK, RdbHelper::DeleteRdbStore(RdbReadOnlyTest::READONLY_DATABASE_BAK_NAME));
}

void RdbReadOnlyTest::SetUp()
{
}

void RdbReadOnlyTest::TearDown()
{
}

/**
 * @tc.name: RdbStore_ReadOnly_0001, open read-only database if the database is not exist
 * @tc.desc: 1. set isReadOnly as true
 *           2. open read-only database
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0001, TestSize.Level1)
{
    int errCode = E_ERROR;
    RdbStoreConfig config(RdbReadOnlyTest::DATABASE_NAME);
    config.SetReadOnly(true);
    ReadOnlyTestOpenCallback helper;
    // create read-only database, user_version is 1
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(nullptr, store);
    EXPECT_EQ(E_SQLITE_CANTOPEN, errCode);
}

/**
 * @tc.name: RdbStore_ReadOnly_0002, insert data
 * @tc.desc: insert data into read-only database
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int64_t id;
    ValuesBucket values;
    values.PutString("name", "liSi");
    int ret = store->Insert(id, "test", values);
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0003, update data
 * @tc.desc: update data in read-only database
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int changedRows;
    ValuesBucket values;
    // salary is 300.5
    values.PutDouble("salary", 300.5);
    auto ret = store->Update(changedRows, "test", values);
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0004, delete data
 * @tc.desc: delete data from read-only database
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int deletedRows;
    auto ret = store->Delete(deletedRows, "test", "id = 1");
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0005
 * @tc.desc: execute transaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0005, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    auto ret = store->BeginTransaction();
    EXPECT_EQ(E_NOT_SUPPORT, ret);

    ret = store->Commit();
    EXPECT_EQ(E_NOT_SUPPORT, ret);

    ret = store->RollBack();
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0006
 * @tc.desc: batch insert data
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0006, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int64_t number = 0;
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket values;
    values.PutString("name", "zhangSan");
    valuesBuckets.push_back(std::move(values));
    int error = store->BatchInsert(number, "test", valuesBuckets);
    EXPECT_EQ(E_NOT_SUPPORT, error);
}

/**
 * @tc.name: RdbStore_ReadOnly_0007
 * @tc.desc: get user_version by querySql
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0007, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    auto resultSet = store->QuerySql("PRAGMA user_version");

    EXPECT_NE(nullptr, resultSet);
    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    int value = 0;
    // column index is 0
    EXPECT_EQ(E_OK, resultSet->GetInt(0, value));
    EXPECT_EQ(1, value);

    EXPECT_EQ(E_OK, resultSet->Close());
}

/**
 * @tc.name: RdbStore_ReadOnly_0008
 * @tc.desc: get user_version by execute
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0008, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    auto [ret, object] = store->Execute("PRAGMA user_version");
    EXPECT_EQ(E_NOT_SUPPORT, ret);

    std::tie(ret, object) = store->Execute("PRAGMA user_version=2");
    EXPECT_EQ(E_NOT_SUPPORT, ret);

    auto [code, result] = store->ExecuteExt("PRAGMA user_version=2");
    EXPECT_EQ(E_NOT_SUPPORT, code);
}

/**
 * @tc.name: RdbStore_ReadOnly_0009
 * @tc.desc: query data
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0009, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    auto resultSet = store->QuerySql("SELECT * FROM test");

    int count = 0;
    EXPECT_EQ(E_OK, resultSet->GetRowCount(count));
    // count is 1
    EXPECT_EQ(1, count);

    EXPECT_EQ(E_OK, resultSet->Close());
}

/**
 * @tc.name: RdbStore_ReadOnly_0010
 * @tc.desc: get user_version by executeSql
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0010, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    auto ret = store->ExecuteSql("PRAGMA user_version");
    EXPECT_EQ(E_NOT_SUPPORT, ret);

    ret = store->ExecuteSql("SELECT * FROM test");
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0011
 * @tc.desc: replace data
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0011, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int64_t id;
    ValuesBucket values;
    values.PutString("name", "zhangSan");
    int ret = store->Replace(id, "test", values);
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0012
 * @tc.desc: test ExecuteAndGetLong
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0012, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int64_t count;
    int ret = store->ExecuteAndGetLong(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(E_OK, ret);

    ret = store->ExecuteAndGetLong(count, "PRAGMA user_version");
    EXPECT_EQ(E_DATABASE_BUSY, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0013
 * @tc.desc: test ExecuteAndGetString
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0013, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    std::string count;
    int ret = store->ExecuteAndGetString(count, "SELECT COUNT(*) FROM test");
    EXPECT_EQ(E_OK, ret);

    ret = store->ExecuteAndGetString(count, "PRAGMA user_version");
    EXPECT_EQ(E_DATABASE_BUSY, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0014
 * @tc.desc: test ExecuteForLastInsertedRowId
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0014, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int64_t outValue;
    int ret = store->ExecuteForLastInsertedRowId(outValue, "", {});
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0015
 * @tc.desc: test ExecuteForChangedRowCount
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0015, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int64_t outValue;
    int ret = store->ExecuteForChangedRowCount(outValue, "", {});
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0016
 * @tc.desc: get user_version by GetVersion
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0016, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int version = -1;
    auto ret = store->GetVersion(version);
    EXPECT_EQ(E_OK, ret);
    // version is 1
    EXPECT_EQ(1, version);
}

/**
 * @tc.name: RdbStore_ReadOnly_0017
 * @tc.desc: set user_version by SetVersion
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0017, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    int version = 2;
    auto ret = store->SetVersion(version);
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0018
 * @tc.desc: test vector db
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0018, TestSize.Level1)
{
    if (!OHOS::NativeRdb::IsUsingArkData()) {
        return;
    }
    int errCode = E_ERROR;
    RdbStoreConfig config(RdbReadOnlyTest::READONLY_DATABASE_NAME_18);
    config.SetBundleName("com.example.readOnly.rdb");
    config.SetReadOnly(true);
    config.SetIsVector(true);
    ReadOnlyTestOpenCallback helper;
    // user_version is 1
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(nullptr, store);

    auto [ret, id] = store->BeginTrans();
    EXPECT_EQ(E_NOT_SUPPORT, ret);

    // id is 1
    ret = store->Commit(1);
    EXPECT_EQ(E_NOT_SUPPORT, ret);

    // id is 1
    ret = store->RollBack(1);
    EXPECT_EQ(E_NOT_SUPPORT, ret);

    ValueObject obj;
    // id is 1
    std::tie(ret, obj) = store->Execute("PRAGMA user_version", {}, 1);
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0019
 * @tc.desc: test encrypt db
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0019, TestSize.Level1)
{
    int errCode = E_ERROR;
    RdbStoreConfig config(RdbReadOnlyTest::DATABASE_NAME);
    config.SetBundleName("com.example.encrypt.rdb");
    config.SetEncryptStatus(true);
    ReadOnlyTestOpenCallback helper;
    // user_version is 1
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store);

    RdbHelper::ClearCache();

    RdbStoreConfig config1(RdbReadOnlyTest::DATABASE_NAME);
    config1.SetBundleName("com.example.encrypt.rdb");
    config1.SetReadOnly(true);
    config1.SetEncryptStatus(true);
    // user_version is 1
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(nullptr, store);

    EXPECT_EQ(E_OK, RdbHelper::DeleteRdbStore(RdbReadOnlyTest::DATABASE_NAME));
}

/**
 * @tc.name: RdbStore_ReadOnly_0020
 * @tc.desc: test attach and detach
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0020, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    RdbStoreConfig config(RdbReadOnlyTest::READONLY_DATABASE_NAME);
    auto [ret, size] = store->Attach(config, RdbReadOnlyTest::DATABASE_NAME);
    EXPECT_EQ(E_NOT_SUPPORT, ret);

    std::tie(ret, size) = store->Detach(RdbReadOnlyTest::DATABASE_NAME);
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0021
 * @tc.desc: test SetDistributedTables
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0021, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    AbsRdbPredicates predicates("test");
    OHOS::DistributedRdb::DistributedConfig config;
    // type is 0
    auto ret = store->SetDistributedTables({}, 0, config);
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0022
 * @tc.desc: test CleanDirtyData
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0022, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    uint64_t cursor = 1;
    auto ret = store->CleanDirtyData("test", cursor);
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/**
 * @tc.name: RdbStore_ReadOnly_0023
 * @tc.desc: test BatchInsert
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_ReadOnly_0023, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        ValuesBucket row;
        row.Put("name", "Jim");
        rows.Put(row);
    }
    auto ret = store->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(E_NOT_SUPPORT, ret.first);
    ret = store->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    EXPECT_EQ(E_NOT_SUPPORT, ret.first);
    ret = store->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_ABORT);
    EXPECT_EQ(E_NOT_SUPPORT, ret.first);
    ret = store->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_FAIL);
    EXPECT_EQ(E_NOT_SUPPORT, ret.first);
    ret = store->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_IGNORE);
    EXPECT_EQ(E_NOT_SUPPORT, ret.first);
    ret = store->BatchInsert("test", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    EXPECT_EQ(E_NOT_SUPPORT, ret.first);
}

/**
 * @tc.name: RdbStore_CreateTransaction_001
 * @tc.desc: test Create Transaction
 * @tc.type: FUNC
 */
HWTEST_F(RdbReadOnlyTest, RdbStore_CreateTransaction_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = RdbReadOnlyTest::readOnlyStore;
    auto [errCode, trans] = store->CreateTransaction(Transaction::DEFERRED);
    EXPECT_EQ(E_NOT_SUPPORT, errCode);
    EXPECT_EQ(trans, nullptr);

    std::tie(errCode, trans) = store->CreateTransaction(Transaction::IMMEDIATE);
    EXPECT_EQ(E_NOT_SUPPORT, errCode);
    EXPECT_EQ(trans, nullptr);

    std::tie(errCode, trans) = store->CreateTransaction(Transaction::EXCLUSIVE);
    EXPECT_EQ(E_NOT_SUPPORT, errCode);
    EXPECT_EQ(trans, nullptr);
}
}