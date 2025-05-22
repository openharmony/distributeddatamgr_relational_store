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

#include <gtest/gtest.h>

#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
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

class RdbMemoryDbTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void InitDb();

    static const std::string rdbStorePath;
    static std::shared_ptr<RdbStore> g_store;
};
const std::string RdbMemoryDbTest::rdbStorePath = RDB_TEST_PATH + std::string("MemoryTest");
std::shared_ptr<RdbStore> RdbMemoryDbTest::g_store = nullptr;

void RdbMemoryDbTest::SetUpTestCase(void)
{
}

void RdbMemoryDbTest::TearDownTestCase(void)
{
}

void RdbMemoryDbTest::SetUp(void)
{
    InitDb();
}

void RdbMemoryDbTest::TearDown(void)
{
    RdbStoreConfig config(rdbStorePath);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbHelper::DeleteRdbStore(config);
}

class RdbMemoryDbTestWrongSqlOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};
constexpr const char *WRONG_SQL_TEST = "CREATE TABL IF NOT EXISTS test "
                                 "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                 "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                 "blobType BLOB)";
class RdbMemoryDbTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};
constexpr const char *CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                    "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                    "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                    "blobType BLOB)";
void RdbMemoryDbTest::InitDb()
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbMemoryDbTest::rdbStorePath);
    RdbMemoryDbTestOpenCallback helper;
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbMemoryDbTest::g_store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(g_store, nullptr);
    ASSERT_EQ(errCode, E_OK);
}

int RdbMemoryDbTestWrongSqlOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(WRONG_SQL_TEST);
}

int RdbMemoryDbTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbMemoryDbTestWrongSqlOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int RdbMemoryDbTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}
/**
* @tc.name: GetMemoryDb_001
* @tc.desc: Get MemoryDb with different config
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(RdbMemoryDbTest, GetMemoryDb_001, TestSize.Level1)
{
    int errCode = E_ERROR;
    std::string path = RDB_TEST_PATH + "GetMemoryDb_001";
    RdbStoreConfig config(path.c_str());
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbMemoryDbTestOpenCallback normalCallback;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);
    ASSERT_NE(access(path.c_str(), F_OK), 0);
    rdbStore = nullptr;

    RdbMemoryDbTestWrongSqlOpenCallback abnormalHelper;
    rdbStore = RdbHelper::GetRdbStore(config, 1, abnormalHelper, errCode);
    EXPECT_NE(errCode, E_OK);
    EXPECT_EQ(rdbStore, nullptr);
    rdbStore = nullptr;

    config.SetSearchable(true);
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
    EXPECT_EQ(rdbStore, nullptr);
    rdbStore = nullptr;
    config.SetSearchable(false);

    config.SetIsVector(true);
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
    EXPECT_EQ(rdbStore, nullptr);
    rdbStore = nullptr;
    config.SetIsVector(false);

    config.SetEncryptStatus(true);
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
    EXPECT_EQ(rdbStore, nullptr);
    rdbStore = nullptr;
    config.SetEncryptStatus(false);

    config.SetHaMode(HAMode::MAIN_REPLICA);
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
    EXPECT_EQ(rdbStore, nullptr);
    rdbStore = nullptr;
    config.SetHaMode(HAMode::SINGLE);

    config.SetRoleType(RoleType::VISITOR);
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_NOT_SUPPORT);
    EXPECT_EQ(rdbStore, nullptr);
}

/**
* @tc.name: GetMemoryDb_002
* @tc.desc: Get MemoryDb with different config
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(RdbMemoryDbTest, GetMemoryDb_002, TestSize.Level1)
{
    int errCode = E_ERROR;
    std::string path = RDB_TEST_PATH + "GetMemoryDb_002";
    RdbStoreConfig config(path);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbMemoryDbTestOpenCallback normalCallback;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    config.SetPageSize(1024);
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_CONFIG_INVALID_CHANGE);
    EXPECT_EQ(rdbStore, nullptr);
}

/**
* @tc.name: GetMemoryDb_003
* @tc.desc: Get MemoryDb after delete
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(RdbMemoryDbTest, GetMemoryDb_003, TestSize.Level1)
{
    int errCode = E_ERROR;
    std::string path = RDB_TEST_PATH + "GetMemoryDb_003";
    RdbStoreConfig config(path);
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbMemoryDbTestOpenCallback normalCallback;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);

    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    auto [ret, row] = rdbStore->Insert("test", values);
    EXPECT_EQ(ret, E_OK);
    auto pred = AbsRdbPredicates("test");
    auto resultSet = rdbStore->Query(pred);
    ASSERT_NE(resultSet, nullptr);
    int count = -1;
    EXPECT_EQ(resultSet->GetRowCount(count), E_OK);
    EXPECT_EQ(count, 1);

    auto rdbStore2 = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore2, nullptr);
    resultSet = rdbStore2->Query(pred);
    ASSERT_NE(resultSet, nullptr);
    count = -1;
    EXPECT_EQ(resultSet->GetRowCount(count), E_OK);
    EXPECT_EQ(count, 1);
    resultSet = nullptr;

    RdbHelper::DeleteRdbStore(config);
    std::tie(ret, row) = rdbStore->Insert("test", values);
    EXPECT_EQ(ret, E_ALREADY_CLOSED);

    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);
    resultSet = rdbStore->Query(pred);
    ASSERT_NE(resultSet, nullptr);
    count = -1;
    EXPECT_EQ(resultSet->GetRowCount(count), E_OK);
    EXPECT_EQ(count, 0);
}

/**
* @tc.name: CRUD of MemoryDb_001
* @tc.desc: CRUD with Transaction of MemoryDb
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(RdbMemoryDbTest, CRUDWithMemoryDb_001, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = g_store;

    auto [ret, transaction] = store->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(1, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[1]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(2, result.second);

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    ASSERT_EQ(result.first, E_SQLITE_LOCKED);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 2);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    ValueObject value;
    ret = resultSet->Get(0, value);
    ASSERT_EQ(ret, E_ALREADY_CLOSED);

    result = store->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[2]), RdbStore::NO_ACTION);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(3, result.second);

    result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_ALREADY_CLOSED);

    resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    resultSet->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 3);
}

/**
* @tc.name: CRUD of MemoryDb_002
* @tc.desc: CRUD with Transaction of MemoryDb
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(RdbMemoryDbTest, CRUDWithMemoryDb_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = g_store;

    auto [ret, transaction] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    auto result = transaction->Insert("test", UTUtils::SetRowData(UTUtils::g_rowData[0]));
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    result = transaction->Update("test", UTUtils::SetRowData(UTUtils::g_rowData[1]), "id=1");
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    auto resultSet = transaction->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    int32_t rowCount{};
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
    ret = resultSet->GoToFirstRow();
    ASSERT_EQ(ret, E_OK);
    int32_t columnIndex{};
    ret = resultSet->GetColumnIndex("id", columnIndex);
    ASSERT_EQ(ret, E_OK);
    int32_t id{};
    ret = resultSet->GetInt(columnIndex, id);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(id, 2);

    AbsRdbPredicates predicates("test");
    predicates.EqualTo("id", ValueObject(2));
    result = transaction->Update(UTUtils::SetRowData(UTUtils::g_rowData[2]), predicates);
    ASSERT_EQ(result.first, E_OK);
    ASSERT_EQ(result.second, 1);

    ret = transaction->Commit();
    ASSERT_EQ(ret, E_OK);

    resultSet = store->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSet, nullptr);
    ret = resultSet->GetRowCount(rowCount);
    ASSERT_EQ(ret, E_OK);
    ASSERT_EQ(rowCount, 1);
    ret = resultSet->GoToFirstRow();
    ASSERT_EQ(ret, E_OK);
    resultSet->GetColumnIndex("id", columnIndex);
    ret = resultSet->GetInt(columnIndex, id);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(id, 3);
}

/**
* @tc.name: CRUD of MemoryDb_003
* @tc.desc: CRUD with Transaction of MemoryDb
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(RdbMemoryDbTest, CRUDWithMemoryDb_003, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = g_store;
    store->Execute("DROP TABLE IF EXISTS test1");
    auto res = store->Execute("CREATE TABLE test1 (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
    ASSERT_EQ(res.first, E_OK);
    auto [ret1, transaction1] = store->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(ret1, E_OK);
    ASSERT_NE(transaction1, nullptr);

    auto [ret, transaction] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret, E_OK);
    ASSERT_NE(transaction, nullptr);

    ValuesBuckets rows;
    for (int i = 0; i < 5; i++) {
        Transaction::Row row;
        row.Put("id", i);
        row.Put("name", "Jim_batchInsert");
        rows.Put(row);
    }
    auto result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_NONE);
    ASSERT_EQ(result.first, E_SQLITE_LOCKED);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ROLLBACK);
    ASSERT_EQ(result.first, E_SQLITE_LOCKED);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_ABORT);
    ASSERT_EQ(result.first, E_SQLITE_LOCKED);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_FAIL);
    ASSERT_EQ(result.first, E_SQLITE_LOCKED);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_IGNORE);
    ASSERT_EQ(result.first, E_SQLITE_LOCKED);
    ASSERT_EQ(result.second, -1);

    result = transaction->BatchInsert("test1", rows, ConflictResolution::ON_CONFLICT_REPLACE);
    ASSERT_EQ(result.first, E_SQLITE_LOCKED);
    ASSERT_EQ(result.second, -1);
}

/**
* @tc.name: CRUD of MemoryDb_004
* @tc.desc: CRUD with Transaction of MemoryDb
* @tc.type: FUNC
* @tc.require:
* @tc.author:
*/
HWTEST_F(RdbMemoryDbTest, CRUDWithMemoryDb_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> &store = g_store;

    auto [ret1, transaction1] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret1, E_OK);
    ASSERT_NE(transaction1, nullptr);

    auto [ret2, transaction2] = store->CreateTransaction(Transaction::DEFERRED);
    ASSERT_EQ(ret2, E_OK);
    ASSERT_NE(transaction2, nullptr);

    auto [ret3, transaction3] = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret3, E_OK);
    ASSERT_NE(transaction3, nullptr);

    auto [ret4, transaction4] = store->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(ret4, E_SQLITE_LOCKED);
    ASSERT_EQ(transaction4, nullptr);
    transaction3 = nullptr;

    std::tie(ret4, transaction4) = store->CreateTransaction(Transaction::IMMEDIATE);
    ASSERT_EQ(ret4, E_OK);
    ASSERT_NE(transaction4, nullptr);

    std::tie(ret3, transaction3) = store->CreateTransaction(Transaction::EXCLUSIVE);
    ASSERT_EQ(ret3, E_SQLITE_LOCKED);
    ASSERT_EQ(transaction3, nullptr);
}

/**
*@tc.name: GetMemoryDb_004
*@tc.desc: Get MemoryDb with diff name
*@tc.type: FUNC
*@tc.require:
*@tc.author:
*/
HWTEST_F(RdbMemoryDbTest, GetMemoryDb_004, TestSize.Level1)
{
    int errCode = E_ERROR;
    RdbStoreConfig config(RDB_TEST_PATH);
    config.SetName("mem_test");
    config.SetStorageMode(StorageMode::MODE_MEMORY);
    RdbMemoryDbTestOpenCallback normalCallback;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    config.SetName("eme.db");
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    config.SetName("test123-test");
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(rdbStore, nullptr);

    config.SetName("test%");
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_NE(errCode, E_OK);
    EXPECT_EQ(rdbStore, nullptr);

    config.SetName("test:");
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_NE(errCode, E_OK);
    EXPECT_EQ(rdbStore, nullptr);

    config.SetName("test?");
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_NE(errCode, E_OK);
    EXPECT_EQ(rdbStore, nullptr);

    config.SetName("test$");
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_NE(errCode, E_OK);
    EXPECT_EQ(rdbStore, nullptr);

    config.SetName("test(");
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_NE(errCode, E_OK);
    EXPECT_EQ(rdbStore, nullptr);

    config.SetName("test)");
    rdbStore = RdbHelper::GetRdbStore(config, 1, normalCallback, errCode);
    EXPECT_NE(errCode, E_OK);
    EXPECT_EQ(rdbStore, nullptr);
}