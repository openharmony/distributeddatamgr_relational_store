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

#include <gtest/gtest.h>

#include <string>
#include "rdb_test_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_platform.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

// Database version constants
constexpr int DATABASE_VERSION_UPGRADED = 2;

// Test data ID constants
constexpr int TEST_ID_3 = 3;
constexpr int TEST_ID_4 = 4;
constexpr int TEST_ID_5 = 5;

// Test data age constants
constexpr int ROW_COUNT_THREE = 3;
constexpr int TEST_AGE_18 = 18;
constexpr int TEST_AGE_19 = 19;
constexpr int TEST_AGE_20 = 20;
constexpr int TEST_AGE_21 = 21;

class RdbInterfaceGetStoreTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void QueryCheck1(std::shared_ptr<RdbStore> &store) const;
    void QueryCheck2(std::shared_ptr<RdbStore> &store) const;

    static const std::string MAIN_DATABASE_NAME;
    static const std::string MAIN_DATABASE_NAME_RELEASE;
    static const std::string MAIN_DATABASE_NAME_STATUS;
    static const std::string MAIN_DATABASE_NAME_MINUS;
    std::shared_ptr<RdbStore> CreateGetRDB(int version);
    void CreateRDB(int version);
};

const std::string RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME = RDB_TEST_PATH + "getrdb.db";
const std::string RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME_RELEASE = RDB_TEST_PATH + "releaserdb.db";
const std::string RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME_STATUS = RDB_TEST_PATH + "status.db";
const std::string RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME_MINUS = RDB_TEST_PATH + "minus.db";

class GetRdbOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const GetRdbOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test1(id INTEGER PRIMARY KEY "
                                                       "AUTOINCREMENT, name TEXT NOT NULL, age INTEGER)";

int GetRdbOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int GetRdbOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbInterfaceGetStoreTest::SetUpTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
}

void RdbInterfaceGetStoreTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME_RELEASE);
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME_STATUS);
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME_MINUS);
}

void RdbInterfaceGetStoreTest::SetUp(void)
{
}

void RdbInterfaceGetStoreTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

void RdbInterfaceGetStoreTest::CreateRDB(int version)
{
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME_RELEASE);
    GetRdbOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, version, helper, errCode);
    EXPECT_NE(store, nullptr);
    int currentVersion;
    int ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentVersion, version);

    ret = store->ExecuteSql("CREATE TABLE IF NOT EXISTS test2(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                            "name TEXT NOT NULL, age INTEGER)");
    EXPECT_EQ(ret, E_OK);
    ret = store->ExecuteSql("delete from test1");
    EXPECT_EQ(ret, E_OK);
    ret = store->ExecuteSql("delete from test2");
    EXPECT_EQ(ret, E_OK);
    QueryCheck1(store);
    QueryCheck2(store);
}

void RdbInterfaceGetStoreTest::QueryCheck1(std::shared_ptr<RdbStore> &store) const
{
    int ret;
    int64_t id;
    ValuesBucket values;
    values.Clear();
    values.PutInt("id", TEST_ID_3);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", TEST_AGE_18);
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(TEST_ID_3, id);

    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test1");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    int columnIndex;
    std::string strVal;
    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(strVal, "lisi");
}

void RdbInterfaceGetStoreTest::QueryCheck2(std::shared_ptr<RdbStore> &store) const
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELECT * FROM test1");
    EXPECT_NE(resultSet, nullptr);
    int ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    int columnIndex;
    int intVal;
    int64_t id;
    std::string strVal;

    ret = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(intVal, TEST_AGE_18);

    ValuesBucket values;
    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", TEST_AGE_18);
    ret = store->Insert(id, "test2", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    resultSet = store->QuerySql("SELECT * FROM test2");
    EXPECT_NE(resultSet, nullptr);
    ret = resultSet->GoToNextRow();
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetInt(columnIndex, intVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(intVal, 1);
    ret = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(ret, E_OK);
    ret = resultSet->GetString(columnIndex, strVal);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(strVal, "lisi");
}

/**
 * @tc.name: RdbStore_GetStore_001
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_001, TestSize.Level1)
{
    CreateRDB(1);
    sleep(1);
}

/**
 * @tc.name: RdbStore_GetStore_002
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_002, TestSize.Level1)
{
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME_STATUS);
    GetRdbOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
    int currentVersion;
    int ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentVersion, 1);
    sleep(1);
}

/**
 * @tc.name: RdbStore_GetStore_003
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_003, TestSize.Level1)
{
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME_MINUS);
    GetRdbOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, -1, helper, errCode);
    EXPECT_NE(store, nullptr);
    int currentVersion;
    int ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentVersion, 0);
    sleep(1);
}

std::shared_ptr<RdbStore> RdbInterfaceGetStoreTest::CreateGetRDB(int version)
{
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME);
    GetRdbOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, version, helper, errCode);
    EXPECT_NE(store, nullptr);
    return store;
}

/**
 * @tc.name: RdbStore_GetStore_004
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_004, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store1 = CreateGetRDB(1);

    std::shared_ptr<RdbStore> store = CreateGetRDB(DATABASE_VERSION_UPGRADED);

    int currentVersion;
    int64_t id;
    int changedRows;
    ValuesBucket values;
    int rowCount;

    int ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentVersion, 1);

    ret = store1->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentVersion, 1);

    ret = store->ExecuteSql("delete from test1");
    EXPECT_EQ(ret, E_OK);

    values.Clear();
    values.PutInt("id", TEST_ID_3);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", TEST_AGE_18);
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(TEST_ID_3, id);

    values.Clear();
    values.PutInt("id", TEST_ID_4);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", TEST_AGE_20);
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(TEST_ID_4, id);

    values.Clear();
    values.PutInt("id", TEST_ID_5);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", TEST_AGE_19);
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(TEST_ID_5, id);

    std::shared_ptr<ResultSet> resultSet = store1->QuerySql("select * from test1");
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(ROW_COUNT_THREE, rowCount);

    values.Clear();
    values.PutInt("age", TEST_AGE_21);
    ret = store->Update(changedRows, "test1", values, "age = ?", std::vector<std::string>{ "18" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    ret = store1->Delete(changedRows, "test1", "age = ?", std::vector<std::string>{ "21" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);
}

/**
 * @tc.name: RdbStore_GetStore_005
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_005, TestSize.Level1)
{
    sleep(1);
    CreateRDB(DATABASE_VERSION_UPGRADED);
}

/**
 * @tc.name: RdbStore_GetStore_006
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_006, TestSize.Level1)
{
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME_STATUS);
    GetRdbOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, DATABASE_VERSION_UPGRADED, helper, errCode);
    EXPECT_NE(store, nullptr);
    int currentVersion;
    int ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentVersion, DATABASE_VERSION_UPGRADED);
    sleep(1);
}

/**
 * @tc.name: RdbStore_GetStore_007
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_007, TestSize.Level1)
{
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME_MINUS);
    GetRdbOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, -1, helper, errCode);
    EXPECT_NE(store, nullptr);
    int currentVersion;
    int ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentVersion, 0);
    sleep(1);
}

/**
 * @tc.name: RdbStore_GetStore_008
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_008, TestSize.Level1)
{
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME_MINUS);
    config.SetCustomDir("SetCustomDirTest/");
    GetRdbOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStore_GetStore_009
 * @tc.desc: get database with quick_check
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterfaceGetStoreTest, GetDatabase_009, TestSize.Level0)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME);
    config.SetIntegrityCheck(IntegrityCheck::QUICK);
    GetRdbOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStore_GetStore_010
 * @tc.desc: get database with quick_check
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_010, TestSize.Level0)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME);
    config.SetIntegrityCheck(IntegrityCheck::FULL);
    GetRdbOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStore_GetStore_011
 * @tc.desc: use libs as relative path to get rdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_011, TestSize.Level0)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME);
    std::vector<std::string> paths = { "./" };
    config.SetPluginLibs(paths);
    GetRdbOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_SQLITE_ERROR);
    EXPECT_EQ(store, nullptr);
}

/**
 * @tc.name: RdbStore_GetStore_012
 * @tc.desc: use libs as empty path to get rdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_012, TestSize.Level0)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME);
    std::vector<std::string> paths = { "", "" };
    config.SetPluginLibs(paths);
    GetRdbOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_NE(store, nullptr);
}

/**
 * @tc.name: RdbStore_GetStore_013
 * @tc.desc: use libs as invalid path to get rdbStore
 * @tc.type: FUNC
 */
HWTEST_F(RdbInterfaceGetStoreTest, RdbStore_GetStore_013, TestSize.Level0)
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbInterfaceGetStoreTest::MAIN_DATABASE_NAME);
    std::vector<std::string> paths = { "", "/data/errPath/libErr.so" };
    config.SetPluginLibs(paths);
    GetRdbOpenCallback helper;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_INVALID_FILE_PATH);
    EXPECT_EQ(store, nullptr);
}