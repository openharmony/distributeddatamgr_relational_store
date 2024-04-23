/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "rdb_store_manager.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbGetStoreTest : public testing::Test {
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

const std::string RdbGetStoreTest::MAIN_DATABASE_NAME = RDB_TEST_PATH + "getrdb.db";
const std::string RdbGetStoreTest::MAIN_DATABASE_NAME_RELEASE = RDB_TEST_PATH + "releaserdb.db";
const std::string RdbGetStoreTest::MAIN_DATABASE_NAME_STATUS = RDB_TEST_PATH + "status.db";
const std::string RdbGetStoreTest::MAIN_DATABASE_NAME_MINUS = RDB_TEST_PATH + "minus.db";

class GetOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

std::string const GetOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test1(id INTEGER PRIMARY KEY "
                                                       "AUTOINCREMENT, name TEXT NOT NULL, age INTEGER)";

int GetOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int GetOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbGetStoreTest::SetUpTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
}

void RdbGetStoreTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME_RELEASE);
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME_STATUS);
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME_MINUS);
}

void RdbGetStoreTest::SetUp(void)
{
}

void RdbGetStoreTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

void RdbGetStoreTest::CreateRDB(int version)
{
    RdbStoreConfig config(RdbGetStoreTest::MAIN_DATABASE_NAME_RELEASE);
    GetOpenCallback helper;
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

void RdbGetStoreTest::QueryCheck1(std::shared_ptr<RdbStore> &store) const
{
    int ret;
    int64_t id;
    ValuesBucket values;
    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 18);
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

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

void RdbGetStoreTest::QueryCheck2(std::shared_ptr<RdbStore> &store) const
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
    EXPECT_EQ(intVal, 18);

    ValuesBucket values;
    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 18);
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
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_001, TestSize.Level1)
{
    CreateRDB(1);
    sleep(1);
}

/**
 * @tc.name: RdbStore_GetStore_001
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_00101, TestSize.Level1)
{
    RdbStoreConfig config(RdbGetStoreTest::MAIN_DATABASE_NAME_STATUS);
    GetOpenCallback helper;
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
 * @tc.name: RdbStore_GetStore_001
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_00102, TestSize.Level1)
{
    RdbStoreConfig config(RdbGetStoreTest::MAIN_DATABASE_NAME_MINUS);
    GetOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, -1, helper, errCode);
    EXPECT_NE(store, nullptr);
    int currentVersion;
    int ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentVersion, 0);
    sleep(1);
}

std::shared_ptr<RdbStore> RdbGetStoreTest::CreateGetRDB(int version)
{
    RdbStoreConfig config(RdbGetStoreTest::MAIN_DATABASE_NAME);
    GetOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, version, helper, errCode);
    EXPECT_NE(store, nullptr);
    return store;
}

/**
 * @tc.name: RdbStore_GetStore_002
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_002, TestSize.Level1)
{
    std::shared_ptr<RdbStore> store1 = CreateGetRDB(1);

    std::shared_ptr<RdbStore> store = CreateGetRDB(2);

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
    values.PutInt("id", 3);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 18);
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    values.Clear();
    values.PutInt("id", 4);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(4, id);

    values.Clear();
    values.PutInt("id", 5);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 19);
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(5, id);

    std::shared_ptr<ResultSet> resultSet = store1->QuerySql("select * from test1");
    ret = resultSet->GetRowCount(rowCount);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, rowCount);

    values.Clear();
    values.PutInt("age", 21);
    ret = store->Update(changedRows, "test1", values, "age = ?", std::vector<std::string>{ "18" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    ret = store1->Delete(changedRows, "test1", "age = ?", std::vector<std::string>{ "21" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);
}

/**
 * @tc.name: RdbStore_GetStore_003
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_003, TestSize.Level1)
{
    sleep(1);
    CreateRDB(2);
}

/**
 * @tc.name: RdbStore_GetStore_001
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_00103, TestSize.Level1)
{
    RdbStoreConfig config(RdbGetStoreTest::MAIN_DATABASE_NAME_STATUS);
    GetOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 2, helper, errCode);
    EXPECT_NE(store, nullptr);
    int currentVersion;
    int ret = store->GetVersion(currentVersion);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(currentVersion, 2);
    sleep(1);
}

/**
 * @tc.name: RdbStore_GetStore_001
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_00104, TestSize.Level1)
{
    RdbStoreConfig config(RdbGetStoreTest::MAIN_DATABASE_NAME_MINUS);
    GetOpenCallback helper;
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
 * @tc.name: RdbStore_GetStore_001
 * @tc.desc: createRDB
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_00106, TestSize.Level1)
{
    RdbStoreConfig config(RdbGetStoreTest::MAIN_DATABASE_NAME_MINUS);
    config.SetCustomDir("SetCustomDirTest/");
    GetOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}
