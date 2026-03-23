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
#include "acl.h"
#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_manager.h"
#include "rdb_platform.h"
#include "sqlite_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DATABASE_UTILS;
constexpr int32_t SERVICE_GID = 3012;

class RdbGetStoreTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void CheckAccess(const std::string &dbPath);

    static const std::string MAIN_DATABASE_NAME;
};

const std::string RdbGetStoreTest::MAIN_DATABASE_NAME = RDB_TEST_PATH + "getrdb.db";

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
}

void RdbGetStoreTest::SetUp(void)
{
}

void RdbGetStoreTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

void RdbGetStoreTest::CheckAccess(const std::string &dbPath)
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

/**
 * @tc.name: RdbStore_GetStore_014
 * @tc.desc: createRDB & setAcl check bundle and db from proxylist
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: zd
 */
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_014, TestSize.Level0)
{
    std::string dbPath = "/data/test/settingsdata.db";
    RdbStoreConfig config(dbPath);
    config.SetBundleName("com.ohos.settingsdata");
    GetOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, -1, helper, errCode);
    EXPECT_NE(store, nullptr);
    RdbGetStoreTest::CheckAccess(dbPath);
    RdbHelper::DeleteRdbStore(dbPath);
}

/**
 * @tc.name: RdbStore_GetStore_015
 * @tc.desc: createRDB & search setAcl
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: zd
 */
HWTEST_F(RdbGetStoreTest, RdbStore_GetStore_015, TestSize.Level0)
{
    RdbStoreConfig config(RdbGetStoreTest::MAIN_DATABASE_NAME);
    config.SetSearchable(true);
    GetOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, -1, helper, errCode);
    EXPECT_NE(store, nullptr);
    RdbGetStoreTest::CheckAccess(std::string(RdbGetStoreTest::MAIN_DATABASE_NAME));
}