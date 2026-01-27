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
#include "rdb_platform.h"
#include "sqlite_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
static constexpr const char *MAIN_DATABASE_NAME = "/data/test/bmsdb.db";
static constexpr const char *CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test1(id INTEGER PRIMARY KEY "
                                                       "AUTOINCREMENT, name TEXT NOT NULL, age INTEGER)";
class FoundationStoreTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};


class GetOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int GetOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int GetOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    (void) oldVersion;
    (void) newVersion;
    return E_OK;
}

void FoundationStoreTest::SetUpTestCase(void)
{
}

void FoundationStoreTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
}

void FoundationStoreTest::SetUp(void)
{
}

void FoundationStoreTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

/**
 * @tc.name: RdbStore_GetStore_001
 * @tc.desc: create foundation db
 * @tc.type: FUNC
 * @tc.require: issue
 * @tc.author: lcl
 */
HWTEST_F(FoundationStoreTest, RdbStore_GetStore_001, TestSize.Level1)
{
    RdbStoreConfig config(MAIN_DATABASE_NAME);
    GetOpenCallback helper;
    int errCode = E_OK;
    int currentVersion = 1;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, currentVersion, helper, errCode);
    EXPECT_NE(store, nullptr);
    int ret = store->ExecuteSql(CREATE_TABLE_TEST);
    EXPECT_EQ(ret, E_OK);

    int64_t id;
    ValuesBucket values;
    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 18);
    ret = store->Insert(id, "test1", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    int changedRows;
    values.Clear();
    values.PutInt("age", 21);
    ret = store->Update(changedRows, "test1", values, "age = ?", std::vector<std::string>{ "18" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);

    ret = store->Delete(changedRows, "test1", "age = ?", std::vector<std::string>{ "21" });
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, changedRows);
}