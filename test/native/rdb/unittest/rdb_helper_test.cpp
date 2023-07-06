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
    static const std::string rdbStorePath;
};
const std::string RdbHelperTest::rdbStorePath = RDB_TEST_PATH + std::string("rdbhelper.db");

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

class RdbHelperTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

const std::string RdbHelperTestOpenCallback::CREATE_TABLE_TEST = "CREATE TABL IF NOT EXISTS test "
                                                                 "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                 "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                                 "blobType BLOB)";

int RdbHelperTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
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
    RdbHelperTestOpenCallback helper;
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
    int ret = RdbHelper::DeleteRdbStore("test");
    EXPECT_EQ(ret, E_OK);
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
