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
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class GetRdbStatusTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

const std::string GetRdbStatusTest::DATABASE_NAME = RDB_TEST_PATH + "get_status_test.db";
std::shared_ptr<RdbStore> GetRdbStatusTest::store = nullptr;

class StatusTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    int OnOpen(RdbStore &rdbStore) override;
    static const std::string CREATE_TABLE_TEST;
};


const std::string StatusTestOpenCallback::CREATE_TABLE_TEST = std::string("CREATE TABLE IF NOT EXISTS test ") +
                                                              std::string("(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                          "name TEXT NOT NULL, age INTEGER, salary "
                                                                          "REAL, blobType BLOB)");

int StatusTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int StatusTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int StatusTestOpenCallback::OnOpen(RdbStore &store)
{
    return E_OK;
}

void GetRdbStatusTest::SetUpTestCase(void)
{
}

void GetRdbStatusTest::TearDownTestCase(void)
{
}

void GetRdbStatusTest::SetUp(void)
{
}

void GetRdbStatusTest::TearDown(void)
{
}

/**
 * @tc.name: Get_RdbStore_Status_001
 * @tc.desc: Obtains the RdbStore status when get RdbStore.
 * @tc.type: FUNC
 */
HWTEST_F(GetRdbStatusTest, Get_RdbStore_Status_001, TestSize.Level1)
{
    RdbStoreConfig config(GetRdbStatusTest::DATABASE_NAME);

    int errCode = E_OK;
    StatusTestOpenCallback helper;
    GetRdbStatusTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(GetRdbStatusTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);

    EXPECT_EQ(GetRdbStatusTest::store->GetStatus(), static_cast<int>(OpenStatus::ON_CREATE));
    EXPECT_EQ(RdbHelper::DeleteRdbStore(GetRdbStatusTest::DATABASE_NAME), E_OK);
}

/**
 * @tc.name: Get_RdbStore_Status_002
 * @tc.desc: Obtains the RdbStore status when get RdbStore.
 * @tc.type: FUNC
 */
HWTEST_F(GetRdbStatusTest, Get_RdbStore_Status_002, TestSize.Level1)
{
    RdbStoreConfig config(GetRdbStatusTest::DATABASE_NAME);

    int errCode = E_OK;
    StatusTestOpenCallback helper;
    GetRdbStatusTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(GetRdbStatusTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);

    RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(GetRdbStatusTest::store->GetStatus(), static_cast<int>(OpenStatus::ON_CREATE));
    EXPECT_EQ(RdbHelper::DeleteRdbStore(GetRdbStatusTest::DATABASE_NAME), E_OK);
}
