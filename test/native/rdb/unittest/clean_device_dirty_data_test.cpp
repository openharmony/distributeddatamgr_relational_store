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

#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS;

class CleanDeviceDirtyDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string databaseName;

protected:
    std::shared_ptr<RdbStore> store_;
};

const std::string CleanDeviceDirtyDataTest::databaseName = RDB_TEST_PATH + "clean_device_dirty_data_test.db";

class CleanDeviceDirtyDataTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int CleanDeviceDirtyDataTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int CleanDeviceDirtyDataTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void CleanDeviceDirtyDataTest::SetUpTestCase(void)
{
}

void CleanDeviceDirtyDataTest::TearDownTestCase(void)
{
}

void CleanDeviceDirtyDataTest::SetUp(void)
{
    store_ = nullptr;
    int errCode = RdbHelper::DeleteRdbStore(databaseName);
    EXPECT_EQ(E_OK, errCode);
    RdbStoreConfig config(databaseName);
    config.SetAutoCleanDevice(true);
    EXPECT_TRUE(config.GetAutoCleanDevice());
    CleanDeviceDirtyDataTestOpenCallback helper;
    store_ = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store_, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void CleanDeviceDirtyDataTest::TearDown(void)
{
    store_ = nullptr;
    RdbHelper::ClearCache();
    int errCode = RdbHelper::DeleteRdbStore(databaseName);
    EXPECT_EQ(E_OK, errCode);
}

/**
 * @tc.name: CleanDeviceDirtyData_Basic_001
 * @tc.desc: Test CleanDeviceDirtyData with non-distributed table, should return error
 * @tc.type: FUNC
 */
HWTEST_F(CleanDeviceDirtyDataTest, CleanDeviceDirtyData_Basic_001, TestSize.Level1)
{
    // Test with non-distributed table, should return error
    int ret = store_->CleanDeviceDirtyData("non_existent_table", UINT64_MAX);
    EXPECT_NE(E_OK, ret);
}

/**
 * @tc.name: CleanDeviceDirtyData_With_Different_Cursors_001
 * @tc.desc: Test CleanDeviceDirtyData with different cursor values (0, UINT64_MAX, custom value)
 * @tc.type: FUNC
 */
HWTEST_F(CleanDeviceDirtyDataTest, CleanDeviceDirtyData_With_Different_Cursors_001, TestSize.Level1)
{
    // Test with cursor = 0
    int ret1 = store_->CleanDeviceDirtyData("test_table", 0);
    EXPECT_NE(E_OK, ret1);

    // Test with cursor = UINT64_MAX (default)
    int ret2 = store_->CleanDeviceDirtyData("test_table", UINT64_MAX);
    EXPECT_NE(E_OK, ret2);

    // Test with custom cursor value
    int ret3 = store_->CleanDeviceDirtyData("test_table", 12345);
    EXPECT_NE(E_OK, ret3);
}

/**
 * @tc.name: CleanDeviceDirtyData_Empty_Table_Name_001
 * @tc.desc: Test CleanDeviceDirtyData with empty table name
 * @tc.type: FUNC
 */
HWTEST_F(CleanDeviceDirtyDataTest, CleanDeviceDirtyData_Empty_Table_Name_001, TestSize.Level1)
{
    int ret = store_->CleanDeviceDirtyData("", UINT64_MAX);
    EXPECT_EQ(E_INVALID_ARGS, ret);
}

/**
 * @tc.name: AutoCleanDevice_Config_001
 * @tc.desc: Test SetAutoCleanDevice and GetAutoCleanDevice configuration
 * @tc.type: FUNC
 */
HWTEST_F(CleanDeviceDirtyDataTest, AutoCleanDevice_Config_001, TestSize.Level1)
{
    RdbStoreConfig config(databaseName + "_config_test");

    // Test default value
    EXPECT_TRUE(config.GetAutoCleanDevice());

    // Test setting to false
    config.SetAutoCleanDevice(false);
    EXPECT_FALSE(config.GetAutoCleanDevice());

    // Test setting back to true
    config.SetAutoCleanDevice(true);
    EXPECT_TRUE(config.GetAutoCleanDevice());
}