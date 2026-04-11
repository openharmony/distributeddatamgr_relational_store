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
#include "grd_api_manager.h"
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
    ASSERT_NE(store_, nullptr);
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
 * @tc.name: CleanDeviceDirtyData_Error_Cases_001
 * @tc.desc: Test CleanDeviceDirtyData with various error scenarios
 * @tc.type: FUNC
 */
HWTEST_F(CleanDeviceDirtyDataTest, CleanDeviceDirtyData_Error_Cases_001, TestSize.Level1)
{
    // Test with non-distributed table, should return error
    int ret = store_->CleanDeviceDirtyData("non_existent_table", UINT64_MAX);
    EXPECT_EQ(ret, E_SQLITE_ERROR);

    // Test with empty table name, should return invalid args error
    ret = store_->CleanDeviceDirtyData("", UINT64_MAX);
    EXPECT_EQ(ret, E_INVALID_ARGS);

    ret = RdbHelper::DeleteRdbStore(databaseName);
    EXPECT_EQ(ret, E_OK);

    uint64_t cursor = UINT64_MAX;
    ret = store_->CleanDirtyData("test", cursor);
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
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

/**
 * @tc.name: CleanDeviceDirtyData_ReadOnly_Database_001
 * @tc.desc: Test CleanDeviceDirtyData with read-only database, should return E_NOT_SUPPORT
 * @tc.type: FUNC
 */
HWTEST_F(CleanDeviceDirtyDataTest, CleanDeviceDirtyData_ReadOnly_Database_001, TestSize.Level1)
{
    // Create a read-only database
    std::string readOnlyDbName = RDB_TEST_PATH + "readonly_test.db";
    int errCode = RdbHelper::DeleteRdbStore(readOnlyDbName);
    EXPECT_EQ(E_OK, errCode);

    // First create a normal database
    RdbStoreConfig normalConfig(readOnlyDbName);
    CleanDeviceDirtyDataTestOpenCallback helper;
    std::shared_ptr<RdbStore> normalStore = RdbHelper::GetRdbStore(normalConfig, 1, helper, errCode);
    EXPECT_NE(normalStore, nullptr);
    EXPECT_EQ(errCode, E_OK);
    normalStore = nullptr;
    RdbHelper::ClearCache();

    // Then open it as read-only
    RdbStoreConfig readOnlyConfig(readOnlyDbName, StorageMode::MODE_DISK, true);
    std::shared_ptr<RdbStore> readOnlyStore = RdbHelper::GetRdbStore(readOnlyConfig, 1, helper, errCode);
    ASSERT_NE(readOnlyStore, nullptr);
    EXPECT_EQ(errCode, E_OK);

    // Test CleanDeviceDirtyData on read-only database
    int ret = readOnlyStore->CleanDeviceDirtyData("test_table", UINT64_MAX);
    EXPECT_EQ(ret, E_NOT_SUPPORT);

    // Cleanup
    readOnlyStore = nullptr;
    RdbHelper::ClearCache();
    errCode = RdbHelper::DeleteRdbStore(readOnlyDbName);
    EXPECT_EQ(errCode, E_OK);
}

/**
 * @tc.name: CleanDeviceDirtyData_Memory_Database_001
 * @tc.desc: Test CleanDeviceDirtyData with memory database, should return E_NOT_SUPPORT
 * @tc.type: FUNC
 */
HWTEST_F(CleanDeviceDirtyDataTest, CleanDeviceDirtyData_Memory_Database_001, TestSize.Level1)
{
    // Create a memory database
    std::string memoryDbName = RDB_TEST_PATH + "memory.db";
    RdbStoreConfig memoryConfig(memoryDbName, StorageMode::MODE_MEMORY);

    CleanDeviceDirtyDataTestOpenCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> memoryStore = RdbHelper::GetRdbStore(memoryConfig, 1, helper, errCode);
    ASSERT_NE(memoryStore, nullptr);
    EXPECT_EQ(errCode, E_OK);

    // Test CleanDeviceDirtyData on memory database
    int ret = memoryStore->CleanDeviceDirtyData("test_table", UINT64_MAX);
    EXPECT_EQ(ret, E_NOT_SUPPORT);

    // Cleanup
    memoryStore = nullptr;
    RdbHelper::ClearCache();
}

/**
 * @tc.name: CleanDeviceDirtyData_Vector_Database_001
 * @tc.desc: Test CleanDeviceDirtyData with vector database type, should return E_NOT_SUPPORT
 * @tc.type: FUNC
 */
HWTEST_F(CleanDeviceDirtyDataTest, CleanDeviceDirtyData_Vector_Database_001, TestSize.Level1)
{
    if (!IsUsingArkData()) {
        GTEST_SKIP() << "Current testcase is not compatible from current rdb";
    }
    // Create a database with vector type
    std::string vectorDbName = RDB_TEST_PATH + "vector_test.db";
    int errCode = RdbHelper::DeleteRdbStore(vectorDbName);
    EXPECT_EQ(errCode, E_OK);

    RdbStoreConfig vectorConfig(vectorDbName);
    vectorConfig.SetDBType(DB_VECTOR);
    vectorConfig.SetAutoCleanDevice(true);

    CleanDeviceDirtyDataTestOpenCallback helper;
    std::shared_ptr<RdbStore> vectorStore = RdbHelper::GetRdbStore(vectorConfig, 1, helper, errCode);
    ASSERT_NE(vectorStore, nullptr);
    EXPECT_EQ(errCode, E_OK);
    int ret = vectorStore->CleanDeviceDirtyData("test_table", UINT64_MAX);
    EXPECT_EQ(ret, E_NOT_SUPPORT);
    vectorStore = nullptr;

    errCode = RdbHelper::DeleteRdbStore(vectorDbName);
    EXPECT_EQ(errCode, E_OK);
}