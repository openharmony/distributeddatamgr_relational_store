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

#include "rdb_helper.h"

#include <gtest/gtest.h>

#include <string>

#include "rdb_errno.h"
#include "rdb_open_callback.h"
#include "rdb_manager_impl.h"
#include "rdb_store_manager.h"
#include "rdb_store_impl.h"
#include "sqlite_connection.h"
#include "task_executor.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
const std::string RDB_TEST_PATH = "/data/test/";
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

class RdbDynamicLoadTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void InitDb();

    static const std::string rdbStorePath;
    static std::shared_ptr<RdbStore> store;
};
const std::string RdbDynamicLoadTest::rdbStorePath = RDB_TEST_PATH + std::string("rdbhelper.db");
std::shared_ptr<RdbStore> RdbDynamicLoadTest::store = nullptr;

void RdbDynamicLoadTest::SetUpTestCase(void)
{
}

void RdbDynamicLoadTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(rdbStorePath);
}

void RdbDynamicLoadTest::SetUp(void)
{
}

void RdbDynamicLoadTest::TearDown(void)
{
}

class RdbDynamicLoadTestWrongSqlOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string WRONG_SQL_TEST;
};

class RdbDynamicLoadTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

void RdbDynamicLoadTest::InitDb()
{
    int errCode = E_OK;
    RdbStoreConfig config(RdbDynamicLoadTest::rdbStorePath);
    RdbDynamicLoadTestOpenCallback helper;
    RdbDynamicLoadTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(store, nullptr);
}

const std::string RdbDynamicLoadTestWrongSqlOpenCallback::WRONG_SQL_TEST = "CREATE TABL IF NOT EXISTS test "
                                                                      "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                      "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                                      "blobType BLOB)";
const std::string RdbDynamicLoadTestOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                                                 "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                 "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                                 "blobType BLOB)";

int RdbDynamicLoadTestWrongSqlOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(WRONG_SQL_TEST);
}

int RdbDynamicLoadTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int RdbDynamicLoadTestWrongSqlOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

int RdbDynamicLoadTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

/**
 * @tc.name: DynamicLoading001
 * @tc.desc: Dynamic loading test
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, DynamicLoading001, TestSize.Level0)
{
    EXPECT_TRUE(RdbHelper::Init());

    const std::string dbPath = RDB_TEST_PATH + "DynamicLoading.db";
    RdbStoreConfig config(dbPath);
    config.SetBundleName("com.ohos.config.DynamicLoading");
    int errCode = E_ERROR;
    RdbDynamicLoadTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);

    EXPECT_FALSE(RdbStoreManager::GetInstance().storeCache_.empty());
    EXPECT_NE(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().distributedDataMgr_, nullptr);
    EXPECT_NE(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().rdbService_, nullptr);
    EXPECT_NE(TaskExecutor::GetInstance().pool_, nullptr);

    EXPECT_TRUE(RdbHelper::Destroy());

    EXPECT_TRUE(RdbStoreManager::GetInstance().storeCache_.empty());
    EXPECT_EQ(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().distributedDataMgr_, nullptr);
    EXPECT_EQ(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().rdbService_, nullptr);
    EXPECT_EQ(TaskExecutor::GetInstance().pool_, nullptr);
    EXPECT_TRUE(RdbHelper::Init());
    EXPECT_NE(TaskExecutor::GetInstance().pool_, nullptr);
}

/**
 * @tc.name: DynamicLoading002
 * @tc.desc: Dynamic loading test
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, DynamicLoading002, TestSize.Level0)
{
    EXPECT_TRUE(RdbHelper::Init());

    const std::string dbPath = RDB_TEST_PATH + "DynamicLoading.db";
    RdbStoreConfig config(dbPath);
    config.SetBundleName("com.ohos.config.DynamicLoading");
    int errCode = E_ERROR;
    RdbDynamicLoadTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);

    EXPECT_FALSE(RdbStoreManager::GetInstance().storeCache_.empty());
    EXPECT_NE(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().distributedDataMgr_, nullptr);
    EXPECT_NE(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().rdbService_, nullptr);
    EXPECT_NE(TaskExecutor::GetInstance().pool_, nullptr);
    OHOS::NativeRdb::RdbHelper::DestroyOption destroyOption;
    destroyOption.cleanICU = true;
    EXPECT_TRUE(RdbHelper::Destroy(destroyOption));

    EXPECT_TRUE(RdbStoreManager::GetInstance().storeCache_.empty());
    EXPECT_EQ(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().distributedDataMgr_, nullptr);
    EXPECT_EQ(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().rdbService_, nullptr);
    EXPECT_EQ(TaskExecutor::GetInstance().pool_, nullptr);
}

/**
 * @tc.name: GetICUHandle001
 * @tc.desc: Dynamic loading test
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, GetICUHandle001, TestSize.Level0)
{
    auto res = OHOS::NativeRdb::SqliteConnection::ICUCleanUp();
    EXPECT_EQ(res, E_OK);
    auto handle = OHOS::NativeRdb::SqliteConnection::GetICUHandle();
    EXPECT_NE(handle, nullptr);
    res = OHOS::NativeRdb::SqliteConnection::ICUCleanUp();
    EXPECT_EQ(res, E_OK);
}

/**
 * @tc.name: ObsManger001
 * @tc.desc: Dynamic loading test
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, ObsManger001, TestSize.Level0)
{
    auto clean = OHOS::NativeRdb::ObsManger::CleanUp();
    EXPECT_EQ(clean, E_OK);
    auto handle = OHOS::NativeRdb::ObsManger::GetHandle();
    EXPECT_NE(handle, nullptr);
    clean = OHOS::NativeRdb::ObsManger::CleanUp();
    EXPECT_EQ(clean, E_OK);
}

/**
 * @tc.name: ObsManger002
 * @tc.desc: Dynamic loading test
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, ObsManger002, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "DynamicLoading.db";
    RdbStoreConfig config(dbPath);
    config.SetBundleName("com.ohos.config.DynamicLoading");
    int errCode = E_ERROR;
    RdbDynamicLoadTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);
    std::shared_ptr<RdbStoreObserver> observer;
    auto status =
        rdbStore->Subscribe({ OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED, "observer" }, observer);
    EXPECT_EQ(status, E_OK);
    status =
        rdbStore->UnSubscribe({ OHOS::DistributedRdb::SubscribeMode::LOCAL_SHARED, "observer" }, observer);
    EXPECT_EQ(status, E_OK);
}