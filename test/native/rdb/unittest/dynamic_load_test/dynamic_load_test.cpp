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

#include "block_data.h"
#include "global_resource.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_manager_impl.h"
#include "rdb_open_callback.h"
#include "rdb_store_impl.h"
#include "rdb_store_manager.h"
#include "sqlite_connection.h"
#include "task_executor.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
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
};

void RdbDynamicLoadTest::SetUpTestCase(void)
{
}

void RdbDynamicLoadTest::TearDownTestCase(void)
{
}

void RdbDynamicLoadTest::SetUp(void)
{
}

void RdbDynamicLoadTest::TearDown(void)
{
}

class RdbDynamicLoadTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};
const std::string RdbDynamicLoadTestOpenCallback::CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                                                      "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                                      "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                                                      "blobType BLOB)";

int RdbDynamicLoadTestOpenCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
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
    rdbStore = nullptr;
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
    rdbStore = nullptr;
    EXPECT_TRUE(RdbHelper::Destroy(destroyOption));

    EXPECT_TRUE(RdbStoreManager::GetInstance().storeCache_.empty());
    EXPECT_EQ(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().distributedDataMgr_, nullptr);
    EXPECT_EQ(OHOS::DistributedRdb::RdbManagerImpl::GetInstance().rdbService_, nullptr);
    EXPECT_EQ(TaskExecutor::GetInstance().pool_, nullptr);
}

/**
 * @tc.name: ObsManger001
 * @tc.desc: Destroy when the subscription is not cancelled
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, ObsManger001, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "ObsManger001.db";
    RdbStoreConfig config(dbPath);
    config.SetBundleName("com.ohos.config.DynamicLoading");
    int errCode = E_ERROR;
    RdbDynamicLoadTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);
    std::shared_ptr<const char> autoRelease =
        std::shared_ptr<const char>("ObsManger001", [config](const char *) { RdbHelper::DeleteRdbStore(config); });
    std::shared_ptr<RdbStoreObserver> observer;
    auto status = rdbStore->Subscribe({ SubscribeMode::LOCAL_SHARED, "observer" }, observer);
    EXPECT_EQ(status, E_OK);
    ASSERT_NO_FATAL_FAILURE(EXPECT_TRUE(RdbHelper::Destroy()));
    auto rdbStoreNew = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(rdbStore, rdbStoreNew);
}

/**
 * @tc.name: ObsManger002
 * @tc.desc: Destroy after the database is closed
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, ObsManger002, TestSize.Level0)
{
    const std::string dbPath = RDB_TEST_PATH + "ObsManger002.db";
    RdbStoreConfig config(dbPath);
    config.SetBundleName("com.ohos.config.DynamicLoading");
    int errCode = E_ERROR;
    RdbDynamicLoadTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);
    std::shared_ptr<const char> autoRelease =
        std::shared_ptr<const char>("ObsManger002", [config](const char *) { RdbHelper::DeleteRdbStore(config); });
    std::shared_ptr<RdbStoreObserver> observer;
    auto status = rdbStore->Subscribe({ SubscribeMode::LOCAL_SHARED, "observer" }, observer);
    EXPECT_EQ(status, E_OK);
    rdbStore = nullptr;
    ASSERT_NO_FATAL_FAILURE(EXPECT_TRUE(RdbHelper::Destroy()));
}

/**
 * @tc.name: ICUManager001
 * @tc.desc: Destroy ICU
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, ICUManager001, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "ICUManager001.db";
    RdbStoreConfig config(dbPath);
    config.SetBundleName("com.ohos.config.DynamicLoading");
    int errCode = E_ERROR;
    RdbDynamicLoadTestOpenCallback helper;
    config.SetCollatorLocales("zh_CN");
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);
    std::shared_ptr<const char> autoRelease =
        std::shared_ptr<const char>("ICUManager001", [config](const char *) { RdbHelper::DeleteRdbStore(config); });
    rdbStore->ExecuteSql("CREATE TABLE ICUManager (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, "
                         "data2 INTEGER);");
    int64_t id;
    ValuesBucket valuesBucket;
    valuesBucket.PutString("data1", "张三");
    valuesBucket.PutInt("data2", 20);
    errCode = rdbStore->Insert(id, "ICUManager", valuesBucket);
    EXPECT_EQ(errCode, E_OK);
    rdbStore = nullptr;
    RdbHelper::DestroyOption option;
    option.cleanICU = true;
    ASSERT_NO_FATAL_FAILURE(EXPECT_TRUE(RdbHelper::Destroy(option)));
}

using CheckOnChangeFunc = std::function<void(RdbStoreObserver::ChangeInfo &changeInfo)>;
class SubObserver : public RdbStoreObserver {
public:
    virtual ~SubObserver()
    {
    }
    void OnChange(const std::vector<std::string> &devices) override
    {
    }
    void OnChange(const Origin &origin, const PrimaryFields &fields, RdbStoreObserver::ChangeInfo &&info) override;
    void OnChange() override
    {
    }
    void RegisterCallback(const CheckOnChangeFunc &callback);

private:
    CheckOnChangeFunc checkOnChangeFunc_;
};

void SubObserver::OnChange(const Origin &origin, const PrimaryFields &fields, RdbStoreObserver::ChangeInfo &&info)
{
    if (checkOnChangeFunc_) {
        checkOnChangeFunc_(info);
    }
}

void SubObserver::RegisterCallback(const CheckOnChangeFunc &callback)
{
    checkOnChangeFunc_ = callback;
}

/**
 * @tc.name: DbClient001
 * @tc.desc: Destroy DbClient
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, DbClient001, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "DbClient001.db";
    RdbStoreConfig config(dbPath);
    config.SetBundleName("com.ohos.config.DynamicLoading");
    int errCode = E_ERROR;
    RdbDynamicLoadTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);
    std::shared_ptr<const char> autoRelease =
        std::shared_ptr<const char>("DbClient001", [config](const char *) { RdbHelper::DeleteRdbStore(config); });
    auto obs = std::make_shared<SubObserver>();
    auto flag = std::make_shared<OHOS::BlockData<bool>>(false, 3);
    obs->RegisterCallback([flag](RdbStoreObserver::ChangeInfo &changeInfo) {
        flag->SetValue(true);
        return;
    });
    errCode = rdbStore->Subscribe({ SubscribeMode::LOCAL_DETAIL }, obs);
    EXPECT_EQ(errCode, E_OK);
    int64_t id;
    ValuesBucket valuesBucket;
    valuesBucket.PutString("name", "bob");
    valuesBucket.PutInt("age", 20);
    errCode = rdbStore->Insert(id, "test", valuesBucket);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(flag->GetValue(), true);
    rdbStore = nullptr;
    ASSERT_NO_FATAL_FAILURE(EXPECT_TRUE(RdbHelper::Destroy()));
}

/**
 * @tc.name: OpenSSL001
 * @tc.desc: Destroy OpenSSL
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, OpenSSL001, TestSize.Level1)
{
    const std::string dbPath = RDB_TEST_PATH + "OpenSSL001.db";
    RdbStoreConfig config(dbPath);
    config.SetBundleName("com.ohos.config.DynamicLoading");
    config.SetEncryptStatus(true);
    int errCode = E_ERROR;
    RdbDynamicLoadTestOpenCallback helper;
    std::shared_ptr<RdbStore> rdbStore = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(rdbStore, nullptr);
    std::shared_ptr<const char> autoRelease =
        std::shared_ptr<const char>("OpenSSL001", [config](const char *) { RdbHelper::DeleteRdbStore(config); });
    int64_t id;
    ValuesBucket valuesBucket;
    valuesBucket.PutString("name", "bob");
    valuesBucket.PutInt("age", 20);
    errCode = rdbStore->Insert(id, "test", valuesBucket);
    EXPECT_EQ(errCode, E_OK);
    rdbStore = nullptr;
    RdbHelper::DestroyOption option;
    option.cleanOpenSSL = true;
    ASSERT_NO_FATAL_FAILURE(EXPECT_TRUE(RdbHelper::Destroy(option)));
}

/**
 * @tc.name: GlobalResource001
 * @tc.desc: GlobalResource CleanUp invalid args
 * @tc.type: FUNC
 */
HWTEST_F(RdbDynamicLoadTest, GlobalResource001, TestSize.Level0)
{
    EXPECT_EQ(GlobalResource::CleanUp(-1), E_INVALID_ARGS);
    EXPECT_EQ(GlobalResource::CleanUp(GlobalResource::CLEAN_BUTT), E_INVALID_ARGS);
}