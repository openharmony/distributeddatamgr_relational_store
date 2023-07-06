/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "rdb_types.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;
class SubObserver : public RdbStoreObserver {
public:
    virtual ~SubObserver() {}
    void OnChange(const std::vector<std::string>& devices) override;
};

class RdbStoreSubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string MAIN_DATABASE_NAME;
    static std::shared_ptr<RdbStore> CreateRDB(int version);
    static std::shared_ptr<RdbStore> store;
    static std::shared_ptr<SubObserver> observer_;
};

const std::string RdbStoreSubTest::MAIN_DATABASE_NAME = RDB_TEST_PATH + "subscribe.db";
std::shared_ptr<RdbStore> RdbStoreSubTest::store = nullptr;
std::shared_ptr<SubObserver> RdbStoreSubTest::observer_ = nullptr;

void RdbStoreSubTest::SetUpTestCase(void)
{
    store = CreateRDB(1);
    if (observer_ == nullptr) {
        observer_ = std::make_shared<SubObserver>();
    }
}

void RdbStoreSubTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(MAIN_DATABASE_NAME);
}

void RdbStoreSubTest::SetUp()
{
}

void RdbStoreSubTest::TearDown()
{
}

class Callback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int Callback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int Callback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void SubObserver::OnChange(const std::vector<std::string> &devices)
{
}

std::shared_ptr<RdbStore> RdbStoreSubTest::CreateRDB(int version)
{
    RdbStoreConfig config(RdbStoreSubTest::MAIN_DATABASE_NAME);
    config.SetBundleName("subscribe_test");
    config.SetArea(0);
    config.SetCreateNecessary(true);
    config.SetDistributedType(RDB_DEVICE_COLLABORATION);
    config.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel::S1);
    Callback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, version, helper, errCode);
    EXPECT_NE(store, nullptr);
    return store;
}

/**
 * @tc.name: RdbStoreSubscribeRemote
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeRemote, TestSize.Level1)
{
    EXPECT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::REMOTE }, observer_.get());
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeCloud
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeCloud, TestSize.Level1)
{
    EXPECT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::CLOUD }, observer_.get());
    EXPECT_EQ(status, E_OK);
}

/**
 * @tc.name: RdbStoreSubscribeCloudDetail
 * @tc.desc: RdbStoreSubscribe
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(RdbStoreSubTest, RdbStoreSubscribeCloudDetail, TestSize.Level1)
{
    EXPECT_NE(store, nullptr) << "store is null";
    EXPECT_NE(observer_, nullptr) << "observer is null";
    auto status = store->Subscribe({ SubscribeMode::CLOUD_DETAIL }, observer_.get());
    EXPECT_EQ(status, E_OK);
}
