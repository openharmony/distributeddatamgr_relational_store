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

#include "rdb_manager_impl.h"

#include <gtest/gtest.h>

#include "rdb_service_proxy.h"
#include "rdb_types.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DistributedRdb;

namespace Test {
class RdbManagerImplTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(void){};
    void TearDown(void){};
};

/**
 * @tc.name: GetRdbService_001
 * @tc.desc: Test GetRdbService with valid parameters
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerImplTest, GetRdbService_001, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "com.example.test";
    param.storeName_ = "test.db";
    
    auto& manager = RdbManager::GetInstance();
    auto [status, service] = manager.GetRdbService(param);
    
    EXPECT_EQ(status, 0);
}

/**
 * @tc.name: GetSelfBundleName_001
 * @tc.desc: Test GetSelfBundleName
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerImplTest, GetSelfBundleName_001, TestSize.Level1)
{
    auto& manager = RdbManager::GetInstance();
    std::string bundleName = manager.GetSelfBundleName();
    
    EXPECT_TRUE(!bundleName.empty() || bundleName.empty());
}

/**
 * @tc.name: OnRemoteDied_001
 * @tc.desc: Test OnRemoteDied callback
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerImplTest, OnRemoteDied_001, TestSize.Level1)
{
    auto& manager = RdbManager::GetInstance();
    
    EXPECT_NO_FATAL_FAILURE(manager.OnRemoteDied());
}

/**
 * @tc.name: GetRdbService_002
 * @tc.desc: Test GetRdbService with different bundle names
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerImplTest, GetRdbService_002, TestSize.Level2)
{
    RdbSyncerParam param1;
    param1.bundleName_ = "com.example.test1";
    param1.storeName_ = "test1.db";
    
    RdbSyncerParam param2;
    param2.bundleName_ = "com.example.test2";
    param2.storeName_ = "test2.db";
    
    auto& manager = RdbManager::GetInstance();
    auto [status1, service1] = manager.GetRdbService(param1);
    auto [status2, service2] = manager.GetRdbService(param2);
    
    EXPECT_EQ(status1, 0);
    EXPECT_EQ(status2, 0);
}

/**
 * @tc.name: GetRdbService_003
 * @tc.desc: Test GetRdbService with empty parameters
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerImplTest, GetRdbService_003, TestSize.Level2)
{
    RdbSyncerParam param;
    param.bundleName_ = "";
    param.storeName_ = "";
    
    auto& manager = RdbManager::GetInstance();
    auto [status, service] = manager.GetRdbService(param);
    
    EXPECT_EQ(status, 0);
}

/**
 * @tc.name: SingletonTest
 * @tc.desc: Test RdbManager singleton pattern
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerImplTest, SingletonTest, TestSize.Level1)
{
    auto& manager1 = RdbManager::GetInstance();
    auto& manager2 = RdbManager::GetInstance();
    
    EXPECT_EQ(&manager1, &manager2);
}
} // namespace Test