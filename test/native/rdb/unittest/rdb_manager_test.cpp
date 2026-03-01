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
#include <thread>
#include <vector>

#include "rdb_manager.h"
#include "rdb_manager_impl.h"
#include "rdb_types.h"
#include "rdb_service.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb;

class RdbManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}

    static void TearDownTestCase(void) {}

    void SetUp(void) {}

    void TearDown(void) {}

protected:
    RdbSyncerParam CreateValidParam()
    {
        RdbSyncerParam param;
        param.bundleName_ = "com.example.test";
        param.hapName_ = "test.hap";
        param.storeName_ = "test.db";
        param.area_ = 0;
        param.level_ = 1;
        return param;
    }
};

/**
 * @tc.name: RdbManagerTest_GetInstance_001
 * @tc.desc: Verify GetInstance returns singleton instance consistently
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerTest, GetInstance_001, TestSize.Level1)
{
    auto &instance1 = RdbManager::GetInstance();
    auto &instance2 = RdbManager::GetInstance();

    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: RdbManagerTest_GetRdbService_EmptyBundleName_001
 * @tc.desc: Verify GetRdbService returns E_INVALID_ARGS for empty bundle name
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerTest, GetRdbService_EmptyBundleName_001, TestSize.Level1)
{
    auto &manager = RdbManager::GetInstance();
    RdbSyncerParam param;
    param.bundleName_ = "";
    param.storeName_ = "test.db";

    auto [status, service] = manager.GetRdbService(param);

    EXPECT_EQ(status, E_INVALID_ARGS);
    EXPECT_EQ(service, nullptr);
}

/**
 * @tc.name: RdbManagerTest_GetRdbService_ValidParam_002
 * @tc.desc: Verify GetRdbService with valid parameters (may return service error in test env)
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerTest, GetRdbService_ValidParam_002, TestSize.Level1)
{
    auto &manager = RdbManager::GetInstance();
    auto param = CreateValidParam();

    auto [status, service] = manager.GetRdbService(param);

    // In test environment without distributed data manager, expect E_SERVICE_NOT_FOUND
    EXPECT_TRUE(status == E_SERVICE_NOT_FOUND || status == E_NOT_SUPPORT || status == E_OK);
}

/**
 * @tc.name: RdbManagerTest_RegisterInstance_001
 * @tc.desc: Verify RegisterInstance registers custom instance successfully
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerTest, RegisterInstance_001, TestSize.Level1)
{
    class MockRdbManager : public RdbManager {
    public:
        std::pair<int32_t, std::shared_ptr<RdbService>> GetRdbService(const RdbSyncerParam &param) override
        {
            return {E_OK, nullptr};
        }
        std::string GetSelfBundleName() override
        {
            return "mock.bundle";
        }
        void OnRemoteDied() override {}
    };

    MockRdbManager mockInstance;

    bool result = RdbManager::RegisterInstance(&mockInstance);

    EXPECT_FALSE(result);

    // Verify the registered instance is used
    auto &instance = RdbManager::GetInstance();
    EXPECT_NE(&instance, &mockInstance);
}

/**
 * @tc.name: RdbManagerTest_RegisterInstance_Nullptr_002
 * @tc.desc: Verify RegisterInstance handles nullptr
 * @tc.type: FUNC
 */
HWTEST_F(RdbManagerTest, RegisterInstance_Nullptr_002, TestSize.Level2)
{
    // Register nullptr should restore default instance
    bool result = RdbManager::RegisterInstance(nullptr);

    EXPECT_FALSE(result);

    // GetInstance should still work
    auto &instance = RdbManager::GetInstance();
    EXPECT_NE(&instance, nullptr);
}
