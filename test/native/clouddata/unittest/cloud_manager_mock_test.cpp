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
#include <gmock/gmock.h>
#include <unistd.h>

#include <thread>
#include "cloud_manager.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "itypes_util.h"
#include "logger.h"
#include "cloud_types.h"
#include "system_ability_manager_mock.h"

using namespace testing::ext;
using namespace OHOS::CloudData;
using namespace OHOS;
using namespace std;
using namespace testing;

namespace {
class CloudManagerMockTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
public:
    static inline std::shared_ptr<SystemAbilityMock> sa = nullptr;
    static inline sptr<SystemAbilityManagerMock> sam = nullptr;
};

void CloudManagerMockTest::SetUpTestCase(void)
{
}

void CloudManagerMockTest::TearDownTestCase(void)
{
}

void CloudManagerMockTest::SetUp(void)
{
    sa = std::make_shared<SystemAbilityMock>();
    ISystemAbilityBase::sab = sa;
    sam = sptr(new SystemAbilityManagerMock());
}

void CloudManagerMockTest::TearDown(void)
{
    sam = nullptr;
    ISystemAbilityBase::sab = nullptr;
    sa = nullptr;
}

/**
 * @tc.name: GetCloudService_001
 * @tc.desc: Test GetCloudService when GetSystemAbilityManager returns nullptr
 * @tc.type: FUNC
 */
HWTEST_F(CloudManagerMockTest, GetCloudService_001, TestSize.Level1)
{
    EXPECT_CALL(*sa, GetSystemAbilityManager()).WillOnce(Return(nullptr));

    auto [status, service] = CloudManager::GetInstance().GetCloudService();
    EXPECT_EQ(status, CloudService::Status::SERVER_UNAVAILABLE);
    EXPECT_EQ(service, nullptr);
}

/**
 * @tc.name: GetCloudService_002
 * @tc.desc: Test GetCloudService when CheckSystemAbility returns nullptr and LoadSystemAbility succeeds
 * @tc.type: FUNC
 */
HWTEST_F(CloudManagerMockTest, GetCloudService_002, TestSize.Level1)
{
    EXPECT_CALL(*sa, GetSystemAbilityManager()).WillOnce(Return(sam));
    EXPECT_CALL(*sam, CheckSystemAbility(_)).WillOnce(Return(nullptr));
    EXPECT_CALL(*sam, LoadSystemAbility(An<int32_t>(), An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Return(ERR_OK));

    auto [status, service] = CloudManager::GetInstance().GetCloudService();
    EXPECT_EQ(status, CloudService::Status::SERVER_UNAVAILABLE);
    EXPECT_EQ(service, nullptr);
}

/**
 * @tc.name: GetCloudService_003
 * @tc.desc: Test GetCloudService when CheckSystemAbility returns nullptr and LoadSystemAbility fails
 * @tc.type: FUNC
 */
HWTEST_F(CloudManagerMockTest, GetCloudService_003, TestSize.Level1)
{
    EXPECT_CALL(*sa, GetSystemAbilityManager()).WillOnce(Return(sam));
    EXPECT_CALL(*sam, CheckSystemAbility(_)).WillOnce(Return(nullptr));
    EXPECT_CALL(*sam, LoadSystemAbility(An<int32_t>(), An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Return(-1));

    auto [status, service] = CloudManager::GetInstance().GetCloudService();
    EXPECT_EQ(status, CloudService::Status::SERVER_UNAVAILABLE);
    EXPECT_EQ(service, nullptr);
}

/**
 * @tc.name: GetCloudService_004
 * @tc.desc: Test GetCloudService when CheckSystemAbility returns valid object but GetFeatureInterface fails
 * @tc.type: FUNC
 */
HWTEST_F(CloudManagerMockTest, GetCloudService_004, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject = new IPCObjectStub();

    EXPECT_CALL(*sa, GetSystemAbilityManager()).WillOnce(Return(sam));
    EXPECT_CALL(*sam, CheckSystemAbility(_)).WillOnce(Return(remoteObject));

    auto [status, service] = CloudManager::GetInstance().GetCloudService();
    EXPECT_EQ(status, CloudService::Status::FEATURE_UNAVAILABLE);
    EXPECT_EQ(service, nullptr);
}

/**
 * @tc.name: LoadCallback_OnLoadSystemAbilitySuccess_001
 * @tc.desc: Test OnLoadSystemAbilitySuccess with correct SA ID and valid remoteObject
 * @tc.type: FUNC
 */
HWTEST_F(CloudManagerMockTest, LoadCallback_OnLoadSystemAbilitySuccess_001, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject = new IPCObjectStub();
    EXPECT_CALL(*sa, GetSystemAbilityManager()).WillOnce(Return(sam));
    EXPECT_CALL(*sam, CheckSystemAbility(_)).WillOnce(Return(nullptr));
    EXPECT_CALL(*sam, LoadSystemAbility(An<int32_t>(), An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Invoke([&remoteObject](int32_t saId, const sptr<ISystemAbilityLoadCallback> &callback) {
            callback->OnLoadSystemAbilitySuccess(saId, remoteObject);
            return ERR_OK;
        }));

    auto [status, service] = CloudManager::GetInstance().GetCloudService();
    EXPECT_EQ(status, CloudService::Status::SERVER_UNAVAILABLE);
    EXPECT_EQ(service, nullptr);
}

/**
 * @tc.name: LoadCallback_OnLoadSystemAbilitySuccess_002
 * @tc.desc: Test OnLoadSystemAbilitySuccess with incorrect SA ID
 * @tc.type: FUNC
 */
HWTEST_F(CloudManagerMockTest, LoadCallback_OnLoadSystemAbilitySuccess_002, TestSize.Level1)
{
    EXPECT_CALL(*sa, GetSystemAbilityManager()).WillOnce(Return(sam));
    EXPECT_CALL(*sam, CheckSystemAbility(_)).WillOnce(Return(nullptr));
    EXPECT_CALL(*sam, LoadSystemAbility(An<int32_t>(), An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Invoke([](int32_t saId, const sptr<ISystemAbilityLoadCallback> &callback) {
            callback->OnLoadSystemAbilitySuccess(9999, nullptr);
            return ERR_OK;
        }));

    auto [status, service] = CloudManager::GetInstance().GetCloudService();
    EXPECT_EQ(status, CloudService::Status::SERVER_UNAVAILABLE);
    EXPECT_EQ(service, nullptr);
}

/**
 * @tc.name: LoadCallback_OnLoadSystemAbilitySuccess_003
 * @tc.desc: Test OnLoadSystemAbilitySuccess with correct SA ID but nullptr remoteObject
 * @tc.type: FUNC
 */
HWTEST_F(CloudManagerMockTest, LoadCallback_OnLoadSystemAbilitySuccess_003, TestSize.Level1)
{
    EXPECT_CALL(*sa, GetSystemAbilityManager()).WillOnce(Return(sam));
    EXPECT_CALL(*sam, CheckSystemAbility(_)).WillOnce(Return(nullptr));
    EXPECT_CALL(*sam, LoadSystemAbility(An<int32_t>(), An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Invoke([](int32_t saId, const sptr<ISystemAbilityLoadCallback> &callback) {
            callback->OnLoadSystemAbilitySuccess(saId, nullptr);
            return ERR_OK;
        }));

    auto [status, service] = CloudManager::GetInstance().GetCloudService();
    EXPECT_EQ(status, CloudService::Status::SERVER_UNAVAILABLE);
    EXPECT_EQ(service, nullptr);
}

/**
 * @tc.name: LoadCallback_OnLoadSystemAbilityFail_001
 * @tc.desc: Test OnLoadSystemAbilityFail callback
 * @tc.type: FUNC
 */
HWTEST_F(CloudManagerMockTest, LoadCallback_OnLoadSystemAbilityFail_001, TestSize.Level1)
{
    EXPECT_CALL(*sa, GetSystemAbilityManager()).WillOnce(Return(sam));
    EXPECT_CALL(*sam, CheckSystemAbility(_)).WillOnce(Return(nullptr));
    EXPECT_CALL(*sam, LoadSystemAbility(An<int32_t>(), An<const sptr<ISystemAbilityLoadCallback>&>()))
        .WillOnce(Invoke([](int32_t saId, const sptr<ISystemAbilityLoadCallback> &callback) {
            callback->OnLoadSystemAbilityFail(saId);
            return ERR_OK;
        }));

    auto [status, service] = CloudManager::GetInstance().GetCloudService();
    EXPECT_EQ(status, CloudService::Status::SERVER_UNAVAILABLE);
    EXPECT_EQ(service, nullptr);
}
}
