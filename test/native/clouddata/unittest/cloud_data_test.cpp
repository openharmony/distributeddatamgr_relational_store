/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <unistd.h>

#include "accesstoken_kit.h"
#include "cloud_manager.h"
#include "logger.h"
#include "token_setproc.h"

namespace OHOS::CloudData {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::Rdb;
uint64_t g_selfTokenID = 0;
static constexpr const char *TEST_BUNDLE_NAME = "bundleName";
static constexpr const char *TEST_ACCOUNT_ID = "testId";
static constexpr const char *TEST_STORE_ID = "storeId";
void AllocHapToken(HapPolicyParams policy)
{
    HapInfoParams info = { .userID = 100,
        .bundleName = "ohos.clouddatatest.demo",
        .instIndex = 0,
        .appIDDesc = "ohos.clouddatatest.demo",
        .isSystemApp = true };
    auto token = AccessTokenKit::AllocHapToken(info, policy);
    SetSelfTokenID(token.tokenIDEx);
}

class CloudDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp()
    {
    }
    void TearDown()
    {
    }
};

void CloudDataTest::SetUpTestCase(void)
{
    g_selfTokenID = GetSelfTokenID();
}

void CloudDataTest::TearDownTestCase(void)
{
    SetSelfTokenID(g_selfTokenID);
}

/* *
 * @tc.name: CloudDataTest_001
 * @tc.desc: Test the system application permissions of the QueryStatistics API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudDataTest_001, TestSize.Level0)
{
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS) {
        EXPECT_TRUE(false);
    } else {
        auto [status, info] = proxy->QueryStatistics(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, TEST_STORE_ID);
        EXPECT_EQ(status, CloudService::PERMISSION_DENIED);
        EXPECT_TRUE(info.empty());
    }
}

/* *
 * @tc.name: CloudDataTest_002
 * @tc.desc: Test the permissions of the QueryStatistics API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudDataTest_002, TestSize.Level0)
{
    HapPolicyParams policy = { .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain",
        .permList = { { .permissionName = "ohos.permission.TEST",
            .bundleName = "ohos.clouddatatest.demo",
            .grantMode = 1,
            .availableLevel = APL_SYSTEM_BASIC,
            .label = "label",
            .labelId = 1,
            .description = "ohos.clouddatatest.demo",
            .descriptionId = 1 } },
        .permStateList = { { .permissionName = "ohos.permission.TEST",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 } } } };
    AllocHapToken(policy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS) {
        EXPECT_TRUE(false);
    } else {
        auto [status, info] = proxy->QueryStatistics(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, TEST_STORE_ID);
        EXPECT_EQ(status, CloudService::CLOUD_CONFIG_PERMISSION_DENIED);
        EXPECT_TRUE(info.empty());
    }
}

/* *
 * @tc.name: CloudDataTest_003
 * @tc.desc: Test the permissions of the QueryStatistics API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudDataTest_003, TestSize.Level0)
{
    HapPolicyParams policy = { .apl = APL_SYSTEM_BASIC,
        .domain = "test.domain",
        .permList = { { .permissionName = "ohos.permission.CLOUDDATA_CONFIG",
            .bundleName = "ohos.clouddatatest.demo",
            .grantMode = 1,
            .availableLevel = APL_SYSTEM_BASIC,
            .label = "label",
            .labelId = 1,
            .description = "ohos.clouddatatest.demo",
            .descriptionId = 1 } },
        .permStateList = { { .permissionName = "ohos.permission.CLOUDDATA_CONFIG",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 } } } };
    AllocHapToken(policy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS) {
        EXPECT_TRUE(false);
    } else {
        auto [status, info] = proxy->QueryStatistics(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, TEST_STORE_ID);
        EXPECT_EQ(status, CloudService::ERROR);
        EXPECT_TRUE(info.empty());
    }
}
} // namespace OHOS::CloudData