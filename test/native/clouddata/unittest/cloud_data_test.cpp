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
#include "cloud_types.h"
#include "cloud_types_util.h"
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
void AllocSystemHapToken(const HapPolicyParams &policy)
{
    HapInfoParams info = {
        .userID = 100,
        .bundleName = "ohos.clouddatatest.demo",
        .instIndex = 0,
        .appIDDesc = "ohos.clouddatatest.demo",
        .isSystemApp = true
    };
    auto token = AccessTokenKit::AllocHapToken(info, policy);
    SetSelfTokenID(token.tokenIDEx);
}

void AllocNormalHapToken(const HapPolicyParams &policy)
{
    HapInfoParams info = {
        .userID = 100,
        .bundleName = "ohos.clouddatatest.demo",
        .instIndex = 0,
        .appIDDesc = "ohos.clouddatatest.demo",
        .isSystemApp = false
    };
    auto token = AccessTokenKit::AllocHapToken(info, policy);
    SetSelfTokenID(token.tokenIDEx);
}

HapPolicyParams g_normalPolicy = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.CLOUDDATA_CONFIG",
            .bundleName = "ohos.clouddatatest.demo",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "ohos.clouddatatest.demo",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.CLOUDDATA_CONFIG",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

HapPolicyParams g_systemPolicy = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.CLOUDDATA_CONFIG",
            .bundleName = "ohos.clouddatatest.demo",
            .grantMode = 1,
            .availableLevel = APL_SYSTEM_BASIC,
            .label = "label",
            .labelId = 1,
            .description = "ohos.clouddatatest.demo",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.CLOUDDATA_CONFIG",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

HapPolicyParams g_notPermissonPolicy = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.TEST",
            .bundleName = "ohos.clouddatatest.demo",
            .grantMode = 1,
            .availableLevel = APL_SYSTEM_BASIC,
            .label = "label",
            .labelId = 1,
            .description = "ohos.clouddatatest.demo",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.TEST",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

class CloudDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp()
    {
    }
    void TearDown()
    {
        SetSelfTokenID(g_selfTokenID);
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
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto [status, info] = proxy->QueryStatistics(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, TEST_STORE_ID);
    EXPECT_EQ(status, CloudService::PERMISSION_DENIED);
    EXPECT_TRUE(info.empty());
}

/* *
 * @tc.name: CloudDataTest_002
 * @tc.desc: Test the permissions of the QueryStatistics API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudDataTest_002, TestSize.Level1)
{
    AllocSystemHapToken(g_notPermissonPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto [status, info] = proxy->QueryStatistics(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, TEST_STORE_ID);
    EXPECT_EQ(status, CloudService::CLOUD_CONFIG_PERMISSION_DENIED);
    EXPECT_TRUE(info.empty());
}

/* *
 * @tc.name: CloudDataTest_003
 * @tc.desc: Test the permissions of the QueryStatistics API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudDataTest_003, TestSize.Level1)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto [status, info] = proxy->QueryStatistics(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, TEST_STORE_ID);
    EXPECT_EQ(status, CloudService::ERROR);
    EXPECT_TRUE(info.empty());
}

/* *
 * @tc.name: EnableCloud001
 * @tc.desc: Test the EnableCloud API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, EnableCloud001, TestSize.Level0)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::map<std::string, int32_t> switches;
    switches.emplace(TEST_BUNDLE_NAME, 0);
    auto status = proxy->EnableCloud(TEST_ACCOUNT_ID, switches);
    EXPECT_NE(status, CloudService::SUCCESS);
}

/* *
 * @tc.name: DisableCloud001
 * @tc.desc: Test the DisableCloud API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, DisableCloud001, TestSize.Level0)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto status = proxy->DisableCloud(TEST_ACCOUNT_ID);
    EXPECT_NE(status, CloudService::SUCCESS);
}

/* *
 * @tc.name: ChangeAppSwitch001
 * @tc.desc: Test the ChangeAppSwitch API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, ChangeAppSwitch001, TestSize.Level0)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto status = proxy->ChangeAppSwitch(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, 0);
    EXPECT_NE(status, CloudService::SUCCESS);
}

/* *
 * @tc.name: Clean001
 * @tc.desc: Test the Clean API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, Clean001, TestSize.Level1)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::map<std::string, int32_t> actions;
    actions.emplace(TEST_BUNDLE_NAME, 0);
    auto status = proxy->Clean(TEST_ACCOUNT_ID, actions);
    EXPECT_EQ(status, CloudService::ERROR);
}

/* *
 * @tc.name: NotifyDataChange001
 * @tc.desc: Test the NotifyDataChange API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, NotifyDataChange001, TestSize.Level1)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto status = proxy->NotifyDataChange("id", "data", 100);
    EXPECT_EQ(status, CloudService::INVALID_ARGUMENT);
}

/* *
 * @tc.name: NotifyDataChange002
 * @tc.desc: Test the NotifyDataChange API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, NotifyDataChange002, TestSize.Level1)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto status = proxy->NotifyDataChange(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME);
    EXPECT_EQ(status, CloudService::INVALID_ARGUMENT);
}

/* *
 * @tc.name: SetGlobalCloudStrategy001
 * @tc.desc: Test the SetGlobalCloudStrategy API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, SetGlobalCloudStrategy001, TestSize.Level1)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::vector<CommonType::Value> values = { 0 };
    auto status = proxy->SetGlobalCloudStrategy(Strategy::STRATEGY_NETWORK, values);
    EXPECT_EQ(status, CloudService::SUCCESS);
}

/* *
 * @tc.name: QueryLastSyncInfo001
 * @tc.desc: Test the system application permissions of the QueryLastSyncInfo API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, QueryLastSyncInfo001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto [status, info] = proxy->QueryLastSyncInfo(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, TEST_STORE_ID);
    EXPECT_EQ(status, CloudService::PERMISSION_DENIED);
    EXPECT_TRUE(info.empty());
}

/* *
 * @tc.name: QueryLastSyncInfo002
 * @tc.desc: Test the permission name of the QueryLastSyncInfo API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, QueryLastSyncInfo002, TestSize.Level1)
{
    AllocSystemHapToken(g_notPermissonPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto [status, info] = proxy->QueryLastSyncInfo(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, TEST_STORE_ID);
    EXPECT_EQ(status, CloudService::CLOUD_CONFIG_PERMISSION_DENIED);
    EXPECT_TRUE(info.empty());
}

/* *
 * @tc.name: AllocResourceAndShare001
 * @tc.desc: Test the system application permissions of the AllocResourceAndShare001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, AllocResourceAndShare001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    DistributedRdb::PredicatesMemo predicates;
    predicates.tables_.push_back(TEST_BUNDLE_NAME);
    std::vector<std::string> columns;
    CloudData::Participants participants;
    auto [ret, _] = proxy->AllocResourceAndShare(TEST_STORE_ID, predicates, columns, participants);
    EXPECT_EQ(ret, CloudService::PERMISSION_DENIED);
}

/* *
 * @tc.name: Share001
 * @tc.desc: Test the system application permissions of the Share001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, Share001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::string sharingRes = "";
    CloudData::Participants participants{};
    CloudData::Results results;
    auto ret = proxy->Share(sharingRes, participants, results);
    EXPECT_EQ(ret, CloudService::PERMISSION_DENIED);
}

/* *
 * @tc.name: Unshare001
 * @tc.desc: Test the system application permissions of the Unshare001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, Unshare001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::string sharingRes = "";
    CloudData::Participants participants{};
    CloudData::Results results;
    auto ret = proxy->Unshare(sharingRes, participants, results);
    EXPECT_EQ(ret, CloudService::PERMISSION_DENIED);
}

/* *
 * @tc.name: Exit001
 * @tc.desc: Test the system application permissions of the Exit001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, Exit001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::string sharingRes = "";
    std::pair<int32_t, std::string> result;
    auto ret = proxy->Exit(sharingRes, result);
    EXPECT_EQ(ret, CloudService::PERMISSION_DENIED);
}

/* *
 * @tc.name: ChangePrivilege001
 * @tc.desc: Test the system application permissions of the ChangePrivilege001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, ChangePrivilege001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::string sharingRes = "";
    CloudData::Participants participants{};
    CloudData::Results results;
    auto ret = proxy->ChangePrivilege(sharingRes, participants, results);
    EXPECT_EQ(ret, CloudService::PERMISSION_DENIED);
}

/* *
 * @tc.name: Query001
 * @tc.desc: Test the system application permissions of the Query001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, Query001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::string sharingRes = "";
    CloudData::QueryResults result;
    auto ret = proxy->Query(sharingRes, result);
    EXPECT_EQ(ret, CloudService::PERMISSION_DENIED);
}

/* *
 * @tc.name:QueryByInvitation001
 * @tc.desc: Test the system application permissions of the QueryByInvitation001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, QueryByInvitation001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::string invitation = "";
    CloudData::QueryResults result;
    auto ret = proxy->QueryByInvitation(invitation, result);
    EXPECT_EQ(ret, CloudService::PERMISSION_DENIED);
}

/* *
 * @tc.name:ConfirmInvitation001
 * @tc.desc: Test the system application permissions of the ConfirmInvitation001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, ConfirmInvitation001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::string sharingRes = "";
    int32_t confirmation = 0;
    std::tuple<int32_t, std::string, std::string> result;
    auto ret = proxy->ConfirmInvitation(sharingRes, confirmation, result);
    EXPECT_EQ(ret, CloudService::PERMISSION_DENIED);
}

/* *
 * @tc.name:ChangeConfirmation001
 * @tc.desc: Test the system application permissions of the ChangeConfirmation001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, ChangeConfirmation001, TestSize.Level0)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::string sharingRes = "";
    int32_t confirmation = 0;
    std::pair<int32_t, std::string> result;
    auto ret = proxy->ChangeConfirmation(sharingRes, confirmation, result);
    EXPECT_EQ(ret, CloudService::PERMISSION_DENIED);
}

/* *
 * @tc.name:SetCloudStrategy001
 * @tc.desc: Test the system application permissions of the SetCloudStrategy001 API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, SetCloudStrategy001, TestSize.Level1)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    std::vector<CommonType::Value> values;
    values.push_back(CloudData::NetWorkStrategy::WIFI);
    CloudData::Strategy strategy = CloudData::Strategy::STRATEGY_BUTT;
    auto ret = proxy->SetCloudStrategy(strategy, values);
    EXPECT_EQ(ret, CloudService::IPC_ERROR);
    strategy = CloudData::Strategy::STRATEGY_NETWORK;
    ret = proxy->SetCloudStrategy(strategy, values);
    EXPECT_EQ(ret, CloudService::SUCCESS);
}
} // namespace OHOS::CloudData