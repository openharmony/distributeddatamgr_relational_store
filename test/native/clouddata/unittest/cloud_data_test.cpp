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

#define LOG_TAG "CloudDataTest"

#include <condition_variable>
#include <gtest/gtest.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "cloud_manager.h"
#include "cloud_notifier_stub.h"
#include "cloud_service_proxy.h"
#include "cloud_types.h"
#include "cloud_types_util.h"
#include "logger.h"
#include "rdb_types.h"
#include "token_setproc.h"

namespace OHOS::CloudData {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::Rdb;
using namespace DistributedRdb;
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

    static std::mutex syncCompleteLock_;
    static std::condition_variable syncCompleteCv_;
    static int32_t progressStatus_;
    static int32_t code_;
    static constexpr uint32_t delayTime = 2000;
};

std::mutex CloudDataTest::syncCompleteLock_;
std::condition_variable CloudDataTest::syncCompleteCv_;
int32_t CloudDataTest::progressStatus_ = Progress::SYNC_BEGIN;
int32_t CloudDataTest::code_ = ProgressCode::SUCCESS;

void CloudDataTest::SetUpTestCase(void)
{
    LOG_INFO("SetUpTestCase in.");
    g_selfTokenID = GetSelfTokenID();
}

void CloudDataTest::TearDownTestCase(void)
{
    LOG_INFO("TearDownTestCase in.");
    SetSelfTokenID(g_selfTokenID);
}

/* *
 * @tc.name: CloudSync_SyncComplete_001
 * @tc.desc: Test the CloudSync API with syncComplete callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync_SyncComplete_001, TestSize.Level1)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto progress = [](DistributedRdb::Details &&details) {
        ASSERT_NE(details.size(), 0);
        progressStatus_ = details.begin()->second.progress;
        code_ = details.begin()->second.code;
        LOG_INFO("CloudSync_SyncComplete_001, progressStatus_:%{public}d, code_:%{public}d", progressStatus_, code_);
        if (progressStatus_ == Progress::SYNC_FINISH) {
            LOG_INFO("CloudSync_SyncComplete_001, start to notify, progressStatus_:%{public}d, code_:%{public}d",
                progressStatus_, code_);
            std::unique_lock<std::mutex> lock(syncCompleteLock_);
            syncCompleteCv_.notify_one();
        }
    };
    int32_t syncMode = 4; // 4 is native_first
    uint32_t seqNum = 101;
    auto status = proxy->CloudSync(TEST_BUNDLE_NAME, TEST_STORE_ID, { syncMode, seqNum }, progress);
    EXPECT_EQ(status, CloudService::SUCCESS);
    std::unique_lock<std::mutex> lock(syncCompleteLock_);
    auto result = syncCompleteCv_.wait_for(lock, std::chrono::milliseconds(CloudDataTest::delayTime), [] {
        LOG_INFO("CloudSync_SyncComplete_001, wait_for in, progressStatus_:%{public}d, code_:%{public}d",
            progressStatus_, code_);
        return progressStatus_ == Progress::SYNC_FINISH && code_ == ProgressCode::CLOUD_DISABLED;
    });
    EXPECT_TRUE(result);
    LOG_INFO("CloudSync_SyncComplete_001 test end.");
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
    SwitchConfig config;
    auto status = proxy->ChangeAppSwitch(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, 0, config);
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
    std::map<std::string, ClearConfig> configs;
    auto status = proxy->Clean(TEST_ACCOUNT_ID, actions, configs);
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

/* *
 * @tc.name: CloudSync001
 * @tc.desc: Test the invalid param of the CloudSync API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync001, TestSize.Level1)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto ret = proxy->CloudSync(TEST_BUNDLE_NAME, TEST_STORE_ID, {}, nullptr);  // no progress
    EXPECT_EQ(ret, CloudService::INVALID_ARGUMENT);
    LOG_INFO("CloudSync001 test end.");
}

/* *
 * @tc.name: CloudSync002
 * @tc.desc: Test the CloudSync API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync002, TestSize.Level1)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto progress = [](DistributedRdb::Details &&) {};
    auto status = proxy->CloudSync(TEST_BUNDLE_NAME, TEST_STORE_ID, {}, progress);
    EXPECT_EQ(status, CloudService::INVALID_ARGUMENT);  // invalid syncMode
    LOG_INFO("CloudSync002 test end.");
}

/* *
 * @tc.name: CloudSync003
 * @tc.desc: Test the CloudSync API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync003, TestSize.Level1)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto progress = [](DistributedRdb::Details &&) {};
    int32_t syncMode = 4; // 4 is native_first
    uint32_t seqNum = 10;
    auto status = proxy->CloudSync(TEST_BUNDLE_NAME, TEST_STORE_ID, { syncMode, seqNum }, progress);
    EXPECT_EQ(status, CloudService::SUCCESS);
    LOG_INFO("CloudSync003 test end.");
}

/* *
 * @tc.name: CloudSync004
 * @tc.desc: Test the hap permission of the CloudSync API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync004, TestSize.Level1)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto progress = [](DistributedRdb::Details &&) {};
    int32_t syncMode = 4; // 4 is native_first
    uint32_t seqNum = 100;
    auto status = proxy->CloudSync(TEST_BUNDLE_NAME, TEST_STORE_ID, { syncMode, seqNum }, progress);
    EXPECT_EQ(status, CloudService::PERMISSION_DENIED);
    LOG_INFO("CloudSync004 test end.");
}

/* *
 * @tc.name: CloudSync005
 * @tc.desc: Test the permissions of the CloudSync API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync005, TestSize.Level1)
{
    AllocSystemHapToken(g_notPermissonPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto progress = [](DistributedRdb::Details &&) {};
    int32_t syncMode = 4; // 4 is native_first
    uint32_t seqNum = 1000;
    auto status = proxy->CloudSync(TEST_BUNDLE_NAME, TEST_STORE_ID, { syncMode, seqNum }, progress);
    EXPECT_EQ(status, CloudService::CLOUD_CONFIG_PERMISSION_DENIED);
    LOG_INFO("CloudSync005 test end.");
}

/* *
 * @tc.name: CloudSync006
 * @tc.desc: Test the CloudSync API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync006, TestSize.Level1)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto progress = [](DistributedRdb::Details &&) {};
    int32_t syncMode = 4; // 4 is native_first
    uint32_t seqNum = 20;
    auto status = proxy->CloudSync(TEST_BUNDLE_NAME, TEST_STORE_ID, { syncMode, seqNum }, progress);
    EXPECT_EQ(status, CloudService::SUCCESS);

    // same seqNum, register progress failed.
    status = proxy->CloudSync(TEST_BUNDLE_NAME, TEST_STORE_ID, { syncMode, seqNum }, progress);
    EXPECT_EQ(status, CloudService::ERROR);
    LOG_INFO("CloudSync006 test end.");
}

/* *
 * @tc.name: CloudSync007
 * @tc.desc: Test the invalid param of the CloudSync API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync007, TestSize.Level1)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto progress = [](DistributedRdb::Details &&) {};
    int32_t syncMode = 4; // 4 is native_first
    uint32_t seqNum = 21;
    auto ret = proxy->CloudSync("", TEST_STORE_ID, { syncMode, seqNum }, progress);  // bundleName is empty
    EXPECT_EQ(ret, CloudService::INVALID_ARGUMENT);
    LOG_INFO("CloudSync007 test end.");
}

/* *
 * @tc.name: CloudSync008
 * @tc.desc: Test the invalid param of the CloudSync API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync008, TestSize.Level1)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto progress = [](DistributedRdb::Details &&) {};
    int32_t syncMode = 4; // 4 is native_first
    uint32_t seqNum = 22;
    auto ret = proxy->CloudSync(TEST_BUNDLE_NAME, "", { syncMode, seqNum }, progress);  // storeId is empty
    EXPECT_EQ(ret, CloudService::INVALID_ARGUMENT);
    LOG_INFO("CloudSync008 test end.");
}

/* *
 * @tc.name: CloudSync009
 * @tc.desc: Test the invalid param of the CloudSync API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, CloudSync009, TestSize.Level1)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    auto progress = [](DistributedRdb::Details &&) {};
    int32_t syncMode = 10;
    uint32_t seqNum = 22;
    auto ret = proxy->CloudSync(TEST_BUNDLE_NAME, TEST_STORE_ID, { syncMode, seqNum }, progress);  // invalid syncMode
    EXPECT_EQ(ret, CloudService::INVALID_ARGUMENT);
    LOG_INFO("CloudSync009 test end.");
}

/* *
 * @tc.name: InitNotifier001
 * @tc.desc: Test the InitNotifier API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, InitNotifier001, TestSize.Level1)
{
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    sptr<CloudNotifierStub> notifier = nullptr;
    auto status = proxy->InitNotifier(notifier);  // can not Marshalling a 'nullptr'
    EXPECT_EQ(status, CloudService::IPC_PARCEL_ERROR);
    LOG_INFO("InitNotifier001 test end.");
}

/* *
 * @tc.name: InitNotifier002
 * @tc.desc: Test the InitNotifier API
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, InitNotifier002, TestSize.Level1)
{
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    ASSERT_EQ(state == CloudService::SUCCESS && proxy != nullptr, true);
    sptr<CloudNotifierStub> notifier = new (std::nothrow) CloudNotifierStub(nullptr);
    auto status = proxy->InitNotifier(notifier);
    EXPECT_EQ(status, CloudService::SUCCESS);
    LOG_INFO("InitNotifier002 test end.");
}

/* *
 * @tc.name: MarshallingOptionTest
 * @tc.desc: Test the Marshalling interface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudDataTest, MarshallingOptionTest, TestSize.Level1)
{
    LOG_INFO("MarshallingOptionTest test in.");
    CloudData::CloudService::Option input;
    input.syncMode = 4;
    input.seqNum = 10;
    MessageParcel parcel;
    bool ret = ITypesUtil::Marshalling(input, parcel);
    EXPECT_TRUE(ret);

    CloudData::CloudService::Option output;
    ret = ITypesUtil::Unmarshalling(output, parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(output.syncMode, input.syncMode);
    EXPECT_EQ(output.seqNum, input.seqNum);
    LOG_INFO("MarshallingOptionTest test end.");
}
} // namespace OHOS::CloudData