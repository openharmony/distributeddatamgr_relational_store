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
#include "cloud_data_test_ut2fuzz.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>

#include "accesstoken_kit.h"
#include "cloud_manager.h"
#include "cloud_types.h"
#include "cloud_types_util.h"
#include "logger.h"
#include "token_setproc.h"


using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::Rdb;
using namespace OHOS::CloudData;
namespace OHOS {

static constexpr const char *TEST_BUNDLE_NAME = "bundleName";
static constexpr const char *TEST_ACCOUNT_ID = "testId";

void AllocSystemHapToken(const HapPolicyParams &policy)
{
    HapInfoParams info = { .userID = 100,
        .bundleName = "ohos.clouddatatest.demo",
        .instIndex = 0,
        .appIDDesc = "ohos.clouddatatest.demo",
        .isSystemApp = true };
    auto token = AccessTokenKit::AllocHapToken(info, policy);
    SetSelfTokenID(token.tokenIDEx);
}

void AllocNormalHapToken(const HapPolicyParams &policy)
{
    HapInfoParams info = { .userID = 100,
        .bundleName = "ohos.clouddatatest.demo",
        .instIndex = 0,
        .appIDDesc = "ohos.clouddatatest.demo",
        .isSystemApp = false };
    auto token = AccessTokenKit::AllocHapToken(info, policy);
    SetSelfTokenID(token.tokenIDEx);
}

HapPolicyParams g_normalPolicy = { .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = { { .permissionName = "ohos.permission.CLOUDDATA_CONFIG",
        .bundleName = "ohos.clouddatatest.demo",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .label = "label",
        .labelId = 1,
        .description = "ohos.clouddatatest.demo",
        .descriptionId = 1 } },
    .permStateList = { { .permissionName = "ohos.permission.CLOUDDATA_CONFIG",
        .isGeneral = true,
        .resDeviceID = { "local" },
        .grantStatus = { PermissionState::PERMISSION_GRANTED },
        .grantFlags = { 1 } } } };

HapPolicyParams g_systemPolicy = { .apl = APL_SYSTEM_BASIC,
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

HapPolicyParams g_notPermissonPolicy = { .apl = APL_SYSTEM_BASIC,
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

CloudData::Participants CreateParticipants(FuzzedDataProvider &fdp)
{
    Privilege privilege;
    privilege.writable = fdp.ConsumeBool();
    privilege.readable = fdp.ConsumeBool();
    privilege.creatable = fdp.ConsumeBool();
    privilege.deletable = fdp.ConsumeBool();
    privilege.shareable = fdp.ConsumeBool();

    Participant participant;
    participant.identity = fdp.ConsumeRandomLengthString();
    participant.role = fdp.ConsumeIntegralInRange<int32_t>(Role::ROLE_NIL, Role::ROLE_BUTT);
    participant.state = fdp.ConsumeIntegralInRange<int32_t>(Confirmation::CFM_NIL, Confirmation::CFM_BUTT);
    participant.privilege = privilege;
    participant.attachInfo = fdp.ConsumeRandomLengthString();

    CloudData::Participants participants;
    participants.push_back(participant);
    return participants;
}

void CloudDataTestCloudDataTest001(FuzzedDataProvider &fdp)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::map<std::string, int32_t> switches;
    switches.emplace(TEST_BUNDLE_NAME, fdp.ConsumeIntegral<int32_t>());
    proxy->EnableCloud(TEST_ACCOUNT_ID, switches);
}

void CloudDataTestChangeAppSwitch001(FuzzedDataProvider &fdp)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    proxy->ChangeAppSwitch(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, fdp.ConsumeIntegral<int32_t>());
}

void CloudDataTestClean001(FuzzedDataProvider &fdp)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::map<std::string, int32_t> actions;
    actions.emplace(TEST_BUNDLE_NAME, fdp.ConsumeIntegral<int32_t>());
    proxy->Clean(TEST_ACCOUNT_ID, actions);
}

void CloudDataTestNotifyDataChange001(FuzzedDataProvider &fdp)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::string eventId = fdp.ConsumeRandomLengthString();
    std::string extraData = fdp.ConsumeRandomLengthString();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    proxy->NotifyDataChange(eventId, extraData, userId);
}

void CloudDataTestShare001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::string sharingRes = fdp.ConsumeRandomLengthString();

    CloudData::Participants participants = CreateParticipants(fdp);
    CloudData::Results results;
    proxy->Share(sharingRes, participants, results);
}

void CloudDataTestUnshare001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::string sharingRes = fdp.ConsumeRandomLengthString();

    CloudData::Participants participants = CreateParticipants(fdp);
    CloudData::Results results;
    proxy->Unshare(sharingRes, participants, results);
}

void CloudDataTestExit001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::string sharingRes = fdp.ConsumeRandomLengthString();
    std::pair<int32_t, std::string> result;
    proxy->Exit(sharingRes, result);
}

void CloudDataTestChangePrivilege001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::string sharingRes = fdp.ConsumeRandomLengthString();
    CloudData::Participants participants = CreateParticipants(fdp);
    CloudData::Results results;
    proxy->ChangePrivilege(sharingRes, participants, results);
}

void CloudDataTestQuery001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::string sharingRes = fdp.ConsumeRandomLengthString();
    CloudData::QueryResults result;
    proxy->Query(sharingRes, result);
}

void CloudDataTestQueryByInvitation001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::string invitation = fdp.ConsumeRandomLengthString();
    CloudData::QueryResults result;
    proxy->QueryByInvitation(invitation, result);
}

void CloudDataTestConfirmInvitation001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::string sharingRes = fdp.ConsumeRandomLengthString();
    int32_t confirmation = fdp.ConsumeIntegral<int32_t>();
    std::tuple<int32_t, std::string, std::string> result;
    proxy->ConfirmInvitation(sharingRes, confirmation, result);
}

void CloudDataTestChangeConfirmation001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::string sharingRes = fdp.ConsumeRandomLengthString();
    int32_t confirmation = fdp.ConsumeIntegral<int32_t>();
    std::pair<int32_t, std::string> result;
    proxy->ChangeConfirmation(sharingRes, confirmation, result);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::CloudDataTestCloudDataTest001(fdp);
    OHOS::CloudDataTestChangeAppSwitch001(fdp);
    OHOS::CloudDataTestClean001(fdp);
    OHOS::CloudDataTestNotifyDataChange001(fdp);
    OHOS::CloudDataTestShare001(fdp);
    OHOS::CloudDataTestUnshare001(fdp);
    OHOS::CloudDataTestExit001(fdp);
    OHOS::CloudDataTestChangePrivilege001(fdp);
    OHOS::CloudDataTestQuery001(fdp);
    OHOS::CloudDataTestQueryByInvitation001(fdp);
    OHOS::CloudDataTestConfirmInvitation001(fdp);
    OHOS::CloudDataTestChangeConfirmation001(fdp);
    return 0;
}
