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
#include "cloudshare_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>

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

static constexpr size_t MAX_RANDOM_STR_LEN = 100;

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

CloudData::Participants CreateParticipants(FuzzedDataProvider &fdp)
{
    Privilege privilege;
    privilege.writable = fdp.ConsumeBool();
    privilege.readable = fdp.ConsumeBool();
    privilege.creatable = fdp.ConsumeBool();
    privilege.deletable = fdp.ConsumeBool();
    privilege.shareable = fdp.ConsumeBool();

    Participant participant;
    participant.identity = fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN);
    participant.role = fdp.ConsumeIntegralInRange<int32_t>(Role::ROLE_NIL, Role::ROLE_BUTT);
    participant.state = fdp.ConsumeIntegralInRange<int32_t>(Confirmation::CFM_NIL, Confirmation::CFM_BUTT);
    participant.privilege = privilege;
    participant.attachInfo = fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN);

    CloudData::Participants participants;
    participants.push_back(participant);
    return participants;
}

void CloudDataTestShare001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::string sharingRes = fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN);

    CloudData::Participants participants = CreateParticipants(fdp);
    CloudData::Results results;
    proxy->Share(sharingRes, participants, results);
}

void CloudDataTestUnshare001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::string sharingRes = fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN);

    CloudData::Participants participants = CreateParticipants(fdp);
    CloudData::Results results;
    proxy->Unshare(sharingRes, participants, results);
}

void CloudDataTestExit001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::string sharingRes = fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN);
    std::pair<int32_t, std::string> result;
    proxy->Exit(sharingRes, result);
}

void CloudDataTestChangePrivilege001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::string sharingRes = fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN);
    CloudData::Participants participants = CreateParticipants(fdp);
    CloudData::Results results;
    proxy->ChangePrivilege(sharingRes, participants, results);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::CloudDataTestShare001(fdp);
    OHOS::CloudDataTestUnshare001(fdp);
    OHOS::CloudDataTestExit001(fdp);
    OHOS::CloudDataTestChangePrivilege001(fdp);
    return 0;
}
