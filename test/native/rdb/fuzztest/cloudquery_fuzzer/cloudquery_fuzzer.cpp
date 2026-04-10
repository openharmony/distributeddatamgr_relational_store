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
#include "cloudquery_fuzzer.h"

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

void CloudDataTestQuery001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::string sharingRes = fdp.ConsumeRandomLengthString();
    CloudData::QueryResults result;
    proxy->Query(sharingRes, result);
}

void CloudDataTestQueryByInvitation001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::string invitation = fdp.ConsumeRandomLengthString();
    CloudData::QueryResults result;
    proxy->QueryByInvitation(invitation, result);
}

void CloudDataTestConfirmInvitation001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::string sharingRes = fdp.ConsumeRandomLengthString();
    int32_t confirmation = fdp.ConsumeIntegral<int32_t>();
    std::tuple<int32_t, std::string, std::string> result;
    proxy->ConfirmInvitation(sharingRes, confirmation, result);
}

void CloudDataTestChangeConfirmation001(FuzzedDataProvider &fdp)
{
    AllocNormalHapToken(g_normalPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::string sharingRes = fdp.ConsumeRandomLengthString();
    int32_t confirmation = fdp.ConsumeIntegral<int32_t>();
    std::pair<int32_t, std::string> result;
    proxy->ChangeConfirmation(sharingRes, confirmation, result);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::CloudDataTestQuery001(fdp);
    OHOS::CloudDataTestQueryByInvitation001(fdp);
    OHOS::CloudDataTestConfirmInvitation001(fdp);
    OHOS::CloudDataTestChangeConfirmation001(fdp);
    return 0;
}
