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
#include "clouddata_fuzzer.h"

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
static constexpr size_t MAX_RANDOM_STR_LEN = 100;

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

CloudData::SwitchConfig CreateSwitchConfig(FuzzedDataProvider &fdp)
{
    CloudData::SwitchConfig config;
    DBSwitchInfo switchInfo;
    switchInfo.enable = fdp.ConsumeBool();
    std::map<std::string, bool> tableInfo;
    tableInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), fdp.ConsumeBool());
    tableInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), fdp.ConsumeBool());
    tableInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), fdp.ConsumeBool());
    tableInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), fdp.ConsumeBool());
    switchInfo.tableInfo = tableInfo;
    config.dbInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), switchInfo);
    config.dbInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), switchInfo);
    config.dbInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), switchInfo);
    config.dbInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), switchInfo);
    return config;
}

CloudData::ClearConfig CreateClearConfig(FuzzedDataProvider &fdp)
{
    CloudData::ClearConfig config;
    DBActionInfo actionInfo;
    actionInfo.action = fdp.ConsumeIntegral<int32_t>();
    std::map<std::string, int32_t> tableInfo;
    tableInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), fdp.ConsumeIntegral<int32_t>());
    tableInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), fdp.ConsumeIntegral<int32_t>());
    tableInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), fdp.ConsumeIntegral<int32_t>());
    tableInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), fdp.ConsumeIntegral<int32_t>());
    actionInfo.tableInfo = tableInfo;
    config.dbInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), actionInfo);
    config.dbInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), actionInfo);
    config.dbInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), actionInfo);
    config.dbInfo.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), actionInfo);
    return config;
}

void CloudDataTestCloudDataTest001(FuzzedDataProvider &fdp)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    std::map<std::string, int32_t> switches;
    switches.emplace(TEST_BUNDLE_NAME, fdp.ConsumeIntegral<int32_t>());
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    proxy->EnableCloud(TEST_ACCOUNT_ID, switches);
}

void CloudDataTestChangeAppSwitch001(FuzzedDataProvider &fdp)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    proxy->ChangeAppSwitch(TEST_ACCOUNT_ID, TEST_BUNDLE_NAME, fdp.ConsumeIntegral<int32_t>(), CreateSwitchConfig(fdp));
}

void CloudDataTestClean001(FuzzedDataProvider &fdp)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::map<std::string, int32_t> actions;
    actions.emplace(TEST_BUNDLE_NAME, fdp.ConsumeIntegral<int32_t>());
    std::map<std::string, ClearConfig> configs;
    configs.emplace(fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN), CreateClearConfig(fdp));
    proxy->Clean(TEST_ACCOUNT_ID, actions, configs);
}

void CloudDataTestNotifyDataChange001(FuzzedDataProvider &fdp)
{
    AllocSystemHapToken(g_systemPolicy);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (state != CloudService::SUCCESS || proxy == nullptr) {
        return;
    }
    std::string eventId = fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN);
    std::string extraData = fdp.ConsumeRandomLengthString(MAX_RANDOM_STR_LEN);
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    proxy->NotifyDataChange(eventId, extraData, userId);
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::CloudDataTestCloudDataTest001(fdp);
    OHOS::CloudDataTestChangeAppSwitch001(fdp);
    OHOS::CloudDataTestClean001(fdp);
    OHOS::CloudDataTestNotifyDataChange001(fdp);
    return 0;
}
