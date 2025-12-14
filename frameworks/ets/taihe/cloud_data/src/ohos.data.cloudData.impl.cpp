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
#define LOG_TAG "AniCloudDataImpl"
#include "logger.h"
#include "ani_cloud_data.h"
#include "ani_error_code.h"
#include "ani_cloud_data_utils.h"
#include "cloud_types.h"

namespace AniCloudData {
using namespace OHOS::Rdb;
void ConfigImpl::ChangeAppCloudSwitchImpl(string_view accountId, string_view bundleName, bool status)
{
    auto work = [&accountId, &bundleName, &status](std::shared_ptr<CloudService> proxy) {
        OHOS::CloudData::SwitchConfig config;
        int32_t code = proxy->ChangeAppSwitch(std::string(accountId), std::string(bundleName), status, config);
        if (code != CloudService::Status::SUCCESS) {
            LOG_ERROR("request, errCode = %{public}d", code);
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::ClearImpl(string_view accountId, map_view<string, ClearAction> appActions)
{
    constexpr size_t MAX_ACTIONS = 1000;
    if (appActions.size() > MAX_ACTIONS) {
        LOG_ERROR("Too many app actions: %{public}zu", appActions.size());
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT);
        return;
    }
    auto work = [&accountId, &appActions](std::shared_ptr<CloudService> proxy) {
        std::map<std::string, int32_t> actions;
        std::map<std::string, OHOS::CloudData::ClearConfig> configs;
        for (auto const &item : appActions) {
            if (item.first.empty()) {
                LOG_ERROR("Invalid bundle name length");
                ThrowAniError(CloudService::Status::INVALID_ARGUMENT);
                return;
            }
            actions[std::string(item.first)] = item.second.get_value();
        }

        int32_t code = proxy->Clean(std::string(accountId), actions, configs);
        if (code != CloudService::Status::SUCCESS) {
            LOG_ERROR("request, errCode = %{public}d", code);
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::ChangeAppCloudSwitchImplWithConfig(string_view accountId, string_view bundleName, bool status,
    optional_view<::ohos::data::cloudData::SwitchConfig> config)
{
    std::map<std::string, OHOS::CloudData::DBSwitchInfo> dbInfo;
    if (config.has_value()) {
        auto switchConfig = config.value();
        for (auto &item : switchConfig.dbInfo) {
            auto convertInfo = ConvertTaiheDbSwitchInfo(item.second);
            dbInfo.emplace(std::string(item.first), std::move(convertInfo));
        }
    }
    OHOS::CloudData::SwitchConfig switchConfig;
    switchConfig.dbInfo = dbInfo;
    auto work = [&accountId, &bundleName, &status, &switchConfig](std::shared_ptr<CloudService> proxy) {
        int32_t code = proxy->ChangeAppSwitch(std::string(accountId), std::string(bundleName), status, switchConfig);
        if (code != CloudService::Status::SUCCESS) {
            LOG_ERROR("request, errCode = %{public}d", code);
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::ClearImplWithConfig(string_view accountId, map_view<string, ClearAction> appActions,
    optional_view<map<::taihe::string, ::ohos::data::cloudData::ClearConfig>> config)
{
    constexpr size_t MAX_ACTIONS = 1000;
    if (appActions.size() > MAX_ACTIONS) {
        LOG_ERROR("Too many app actions: %{public}zu", appActions.size());
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT);
        return;
    }
    std::map<std::string, OHOS::CloudData::ClearConfig> clearConfig;
    if (config.has_value()) {
        for (auto &item : config.value()) {
            auto convertConfig = ConvertTaiheClearConfig(item.second);
            clearConfig.emplace(std::string(item.first), std::move(convertConfig));
        }
    }
    auto work = [&accountId, &appActions, &clearConfig](std::shared_ptr<CloudService> proxy) {
        std::map<std::string, int32_t> actions;
        for (auto const &item : appActions) {
            if (item.first.empty()) {
                LOG_ERROR("Invalid bundle name length");
                ThrowAniError(CloudService::Status::INVALID_ARGUMENT);
                return;
            }
            actions[std::string(item.first)] = item.second.get_value();
        }

        int32_t code = proxy->Clean(std::string(accountId), actions, clearConfig);
        if (code != CloudService::Status::SUCCESS) {
            LOG_ERROR("request, errCode = %{public}d", code);
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}
}

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_ChangeAppCloudSwitchImpl(AniCloudData::ConfigImpl::ChangeAppCloudSwitchImpl);
TH_EXPORT_CPP_API_ClearImpl(AniCloudData::ConfigImpl::ClearImpl);
TH_EXPORT_CPP_API_ChangeAppCloudSwitchImplWithConfig(AniCloudData::ConfigImpl::ChangeAppCloudSwitchImplWithConfig);
TH_EXPORT_CPP_API_ClearImplWithConfig(AniCloudData::ConfigImpl::ClearImplWithConfig);

// NOLINTEND
