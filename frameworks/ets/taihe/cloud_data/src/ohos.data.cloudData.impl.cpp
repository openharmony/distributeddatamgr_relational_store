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
#include "ani_cloud_data_config.h"
#include "ani_error_code.h"
#include "ani_cloud_data_utils.h"
#include "cloud_types.h"
#include "ani_rdb_utils.h"

namespace AniCloudData {
using namespace OHOS::Rdb;
static constexpr size_t MAX_ACTIONS = 1000;

bool VerifyExtraData(const ExtraData &data)
{
    return (!data.eventId.empty()) && (!data.extraData.empty());
}

void ConfigImpl::EnableCloudImpl(string_view accountId, map_view<string, bool> switches)
{
    if (accountId.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of accountId must be string and not empty.");
        return;
    }
    auto work = [&accountId, &switches](std::shared_ptr<CloudService> proxy) {
        std::map<std::string, int32_t> realSwitches;
        for (auto &item : switches) {
            realSwitches[std::string(item.first)] = item.second ? CloudService::Switch::SWITCH_ON
                : CloudService::Switch::SWITCH_OFF;
        }

        int32_t code = proxy->EnableCloud(std::string(accountId), realSwitches);
        LOG_INFO("EnableCloudImpl work code(%{public}d)", code);
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::DisableCloudImpl(string_view accountId)
{
    if (accountId.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of accountId must be string and not empty.");
        return;
    }
    auto work = [&accountId](std::shared_ptr<CloudService> proxy) {
        int32_t code = proxy->DisableCloud(std::string(accountId));
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::ChangeAppCloudSwitchImpl(string_view accountId, string_view bundleName, bool status)
{
    if (accountId.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of accountId must be string and not empty.");
        return;
    }
    if (bundleName.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of bundleName must be string and not empty.");
        return;
    }
    auto work = [&accountId, &bundleName, &status](std::shared_ptr<CloudService> proxy) {
        OHOS::CloudData::SwitchConfig config;
        int32_t code = proxy->ChangeAppSwitch(std::string(accountId), std::string(bundleName), status, config);
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::NotifyDataChangeOptional(
    const ExtraData &extInfo, optional_view<int32_t> userId)
{
    int32_t id = userId.has_value() ? userId.value() : CloudService::INVALID_USER_ID;
    NotifyDataChangeWithId(extInfo, id);
}

void ConfigImpl::NotifyDataChangeImpl(const ExtraData &extInfo)
{
    NotifyDataChangeWithId(extInfo, CloudService::INVALID_USER_ID);
}

void ConfigImpl::NotifyDataChangeWithId(const ExtraData &extInfo, int32_t userId)
{
    if (!VerifyExtraData(extInfo)) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of extInfo must be Extradata and not empty.");
        return;
    }
    auto work = [&extInfo, &userId](std::shared_ptr<CloudService> proxy) {
        int32_t code = proxy->NotifyDataChange(std::string(extInfo.eventId), std::string(extInfo.extraData), userId);
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::NotifyDataChangeBoth(string_view accountId, string_view bundleName)
{
    if (accountId.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of accountId must be string and not empty.");
        return;
    }
    if (bundleName.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of bundleName must be string and not empty.");
        return;
    }
    auto work = [&accountId, &bundleName](std::shared_ptr<CloudService> proxy) {
        int32_t code = proxy->NotifyDataChange(std::string(accountId), std::string(bundleName));
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

map<string, array<TaiHeStatisticInfo>> ConfigImpl::QueryStatisticsImpl(
    string_view accountId, string_view bundleName, optional_view<string> storeId)
{
    std::optional<std::pair<int32_t, std::map<std::string, StatisticInfos>>> result;
    map<string, array<TaiHeStatisticInfo>> ret;
    if (accountId.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of accountId must be string and not empty.");
        return ret;
    }
    if (bundleName.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of bundleName must be string and not empty.");
        return ret;
    }
    auto work = [&accountId, &bundleName, &storeId, &result](std::shared_ptr<CloudService> proxy) {
        result = proxy->QueryStatistics(std::string(accountId), std::string(bundleName),
            std::string(storeId.has_value() ? storeId.value() : ""));
    };
    RequestIPC(work);
    int errCode = CloudService::Status::ERROR;
    if (result.has_value()) {
        errCode = result.value().first;
        ret = ConvertStatisticInfo(result.value().second);
    }
    if (errCode != CloudService::Status::SUCCESS) {
        ThrowAniError(errCode);
    }
    return ret;
}

map<string, SyncInfo> ConfigImpl::QueryLastSyncInfoImpl(
    string_view accountId, string_view bundleName, optional_view<string> storeId)
{
    std::optional<std::pair<int32_t, QueryLastResults>> result;
    map<string, SyncInfo> ret;
    auto work = [&accountId, &bundleName, &storeId, &result](std::shared_ptr<CloudService> proxy) {
        result = proxy->QueryLastSyncInfo(std::string(accountId), std::string(bundleName),
            std::string(storeId.has_value() ? storeId.value() : ""));
    };
    RequestIPC(work);
    int errCode = CloudService::Status::ERROR;
    if (result.has_value()) {
        errCode = result.value().first;
        auto syncInfo = ConvertSyncInfo(result.value().second);
        if (!syncInfo.first) {
            ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "query last sync info failed.");
            return ret;
        }
        ret = syncInfo.second;
    }
    if (errCode != CloudService::Status::SUCCESS) {
        ThrowAniError(errCode);
    }
    return ret;
}

void ConfigImpl::ClearImpl(string_view accountId, map_view<string, ClearAction> appActions)
{
    if (accountId.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of accountId must be string and not empty.");
        return;
    }
    if (appActions.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of appActions not empty.");
        return;
    }
    if (appActions.size() > MAX_ACTIONS) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "Too many app actions");
        return;
    }

    auto work = [&accountId, &appActions](std::shared_ptr<CloudService> proxy) {
        std::map<std::string, int32_t> actions;
        std::map<std::string, OHOS::CloudData::ClearConfig> configs;
        for (auto const &item : appActions) {
            actions[std::string(item.first)] = item.second.get_value();
        }

        int32_t code = proxy->Clean(std::string(accountId), actions, configs);
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::ChangeAppCloudSwitchImplWithConfig(string_view accountId, string_view bundleName, bool status,
    optional_view<::ohos::data::cloudData::SwitchConfig> config)
{
    if (accountId.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of accountId must be string and not empty.");
        return;
    }
    if (bundleName.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of bundleName must be string and not empty.");
        return;
    }
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
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::ClearImplWithConfig(string_view accountId, map_view<string, ClearAction> appActions,
    optional_view<map<::taihe::string, ::ohos::data::cloudData::ClearConfig>> config)
{
    if (accountId.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of accountId must be string and not empty.");
        return;
    }
    if (appActions.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of appActions not empty.");
        return;
    }
    if (appActions.size() > MAX_ACTIONS) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "Too many app actions");
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
            actions[std::string(item.first)] = item.second.get_value();
        }

        int32_t code = proxy->Clean(std::string(accountId), actions, clearConfig);
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::SetGlobalCloudStrategyImpl(
    StrategyType strategy, optional_view<array<::ohos::data::commonType::ValueType>> param)
{
    if (strategy.get_key() != StrategyType::key_t::NETWORK) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of strategy must be StrategyType.");
        return;
    }
    std::vector<OHOS::CommonType::Value> values;
    if (param.has_value()) {
        for (auto it = param.value().begin(); it != param.value().end(); ++it) {
            if (!it->holds_INT64()) {
                ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
                    "member of param must be of type NetWorkStrategy");
                return;
            }
            int64_t val = it->get_INT64_ref();
            if (val < 0 || val > OHOS::CloudData::NetWorkStrategy::NETWORK_STRATEGY_BUTT) {
                ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
                    "member of param must be of type NetWorkStrategy");
                return;
            }
            values.push_back(it->get_INT64_ref());
        }
    }
    auto work = [&strategy, &param, &values](std::shared_ptr<CloudService> proxy) {
        int32_t code = proxy->SetGlobalCloudStrategy(static_cast<Strategy>(strategy.get_value()), values);
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::CloudSyncImpl(string_view bundleName, string_view storeId, SyncMode mode,
    callback_view<void(const ProgressDetails &data)> progress)
{
    auto work = [&bundleName, &storeId, &mode, progress](std::shared_ptr<CloudService> proxy) {
        auto async = [progress](const OHOS::DistributedRdb::Details &details) {
            if (details.empty()) {
                LOG_ERROR("details is nullptr");
                return;
            }
            progress(ConvertProgressDetail(details.begin()->second));
        };
        CloudService::Option option;
        option.syncMode = ani_rdbutils::SyncModeToNative(mode);
        option.seqNum = GetSeqNum();
        auto status = proxy->CloudSync(std::string(bundleName), std::string(storeId), option, async);
        if (status == CloudService::Status::INVALID_ARGUMENT) {
            status = CloudService::Status::INVALID_ARGUMENT_V20;
        }
        if (status != CloudService::Status::SUCCESS) {
            ThrowAniError(status);
        }
    };
    RequestIPC(work);
}

void SetCloudStrategyImpl(StrategyType strategy, optional_view<array<::ohos::data::commonType::ValueType>> param)
{
    if (strategy.get_key() != StrategyType::key_t::NETWORK) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT, "The type of strategy must be StrategyType.");
        return;
    }
    std::vector<OHOS::CommonType::Value> values;
    if (param.has_value()) {
        for (auto it = param.value().begin(); it != param.value().end(); ++it) {
            if (!it->holds_INT64()) {
                ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
                    "member of param must be of type NetWorkStrategy");
                return;
            }
            int64_t val = it->get_INT64_ref();
            if (val < 0 || val > OHOS::CloudData::NetWorkStrategy::NETWORK_STRATEGY_BUTT) {
                ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
                    "member of param must be of type NetWorkStrategy");
                return;
            }
            values.push_back(it->get_INT64_ref());
        }
    }
    auto work = [&strategy, &param, &values](std::shared_ptr<CloudService> proxy) {
        int32_t code = proxy->SetCloudStrategy(static_cast<Strategy>(strategy.get_value()), values);
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}
}

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_EnableCloudImpl(AniCloudData::ConfigImpl::EnableCloudImpl);
TH_EXPORT_CPP_API_DisableCloudImpl(AniCloudData::ConfigImpl::DisableCloudImpl);
TH_EXPORT_CPP_API_ChangeAppCloudSwitchImpl(AniCloudData::ConfigImpl::ChangeAppCloudSwitchImpl);
TH_EXPORT_CPP_API_NotifyDataChangeOptional(AniCloudData::ConfigImpl::NotifyDataChangeOptional);
TH_EXPORT_CPP_API_NotifyDataChangeImpl(AniCloudData::ConfigImpl::NotifyDataChangeImpl);
TH_EXPORT_CPP_API_NotifyDataChangeWithId(AniCloudData::ConfigImpl::NotifyDataChangeWithId);
TH_EXPORT_CPP_API_NotifyDataChangeBoth(AniCloudData::ConfigImpl::NotifyDataChangeBoth);
TH_EXPORT_CPP_API_QueryStatisticsImpl(AniCloudData::ConfigImpl::QueryStatisticsImpl);
TH_EXPORT_CPP_API_QueryLastSyncInfoImpl(AniCloudData::ConfigImpl::QueryLastSyncInfoImpl);
TH_EXPORT_CPP_API_ClearImpl(AniCloudData::ConfigImpl::ClearImpl);
TH_EXPORT_CPP_API_ChangeAppCloudSwitchImplWithConfig(AniCloudData::ConfigImpl::ChangeAppCloudSwitchImplWithConfig);
TH_EXPORT_CPP_API_ClearImplWithConfig(AniCloudData::ConfigImpl::ClearImplWithConfig);
TH_EXPORT_CPP_API_SetGlobalCloudStrategyImpl(AniCloudData::ConfigImpl::SetGlobalCloudStrategyImpl);
TH_EXPORT_CPP_API_CloudSyncImpl(AniCloudData::ConfigImpl::CloudSyncImpl);
TH_EXPORT_CPP_API_SetCloudStrategyImpl(AniCloudData::SetCloudStrategyImpl);

// NOLINTEND
