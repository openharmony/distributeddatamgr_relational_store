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
std::mutex ConfigImpl::syncInfoObserversMutex_;
std::map<std::string, std::map<std::string, std::vector<std::shared_ptr<TaiheCloudSyncInfoObserver>>>>
    ConfigImpl::syncInfoObservers_;
std::mutex ConfigImpl::autoSyncTriggerObserversMutex_;
std::vector<std::shared_ptr<TaiheCloudSyncTriggerObserver>> ConfigImpl::autoSyncTriggerObservers_;

bool VerifyExtraData(const ExtraData &data)
{
    return (!data.eventId.empty()) && (!data.extraData.empty());
}

TaiheCloudSyncInfoObserver::TaiheCloudSyncInfoObserver(TaiheSyncInfoCallback callback) : callback_(std::move(callback))
{
}

void TaiheCloudSyncInfoObserver::OnSyncInfoChanged(const std::map<std::string, QueryLastResults> &data)
{
    taihe::env_guard guard;
    auto converted = ConvertBatchSyncInfo(data);
    if (converted.first) {
        LOG_INFO("OnSyncInfoChanged size: %{public}zu", converted.second.size());
        callback_(converted.second);
    }
}

void TaiheCloudSyncInfoObserver::OnSyncInfoChanged(const int32_t triggerMode)
{
    LOG_INFO("OnSyncInfoChanged triggerMode: %{public}d", triggerMode);
}

bool TaiheCloudSyncInfoObserver::operator==(const TaiheSyncInfoCallback &other) const
{
    return callback_ == other;
}

TaiheCloudSyncTriggerObserver::TaiheCloudSyncTriggerObserver(TaiheSyncTriggerCallback callback)
    : callback_(std::move(callback))
{
}

void TaiheCloudSyncTriggerObserver::OnSyncInfoChanged(const std::map<std::string, QueryLastResults> &data)
{
}

void TaiheCloudSyncTriggerObserver::OnSyncInfoChanged(const int32_t triggerMode)
{
    auto mode = ::ohos::data::cloudData::AutoSyncTriggerMode::from_value(triggerMode);
    TaiheCloudSyncTriggerInfo triggerInfo = {
        .mode = mode
    };
    callback_(triggerInfo);
}

bool TaiheCloudSyncTriggerObserver::operator==(const TaiheSyncTriggerCallback &other) const
{
    return callback_ == other;
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
            LOG_ERROR("request, errcode = %{public}d", code);
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
            LOG_ERROR("request, errcode = %{public}d", code);
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
            LOG_ERROR("request, errcode = %{public}d", code);
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

map<string, map<string, SyncInfo>> ConfigImpl::QueryLastSyncInfoBatchImpl(
    string_view accountId, array_view<::ohos::data::cloudData::BundleInfo> bundleInfos)
{
    std::optional<std::pair<int32_t, BatchQueryLastResults>> result;
    map<string, map<string, SyncInfo>> ret;
    if (accountId.empty()) {
        ThrowAniError(
            CloudService::Status::INVALID_ARGUMENT_V20, "The type of accountId must be string and not empty.");
        return ret;
    }
    if (bundleInfos.empty()) {
        ThrowAniError(
            CloudService::Status::INVALID_ARGUMENT_V20, "The type of bundleInfos must be array and not empty.");
        return ret;
    }
    if (bundleInfos.size() > 30) { // 30 is max bundleInfos size
        ThrowAniError(
            CloudService::Status::INVALID_ARGUMENT_V20, "The size of bundleInfos must be less than or equal to 30.");
        return ret;
    }

    std::vector<OHOS::CloudData::BundleInfo> nativeBundleInfos;
    for (auto &info : bundleInfos) {
        OHOS::CloudData::BundleInfo nativeInfo;
        nativeInfo.bundleName = std::string(info.bundleName);
        if (info.storeId.has_value()) {
            nativeInfo.storeId = std::string(info.storeId.value());
        }
        nativeBundleInfos.push_back(nativeInfo);
    }

    auto work = [&accountId, &nativeBundleInfos, &result](std::shared_ptr<CloudService> proxy) {
        result = proxy->QueryLastSyncInfoBatch(std::string(accountId), nativeBundleInfos);
    };
    RequestIPC(work);
    int errCode = CloudService::Status::ERROR;
    if (result.has_value()) {
        errCode = result.value().first;
        auto batchSyncInfo = ConvertBatchSyncInfo(result.value().second);
        if (!batchSyncInfo.first) {
            LOG_ERROR(" ConvertBatchSyncInfo failed");
        }
        ret = batchSyncInfo.second;
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
            LOG_ERROR("request, errCode = %{public}d", code);
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
            LOG_ERROR("request, errCode = %{public}d", code);
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
            LOG_ERROR("request, errCode = %{public}d", code);
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
            LOG_ERROR("request, errcode = %{public}d", code);
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
            LOG_ERROR("request, errcode = %{public}d", status);
            ThrowAniError(status);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::OnSyncInfoChanged(array_view<::ohos::data::cloudData::BundleInfo> bundleInfos,
    callback_view<void(map_view<string, map<string, SyncInfo>> data)> progress)
{
    if (bundleInfos.empty() || bundleInfos.size() > 30) { // 30 is max bundleInfos size
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT_V20,
            "The size of bundleInfos must be less than or equal to 30 and greater than 0.");
        return;
    }
    std::vector<OHOS::CloudData::BundleInfo> nativeBundleInfos;
    for (auto &info : bundleInfos) {
        OHOS::CloudData::BundleInfo nativeInfo;
        nativeInfo.bundleName = std::string(info.bundleName);
        if (info.storeId.has_value()) {
            nativeInfo.storeId = std::string(info.storeId.value());
        }
        nativeBundleInfos.push_back(nativeInfo);
    }
    TaiheSyncInfoCallback holder = progress;
    std::vector<OHOS::CloudData::BundleInfo> toSubscribe = CollectSubscribeInfos(nativeBundleInfos, holder);
    if (toSubscribe.empty()) {
        LOG_DEBUG("Duplicate subscribe for sync info changed.");
        return;
    }
    auto observer = std::make_shared<TaiheCloudSyncInfoObserver>(holder);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (proxy == nullptr) {
        if (state != CloudService::SERVER_UNAVAILABLE) {
            state = CloudService::NOT_SUPPORT;
        }
        LOG_ERROR("proxy is NULL");
        ThrowAniError(state);
        return;
    }
    auto status = proxy->Subscribe(CloudSubscribeType::SYNC_INFO_CHANGED, toSubscribe, observer);
    if (status != CloudService::Status::SUCCESS) {
        LOG_ERROR("Subscribe failed, errcode = %{public}d", status);
        ThrowAniError(status);
        return;
    }
    std::lock_guard<std::mutex> lock(syncInfoObserversMutex_);
    for (auto &bundleInfo : toSubscribe) {
        syncInfoObservers_[bundleInfo.bundleName][bundleInfo.storeId].push_back(observer);
    }
}

std::vector<OHOS::CloudData::BundleInfo> ConfigImpl::CollectSubscribeInfos(
    const std::vector<OHOS::CloudData::BundleInfo> &toSubscribe, const TaiheSyncInfoCallback &callback)
{
    std::lock_guard<std::mutex> lock(syncInfoObserversMutex_);
    std::vector<OHOS::CloudData::BundleInfo> result;
    for (const auto &info : toSubscribe) {
        auto bundleIt = syncInfoObservers_.find(info.bundleName);
        if (bundleIt == syncInfoObservers_.end()) {
            result.push_back(info);
            continue;
        }
        auto storeIt = bundleIt->second.find(info.storeId);
        if (storeIt == bundleIt->second.end()) {
            result.push_back(info);
            continue;
        }

        bool isDuplicate = std::any_of(storeIt->second.begin(), storeIt->second.end(),
            [&callback](const std::shared_ptr<TaiheCloudSyncInfoObserver> &observer) {
                if (observer == nullptr) {
                    return false;
                }
                return *observer == callback;
            });
        if (isDuplicate) {
            LOG_DEBUG("Duplicate subscribe for bundleName:%{public}s storeId:%{public}.3s",
                info.bundleName.c_str(), info.storeId.c_str());
            continue;
        }
        result.push_back(info);
    }
    return result;
}

void ConfigImpl::OffSyncInfoChanged(array_view<::ohos::data::cloudData::BundleInfo> bundleInfos,
    optional_view<callback<void(map_view<string, map<string, SyncInfo>> data)>> progress)
{
    if (bundleInfos.empty() || bundleInfos.size() > 30) { // 30 is max bundleInfos size
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT_V20,
            "The size of bundleInfos must be less than or equal to 30 and greater than 0.");
        return;
    }

    std::vector<OHOS::CloudData::BundleInfo> nativeBundleInfos;
    for (auto &info : bundleInfos) {
        OHOS::CloudData::BundleInfo nativeInfo;
        nativeInfo.bundleName = std::string(info.bundleName);
        if (info.storeId.has_value()) {
            nativeInfo.storeId = std::string(info.storeId.value());
        }
        nativeBundleInfos.push_back(nativeInfo);
    }

    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (proxy == nullptr) {
        if (state != CloudService::SERVER_UNAVAILABLE) {
            state = CloudService::NOT_SUPPORT;
        }
        ThrowAniError(state);
        return;
    }

    auto unsubscribeInfos = CollectUnsubscribeInfos(nativeBundleInfos, progress);
    for (const auto &[observer, infos] : unsubscribeInfos) {
        proxy->Unsubscribe(CloudSubscribeType::SYNC_INFO_CHANGED, infos, observer);
    }
}

ConfigImpl::UnsubscribeInfo ConfigImpl::CollectUnsubscribeInfos(
    const std::vector<OHOS::CloudData::BundleInfo> &toUnsubscribe,
    optional_view<callback<void(map_view<string, map<string, SyncInfo>> data)>> progress)
{
    bool hasCallback = progress.has_value();
    UnsubscribeInfo unsubscribeInfos;
    std::lock_guard<std::mutex> lock(syncInfoObserversMutex_);
    for (const auto &info : toUnsubscribe) {
        auto bundleIt = syncInfoObservers_.find(info.bundleName);
        if (bundleIt == syncInfoObservers_.end()) {
            continue;
        }
        auto storeIt = bundleIt->second.find(info.storeId);
        if (storeIt == bundleIt->second.end()) {
            continue;
        }
        auto obsIt = storeIt->second.begin();
        while (obsIt != storeIt->second.end()) {
            if (*obsIt == nullptr) {
                obsIt = storeIt->second.erase(obsIt);
                continue;
            }
            if (hasCallback && !(**obsIt == progress.value())) {
                ++obsIt;
                continue;
            }
            unsubscribeInfos[*obsIt].push_back(info);
            obsIt = storeIt->second.erase(obsIt);
        }
        if (storeIt->second.empty()) {
            bundleIt->second.erase(storeIt);
        }
        if (bundleIt->second.empty()) {
            syncInfoObservers_.erase(bundleIt);
        }
    }
    return unsubscribeInfos;
}

void ConfigImpl::StopCloudSyncImpl(array_view<::ohos::data::cloudData::BundleInfo> bundleInfos)
{
    if (bundleInfos.empty()) {
        ThrowAniError(CloudService::Status::INVALID_ARGUMENT,
            "The type of bundleInfos must be Array<BundleInfo> and not empty.");
        return;
    }

    std::vector<OHOS::CloudData::BundleInfo> nativeBundleInfos;
    for (const auto &info : bundleInfos) {
        OHOS::CloudData::BundleInfo nativeInfo;
        nativeInfo.bundleName = std::string(info.bundleName);
        if (info.storeId.has_value()) {
            nativeInfo.storeId = std::string(info.storeId.value());
        }
        nativeBundleInfos.push_back(std::move(nativeInfo));
    }

    auto work = [&nativeBundleInfos](std::shared_ptr<CloudService> proxy) {
        int32_t code = proxy->StopCloudSyncTask(nativeBundleInfos);
        LOG_DEBUG("StopCloudSyncTask return %{public}d", code);
        if (code != CloudService::Status::SUCCESS) {
            ThrowAniError(code);
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
            LOG_ERROR("request, errcode = %{public}d", code);
            ThrowAniError(code);
        }
    };
    RequestIPC(work);
}

void ConfigImpl::OnAutoSyncTrigger(::taihe::callback_view<void(TaiheCloudSyncTriggerInfo const& data)> observer)
{
    TaiheSyncTriggerCallback holder = observer;
    {
        std::lock_guard<std::mutex> lock(autoSyncTriggerObserversMutex_);
        bool isDuplicate = std::any_of(autoSyncTriggerObservers_.begin(), autoSyncTriggerObservers_.end(),
            [&holder](const std::shared_ptr<TaiheCloudSyncTriggerObserver> &obs) {
                return *obs == holder;
            });
        if (isDuplicate) {
            LOG_DEBUG("Duplicate subscribe for auto sync trigger.");
            return;
        }
    }

    auto obs = std::make_shared<TaiheCloudSyncTriggerObserver>(observer);
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (proxy == nullptr) {
        if (state != CloudService::SERVER_UNAVAILABLE) {
            state = CloudService::NOT_SUPPORT;
        }
        LOG_ERROR("proxy is NULL");
        ThrowAniError(state);
        return;
    }
    auto status = proxy->SubscribeCloudSyncTrigger(obs);
    if (status != CloudService::Status::SUCCESS) {
        LOG_ERROR("SubscribeCloudSyncTrigger failed, errcode = %{public}d", status);
        ThrowAniError(status);
        return;
    }
    std::lock_guard<std::mutex> lock(autoSyncTriggerObserversMutex_);
    autoSyncTriggerObservers_.push_back(obs);
}

void ConfigImpl::OffAutoSyncTrigger(
    ::taihe::optional_view<::taihe::callback<void(TaiheCloudSyncTriggerInfo const& data)>> observer)
{
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (proxy == nullptr) {
        if (state != CloudService::SERVER_UNAVAILABLE) {
            state = CloudService::NOT_SUPPORT;
        }
        ThrowAniError(state);
        return;
    }

    if (!observer.has_value()) {
        proxy->UnSubscribeCloudSyncTrigger(nullptr);
        std::lock_guard<std::mutex> lock(autoSyncTriggerObserversMutex_);
        autoSyncTriggerObservers_.clear();
        return;
    }

    TaiheSyncTriggerCallback holder = observer.value();
    std::shared_ptr<TaiheCloudSyncTriggerObserver> targetObserver;
    {
        std::lock_guard<std::mutex> lock(autoSyncTriggerObserversMutex_);
        auto it = std::find_if(autoSyncTriggerObservers_.begin(), autoSyncTriggerObservers_.end(),
            [&holder](const std::shared_ptr<TaiheCloudSyncTriggerObserver> &obs) {
                return *obs == holder;
            });
        if (it != autoSyncTriggerObservers_.end()) {
            targetObserver = *it;
            autoSyncTriggerObservers_.erase(it);
        }
    }

    if (targetObserver != nullptr) {
        proxy->UnSubscribeCloudSyncTrigger(targetObserver);
    }
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
TH_EXPORT_CPP_API_QueryLastSyncInfoBatchImpl(AniCloudData::ConfigImpl::QueryLastSyncInfoBatchImpl);
TH_EXPORT_CPP_API_ClearImpl(AniCloudData::ConfigImpl::ClearImpl);
TH_EXPORT_CPP_API_ChangeAppCloudSwitchImplWithConfig(AniCloudData::ConfigImpl::ChangeAppCloudSwitchImplWithConfig);
TH_EXPORT_CPP_API_ClearImplWithConfig(AniCloudData::ConfigImpl::ClearImplWithConfig);
TH_EXPORT_CPP_API_SetGlobalCloudStrategyImpl(AniCloudData::ConfigImpl::SetGlobalCloudStrategyImpl);
TH_EXPORT_CPP_API_CloudSyncImpl(AniCloudData::ConfigImpl::CloudSyncImpl);
TH_EXPORT_CPP_API_OnSyncInfoChanged(AniCloudData::ConfigImpl::OnSyncInfoChanged);
TH_EXPORT_CPP_API_OffSyncInfoChanged(AniCloudData::ConfigImpl::OffSyncInfoChanged);
TH_EXPORT_CPP_API_SetCloudStrategyImpl(AniCloudData::SetCloudStrategyImpl);
TH_EXPORT_CPP_API_OnAutoSyncTrigger(AniCloudData::ConfigImpl::OnAutoSyncTrigger);
TH_EXPORT_CPP_API_OffAutoSyncTrigger(AniCloudData::ConfigImpl::OffAutoSyncTrigger);
TH_EXPORT_CPP_API_StopCloudSyncImpl(AniCloudData::ConfigImpl::StopCloudSyncImpl);

// NOLINTEND
