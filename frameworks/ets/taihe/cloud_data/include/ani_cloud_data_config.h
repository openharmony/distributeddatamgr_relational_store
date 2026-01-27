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
#ifndef OHOS_RELATION_STORE_ANI_CLOUD_DATA_CONFIG_H
#define OHOS_RELATION_STORE_ANI_CLOUD_DATA_CONFIG_H
#include <functional>
#include "ohos.data.cloudData.proj.hpp"
#include "ohos.data.cloudData.impl.hpp"
#include "ohos.data.cloudData.sharing.proj.hpp"
#include "ohos.data.cloudData.sharing.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "cloud_service.h"
#include "cloud_manager.h"

namespace AniCloudData {
using namespace OHOS::CloudData;
using namespace ::taihe;
using namespace ::ohos::data::cloudData;
using namespace ::ohos::data::cloudData::sharing;
using namespace ::ohos::data::relationalStore;
using TaiHeStatisticInfo = ::ohos::data::cloudData::StatisticInfo;
using TaiHeParticipant = ohos::data::cloudData::sharing::Participant;
using TaiHeResult = ::ohos::data::cloudData::sharing::Result;
class ConfigImpl {
public:
    static void EnableCloudImpl(string_view accountId, map_view<string, bool> switches);
    static void DisableCloudImpl(string_view accountId);
    static void ChangeAppCloudSwitchImpl(string_view accountId, string_view bundleName, bool status);
    static void NotifyDataChangeOptional(const ExtraData &extInfo, optional_view<int32_t> userId);
    static void NotifyDataChangeImpl(const ExtraData &extInfo);
    static void NotifyDataChangeWithId(const ExtraData &extInfo, int32_t userId);
    static void NotifyDataChangeBoth(string_view accountId, string_view bundleName);
    static map<string, array<TaiHeStatisticInfo>> QueryStatisticsImpl(string_view accountId, string_view bundleName,
        optional_view<string> storeId);
    static map<string, SyncInfo> QueryLastSyncInfoImpl(string_view accountId, string_view bundleName,
        optional_view<string> storeId);
    static void ClearImpl(string_view accountId, map_view<string, ClearAction> appActions);
    static void ChangeAppCloudSwitchImplWithConfig(string_view accountId, string_view bundleName, bool status,
        optional_view<::ohos::data::cloudData::SwitchConfig> config);
    static void ClearImplWithConfig(string_view accountId, map_view<string, ClearAction> appActions,
        optional_view<map<::taihe::string, ::ohos::data::cloudData::ClearConfig>> config);
    static void SetGlobalCloudStrategyImpl(StrategyType strategy,
        optional_view<array<::ohos::data::commonType::ValueType>> param);
    static void CloudSyncImpl(string_view bundleName, string_view storeId, SyncMode mode,
        callback_view<void(const ProgressDetails &data)> progress);
};

void SetCloudStrategyImpl(StrategyType strategy,
    optional_view<array<::ohos::data::commonType::ValueType>> param);
} // namespace AniCloudData
#endif