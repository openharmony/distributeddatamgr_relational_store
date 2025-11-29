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

namespace AniCloudData {
using namespace OHOS::Rdb;
void ConfigImpl::ChangeAppCloudSwitchImpl(string_view accountId, string_view bundleName, bool status)
{
    auto work = [&accountId, &bundleName, &status](std::shared_ptr<CloudService> proxy) {
        int32_t code = proxy->ChangeAppSwitch(std::string(accountId), std::string(bundleName), status);
        if (code != CloudService::Status::SUCCESS) {
            LOG_ERROR("request, errcode = %{public}d", code);
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
        for (auto const &item : appActions) {
            if (item.first.empty()) {
                LOG_ERROR("Invalid bundle name length");
                ThrowAniError(CloudService::Status::INVALID_ARGUMENT);
                return;
            }
            actions[std::string(item.first)] = item.second.get_value();
        }

        int32_t code = proxy->Clean(std::string(accountId), actions);
        if (code != CloudService::Status::SUCCESS) {
            LOG_ERROR("request, errcode = %{public}d", code);
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

// NOLINTEND
