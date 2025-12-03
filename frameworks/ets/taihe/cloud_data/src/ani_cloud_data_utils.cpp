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
#define LOG_TAG "AniCloudDataUtils"
#include "ani_cloud_data_utils.h"
#include "logger.h"
#include "ani_error_code.h"

namespace AniCloudData {
using namespace OHOS::Rdb;
void RequestIPC(std::function<void(std::shared_ptr<CloudService>)> work)
{
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (proxy == nullptr) {
        if (state != CloudService::SERVER_UNAVAILABLE) {
            state = CloudService::NOT_SUPPORT;
        }
        LOG_ERROR("proxy is NULL");
        ThrowAniError(state);
        return;
    }
    work(proxy);
}

OHOS::CloudData::DBSwitchInfo ConvertTaiheDbSwitchInfo(::ohos::data::cloudData::DBSwitchInfo dbSwitchInfo)
{
    OHOS::CloudData::DBSwitchInfo dbInfo;
    std::map<std::string, bool> info;
    auto tableInfo = dbSwitchInfo.tableInfo;
    if (tableInfo.has_value()) {
        for (auto &item : tableInfo.value()) {
            info.emplace(std::string(item.first), item.second);
        }
        dbInfo.tableInfo = info;
    }
    dbInfo.enable = dbSwitchInfo.enable;
    return dbInfo;
}

OHOS::CloudData::ClearConfig ConvertTaiheClearConfig(::ohos::data::cloudData::ClearConfig clearConfig)
{
    OHOS::CloudData::ClearConfig config;
    std::map<std::string, OHOS::CloudData::DBActionInfo> dbInfo;
    for (auto &item : clearConfig.dbInfo) {
        auto actionInfo = ConvertTaiheDbActionInfo(item.second);
        dbInfo.emplace(std::string(item.first), std::move(actionInfo));
    }
    config.dbInfo = dbInfo;
    return config;
}

OHOS::CloudData::DBActionInfo ConvertTaiheDbActionInfo(::ohos::data::cloudData::DBActionInfo actionInfo)
{
    OHOS::CloudData::DBActionInfo dbActionInfo;
    std::map<std::string, int32_t> info;
    auto tableInfo = actionInfo.tableInfo;
    if (tableInfo.has_value()) {
        for (auto &item : tableInfo.value()) {
            info.emplace(std::string(item.first), item.second.get_value());
        }
        dbActionInfo.tableInfo = info;
    }
    dbActionInfo.action = actionInfo.action.get_value();
    return dbActionInfo;
}
}  // namespace
