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
#define LOG_TAG "OhDataUtils"

#include <sstream>
#include <fstream>

#include "oh_data_utils.h"
#include "rdb_helper.h"
#include "logger.h"

namespace OHOS::RdbNdk {
static constexpr const char *TRUSTLIST_CONF_PATH = "/system/etc/trustlist/conf/";
static constexpr const char *TRUSTLIST_CONFIG_JSON_PATH = "trustlist_config.json";
std::optional<bool> Utils::flag_;
std::mutex Utils::mutex_;
NativeRdb::ConflictResolution Utils::ConvertConflictResolution(Rdb_ConflictResolution resolution)
{
    switch (resolution) {
        case RDB_CONFLICT_NONE:
            return NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
        case RDB_CONFLICT_ROLLBACK:
            return NativeRdb::ConflictResolution::ON_CONFLICT_ROLLBACK;
        case RDB_CONFLICT_ABORT:
            return NativeRdb::ConflictResolution::ON_CONFLICT_ABORT;
        case RDB_CONFLICT_FAIL:
            return NativeRdb::ConflictResolution::ON_CONFLICT_FAIL;
        case RDB_CONFLICT_IGNORE:
            return NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE;
        case RDB_CONFLICT_REPLACE:
            return NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE;
        default:
            return NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
    }
}

bool Utils::TrustlistProxy::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(bundleName)], bundleName);
    return true;
}
 
bool Utils::TrustlistProxy::Unmarshal(const Serializable::json &node)
{
    GetValue(node, GET_NAME(bundleName), bundleName);
    return true;
}

bool Utils::IsContainTerminator()
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    if (flag_.has_value()) {
        return *flag_;
    }
    flag_ = false;
    std::ifstream fin(std::string(TRUSTLIST_CONF_PATH) + std::string(TRUSTLIST_CONFIG_JSON_PATH));
    if (!fin.good()) {
        LOG_ERROR("Failed to open silent json file");
        return *flag_;
    }
    std::string jsonStr;
    while (fin.good()) {
        std::string line;
        std::getline(fin, line);
        jsonStr += line;
    }

    Utils::TrustlistProxy trustlistProxy;
    trustlistProxy.Unmarshall(jsonStr);
    fin.close();
    if (!trustlistProxy.bundleName.empty() &&
        trustlistProxy.bundleName == OHOS::NativeRdb::RdbHelper::GetSelfBundleName()) {
        flag_ = true;
    }
    return *flag_;
}
} // namespace OHOS::RdbNdk