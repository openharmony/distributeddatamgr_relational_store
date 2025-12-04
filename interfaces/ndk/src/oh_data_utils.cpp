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

#include "oh_data_utils.h"

#include <fstream>
#include <sstream>

#include "logger.h"
#include "rdb_helper.h"
#include "rdb_sql_utils.h"

using namespace OHOS::NativeRdb;
namespace OHOS::RdbNdk {
static constexpr const char *TRUSTS_CONF_PATH = "/system/etc/trusts/conf/";
static constexpr const char *TRUSTS_CONFIG_JSON_PATH = "trusts_config.json";
bool Utils::isInited_ = false;
bool Utils::flag_ = false;
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

bool Utils::TrustsProxy::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(bundleName)], bundleName);
    return true;
}
 
bool Utils::TrustsProxy::Unmarshal(const Serializable::json &node)
{
    GetValue(node, GET_NAME(bundleName), bundleName);
    return true;
}

bool Utils::IsContainTerminator()
{
    if (isInited_) {
        return flag_;
    }
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    if (isInited_) {
        return flag_;
    }
    std::ifstream fin(std::string(TRUSTS_CONF_PATH) + std::string(TRUSTS_CONFIG_JSON_PATH));
    if (!fin.good()) {
        LOG_ERROR("Failed to open silent json file");
        return flag_;
    }
    std::string jsonStr;
    while (fin.good()) {
        std::string line;
        std::getline(fin, line);
        jsonStr += line;
    }

    Utils::TrustsProxy trustsProxy;
    trustsProxy.Unmarshall(jsonStr);
    fin.close();
    if (!trustsProxy.bundleName.empty() &&
        trustsProxy.bundleName == OHOS::NativeRdb::RdbHelper::GetSelfBundleName()) {
        flag_ = true;
    }
    isInited_ = true;
    return flag_;
}

bool Utils::IsValidContext(const OH_RDB_ReturningContext *context)
{
    if (context == nullptr || context->cursor != nullptr) {
        LOG_ERROR("context or cursor is nullptr.");
        return false;
    }
    if (!context->IsValid()) {
        LOG_ERROR("invalid context.");
        return false;
    }
    return !(context->config.columns.empty() ||
             context->config.maxReturningCount == OHOS::NativeRdb::ReturningConfig::ILLEGAL_RETURNING_COUNT);
}

bool Utils::IsValidRows(const OH_Data_VBuckets *rows)
{
    if (rows == nullptr) {
        LOG_ERROR("rows is null data.");
        return false;
    }
    if (!rows->IsValid()) {
        LOG_ERROR("invalid rows.");
        return false;
    }
    return true;
}

bool Utils::IsValidResolution(Rdb_ConflictResolution resolution)
{
    if (resolution < Rdb_ConflictResolution::RDB_CONFLICT_NONE ||
        resolution > Rdb_ConflictResolution::RDB_CONFLICT_REPLACE) {
        LOG_ERROR("resolution is not valid. %{public}d", resolution);
        return false;
    }
    return true;
}

bool Utils::IsValidTableName(const char *table)
{
    if (table == nullptr) {
        LOG_ERROR("table is nullptr.");
        return false;
    }
    return RdbSqlUtils::IsValidTableName(table);
}

bool Utils::IsValidRdbValuesBucket(OHOS::RdbNdk::RelationalValuesBucket *rdbValuesBucket)
{
    if (rdbValuesBucket == nullptr) {
        LOG_ERROR("rdbValuesBucket is nullptr.");
        return false;
    }
    return !RdbSqlUtils::HasDuplicateAssets(rdbValuesBucket->Get());
}

} // namespace OHOS::RdbNdk