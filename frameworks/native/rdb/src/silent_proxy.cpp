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
#define LOG_TAG "SilentProxy"
#include "silent_proxy.h"

#include <fstream>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "rdb_manager.h"
#include "rdb_service.h"
#include "sqlite_utils.h"

namespace OHOS {
using Rdb::LogLabel;
namespace NativeRdb {
static constexpr const char *SILENT_CONF_PATH = "/system/etc/silent/conf/silentproxy_config.json";
static constexpr uint32_t BUCKET_MAX_SIZE = 4;

bool SilentProxys::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(silentProxys)], silentProxys);
    return true;
}

bool SilentProxys::Unmarshal(const Serializable::json &node)
{
    GetValue(node, GET_NAME(silentProxys), silentProxys);
    return true;
}

bool SilentProxy::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(bundleName)], bundleName);
    SetValue(node[GET_NAME(storeNames)], storeNames);
    return true;
}

bool SilentProxy::Unmarshal(const Serializable::json &node)
{
    GetValue(node, GET_NAME(bundleName), bundleName);
    GetValue(node, GET_NAME(storeNames), storeNames);
    return true;
}

SilentProxyManager::SilentProxyManager(const std::string &configPath) : isSilentCache_(BUCKET_MAX_SIZE)
{
    configPath_ = configPath.empty() ? SILENT_CONF_PATH : configPath;
}

std::pair<int32_t, bool> SilentProxyManager::IsSupportSilentFromProxy(
    const std::string &bundleName, const std::string &storeName)
{
    std::string key = bundleName + "proxy";
    std::map<std::string, bool> cacheConfig;
    std::string dbName = SqliteUtils::RemoveSuffix(storeName);

    if (isSilentCache_.Get(key, cacheConfig)) {
        return { E_OK, cacheConfig.count(dbName) != 0 };
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (isSilentCache_.Get(key, cacheConfig)) {
        return { E_OK, cacheConfig.count(dbName) != 0 };
    }

    SilentProxys silentProxys;
    std::ifstream fin(configPath_);
    if (!fin.is_open()) {
        LOG_ERROR("Failed to open silent json file");
        return { E_ERROR, false };
    }
    std::string line;
    std::string jsonStr;
    while (std::getline(fin, line)) {
        jsonStr += line;
    }
    if (!silentProxys.Unmarshall(jsonStr)) {
        LOG_ERROR("Failed to unmarshal silent json file");
        fin.close();
        return { E_ERROR, false };
    }
    fin.close();
    for (auto &silentProxy : silentProxys.silentProxys) {
        if (silentProxy.bundleName != bundleName) {
            continue;
        }
        for (auto &name : silentProxy.storeNames) {
            cacheConfig[name] = true;
        }
        break;
    }

    isSilentCache_.Set(key, cacheConfig);
    return { E_OK, cacheConfig.count(dbName) != 0 };
}

std::pair<int32_t, bool> SilentProxyManager::IsSupportSilentFromService(
    const std::string &bundleName, const std::string &storeName)
{
    std::string key = bundleName + "service";
    std::map<std::string, bool> cacheConfig;
    std::string dbName = SqliteUtils::RemoveSuffix(storeName);

    if (isSilentCache_.Get(key, cacheConfig)) {
        auto it = cacheConfig.find(dbName);
        if (it != cacheConfig.end()) {
            return { E_OK, it->second };
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (isSilentCache_.Get(key, cacheConfig)) {
        auto it = cacheConfig.find(dbName);
        if (it != cacheConfig.end()) {
            return { E_OK, it->second };
        }
    }

    DistributedRdb::RdbSyncerParam param;
    param.bundleName_ = bundleName;
    param.storeName_ = storeName;

    auto [err, service] = DistributedRdb::RdbManager::GetInstance().GetRdbService(param);
    if (err == E_NOT_SUPPORT) {
        cacheConfig[dbName] = false;
        isSilentCache_.Set(key, cacheConfig);
        return { err, false };
    }
    if (err != E_OK || service == nullptr) {
        LOG_ERROR("GetRdbService failed, err is %{public}d.", err);
        return { err, false };
    }
    auto [errcode, ret] = service->IsSupportSilent(param);
    if (errcode != DistributedRdb::RDB_OK) {
        return { E_ERROR, false };
    }
    if (ret) {
        RdbFaultHiViewReporter::ReportFault(
            RdbFaultEvent(RdbFaultType::FT_CURD, E_DFX_SILENT_PROXY_QUERY, bundleName, dbName));
    }
    cacheConfig[dbName] = ret;
    isSilentCache_.Set(key, cacheConfig);
    return { E_OK, ret };
}

std::pair<int32_t, bool> SilentProxyManager::IsSupportSilent(
    const std::string &bundleName, const std::string &storeName)
{
    auto [err, flag] = IsSupportSilentFromProxy(bundleName, storeName);
    if (err == E_OK && flag == true) {
        return { err, flag };
    }
    return IsSupportSilentFromService(bundleName, storeName);
}
} // namespace NativeRdb
} // namespace OHOS
