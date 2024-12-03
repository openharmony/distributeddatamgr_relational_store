/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "RdbStoreManager"
#include "rdb_store_manager.h"

#include <algorithm>
#include <cinttypes>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_radar_reporter.h"
#include "rdb_store_impl.h"
#include "rdb_trace.h"
#include "sqlite_global_config.h"
#include "task_executor.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#if !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "rdb_manager_impl.h"
#include "rdb_security_manager.h"
#endif
#include "security_policy.h"
#endif
#include "rdb_fault_hiview_reporter.h"
#include "sqlite_utils.h"
#include "string_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Reportor = RdbFaultHiViewReporter;
__attribute__((used))
const bool RdbStoreManager::regCollector_ = RdbFaultHiViewReporter::RegCollector(RdbStoreManager::Collector);
RdbStoreManager &RdbStoreManager::GetInstance()
{
    static RdbStoreManager manager;
    return manager;
}

RdbStoreManager::~RdbStoreManager()
{
    Clear();
}

RdbStoreManager::RdbStoreManager() : configCache_(BUCKET_MAX_SIZE)
{
}

std::shared_ptr<RdbStoreImpl> RdbStoreManager::GetStoreFromCache(const RdbStoreConfig &config, const std::string &path)
{
    auto it = storeCache_.find(path);
    if (it == storeCache_.end()) {
        return nullptr;
    }
    std::shared_ptr<RdbStoreImpl> rdbStore = it->second.lock();
    if (rdbStore == nullptr) {
        storeCache_.erase(it);
        return nullptr;
    }
    auto oldConfig = rdbStore->GetConfig();
    if (oldConfig != config) {
        storeCache_.erase(it);
        LOG_INFO("app[%{public}s:%{public}s] path[%{public}s]"
                 " cfg[%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}s]"
                 " %{public}s",
            config.GetBundleName().c_str(), config.GetModuleName().c_str(), SqliteUtils::Anonymous(path).c_str(),
            config.GetDBType(), config.GetHaMode(), config.IsEncrypt(), config.GetArea(), config.GetSecurityLevel(),
            config.GetRoleType(), config.IsReadOnly(), config.GetCustomDir().c_str(),
            Reportor::FormatBrief(Connection::Collect(config), SqliteUtils::Anonymous(config.GetName())).c_str());
        return nullptr;
    }
    return rdbStore;
}

std::shared_ptr<RdbStore> RdbStoreManager::GetRdbStore(
    const RdbStoreConfig &config, int &errCode, int version, RdbOpenCallback &openCallback)
{
    // TOD this lock should only work on storeCache_, add one more lock for connectionpool
    errCode = E_OK;
    std::lock_guard<std::mutex> lock(mutex_);
    if (config.GetRoleType() == VISITOR_WRITE && !IsPermitted(GetSyncParam(config))) {
        errCode = E_ERROR;
        return nullptr;
    }
    RdbStoreConfig modifyConfig = config;
    auto path = config.GetRoleType() != OWNER ? config.GetVisitorDir() : config.GetPath();
    if (modifyConfig.GetRoleType() == OWNER && IsConfigInvalidChanged(path, modifyConfig)) {
        errCode = E_CONFIG_INVALID_CHANGE;
        return nullptr;
    }
    std::shared_ptr<RdbStoreImpl> rdbStore = GetStoreFromCache(modifyConfig, path);
    if (rdbStore != nullptr) {
        return rdbStore;
    }
    rdbStore = std::make_shared<RdbStoreImpl>(modifyConfig, errCode);
    if (errCode != E_OK && modifyConfig != config) {
        LOG_WARN("Failed to GetRdbStore using modifyConfig. path:%{public}s, rc=%{public}d",
            SqliteUtils::Anonymous(path).c_str(), errCode);
        rdbStore = std::make_shared<RdbStoreImpl>(config, errCode);  // retry with input config
    }
    if (errCode != E_OK) {
        LOG_ERROR("GetRdbStore failed. path:%{public}s, rc=%{public}d",
            SqliteUtils::Anonymous(path).c_str(), errCode);
        return nullptr;
    }

    if (modifyConfig.GetRoleType() == OWNER && !modifyConfig.IsReadOnly()) {
        errCode = SetSecurityLabel(modifyConfig);
        if (errCode != E_OK) {
            return nullptr;
        }
        (void)rdbStore->ExchangeSlaverToMaster();
        errCode = ProcessOpenCallback(*rdbStore, modifyConfig, version, openCallback);
        if (errCode != E_OK) {
            LOG_ERROR("fail, storeName:%{public}s path:%{public}s ProcessOpenCallback errCode:%{public}d",
                SqliteUtils::Anonymous(modifyConfig.GetName()).c_str(),
                SqliteUtils::Anonymous(modifyConfig.GetPath()).c_str(), errCode);
            return nullptr;
        }
    }
    storeCache_.insert_or_assign(std::move(path), rdbStore);
    return rdbStore;
}

bool RdbStoreManager::IsConfigInvalidChanged(const std::string &path, RdbStoreConfig &config)
{
    if (config.GetBundleName().empty()) {
        LOG_WARN("Config has no bundleName, path: %{public}s", SqliteUtils::Anonymous(path).c_str());
        return false;
    }
    Param lastParam;
    if (!configCache_.Get(path, lastParam) && GetParamFromService(lastParam) != E_OK) {
        LOG_WARN("Not found config cache, path: %{public}s", SqliteUtils::Anonymous(path).c_str());
        return false;
    };
    bool isLevelInvalidChange = (static_cast<int32_t>(config.GetSecurityLevel()) > lastParam.level_);
    bool isEncryptInvalidChange = (config.IsEncrypt() != lastParam.isEncrypt_);
    bool isAreaInvalidChange = (config.GetArea() != lastParam.area_);
    if (isLevelInvalidChange || isEncryptInvalidChange || isAreaInvalidChange) {
        LOG_WARN("Store config invalid change, storePath %{public}s, securitylevel: %{public}d -> %{public}d, "
                 "area: %{public}d -> %{public}d, isEncrypt: %{public}d -> %{public}d",
            SqliteUtils::Anonymous(path).c_str(), lastParam.level_, static_cast<int32_t>(config.GetSecurityLevel()),
            lastParam.area_, config.GetArea(), lastParam.isEncrypt_, config.IsEncrypt());
        if (isEncryptInvalidChange) {
            config.SetEncryptStatus(lastParam.isEncrypt_);
        }
    }
    return false;
}

DistributedRdb::RdbSyncerParam RdbStoreManager::GetSyncParam(const RdbStoreConfig &config)
{
    DistributedRdb::RdbSyncerParam syncerParam;
    syncerParam.bundleName_ = config.GetBundleName();
    syncerParam.hapName_ = config.GetModuleName();
    syncerParam.storeName_ = config.GetName();
    syncerParam.customDir_ = config.GetCustomDir();
    syncerParam.area_ = config.GetArea();
    syncerParam.level_ = static_cast<int32_t>(config.GetSecurityLevel());
    syncerParam.isEncrypt_ = config.IsEncrypt();
    syncerParam.isAutoClean_ = config.GetAutoClean();
    syncerParam.isSearchable_ = config.IsSearchable();
    syncerParam.roleType_ = config.GetRoleType();
    syncerParam.haMode_ = config.GetHaMode();
    syncerParam.tokenIds_ = config.GetPromiseInfo().tokenIds_;
    syncerParam.uids_ = config.GetPromiseInfo().uids_;
    syncerParam.user_ = config.GetPromiseInfo().user_;
    syncerParam.permissionNames_ = config.GetPromiseInfo().permissionNames_;
    return syncerParam;
}

int32_t RdbStoreManager::GetParamFromService(DistributedRdb::RdbSyncerParam &param)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
    if (err == E_NOT_SUPPORT) {
        return E_ERROR;
    }
    if (err != E_OK || service == nullptr) {
        LOG_ERROR("GetRdbService failed, err is %{public}d.", err);
        return E_ERROR;
    }
    err = service->BeforeOpen(param);
    return err != DistributedRdb::RDB_OK ? E_ERROR : E_OK;
#endif
    return E_ERROR;
}

bool RdbStoreManager::IsPermitted(const DistributedRdb::RdbSyncerParam &param)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
    if (err == E_NOT_SUPPORT) {
        return false;
    }
    if (err != E_OK || service == nullptr) {
        LOG_ERROR("GetRdbService failed, bundleName:%{public}s, err:%{public}d.", param.bundleName_.c_str(), err);
        return false;
    }
    err = service->VerifyPromiseInfo(param);
    if (err == DistributedRdb::RDB_OK) {
        return true;
    }
    LOG_ERROR("failed, bundleName:%{public}s, store:%{public}s, err:%{public}d.", param.bundleName_.c_str(),
        SqliteUtils::Anonymous(param.storeName_).c_str(), err);
#endif
    return false;
}

void RdbStoreManager::Clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = storeCache_.begin();
    while (iter != storeCache_.end()) {
        iter = storeCache_.erase(iter);
    }
    storeCache_.clear();
}

bool RdbStoreManager::Remove(const std::string &path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    configCache_.Delete(path);
    if (storeCache_.find(path) != storeCache_.end()) {
        if (storeCache_[path].lock()) {
            LOG_INFO("store in use by %{public}ld holders", storeCache_[path].lock().use_count());
        }
        storeCache_.erase(path); // clean invalid store ptr
        return true;
    }

    return false;
}

int RdbStoreManager::ProcessOpenCallback(
    RdbStore &rdbStore, const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errCode = E_OK;
    if (version == -1) {
        return errCode;
    }

    int currentVersion;
    errCode = rdbStore.GetVersion(currentVersion);
    if (errCode != E_OK) {
        return errCode;
    }

    if (version == currentVersion) {
        return openCallback.OnOpen(rdbStore);
    }

    if (currentVersion == 0) {
        errCode = openCallback.OnCreate(rdbStore);
    } else if (version > currentVersion) {
        errCode = openCallback.OnUpgrade(rdbStore, currentVersion, version);
    } else {
        errCode = openCallback.OnDowngrade(rdbStore, currentVersion, version);
    }

    if (errCode == E_OK) {
        errCode = rdbStore.SetVersion(version);
    }

    if (errCode != E_OK) {
        LOG_ERROR("RdbHelper ProcessOpenCallback set new version failed.");
        return errCode;
    }

    return openCallback.OnOpen(rdbStore);
}

bool RdbStoreManager::Delete(const std::string &path)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto tokens = StringUtils::Split(path, "/");
    if (!tokens.empty()) {
        DistributedRdb::RdbSyncerParam param;
        param.storeName_ = *tokens.rbegin();
        auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
        if (err != E_OK || service == nullptr) {
            LOG_DEBUG("GetRdbService failed, err is %{public}d.", err);
            return Remove(path);
        }
        err = service->Delete(param);
        if (err != E_OK) {
            LOG_ERROR("service delete store, storeName:%{public}s, err = %{public}d",
                SqliteUtils::Anonymous(param.storeName_).c_str(), err);
            return Remove(path);
        }
    }
#endif
    return Remove(path);
}

int RdbStoreManager::SetSecurityLabel(const RdbStoreConfig &config)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    return SecurityPolicy::SetSecurityLabel(config);
#endif
    return E_OK;
}

std::map<std::string, RdbStoreManager::Info> RdbStoreManager::Collector(const RdbStoreConfig &config)
{
    std::map<std::string, Info> debugInfos;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    Param param = GetSyncParam(config);
    auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
    if (err != E_OK || service == nullptr) {
        LOG_DEBUG("GetRdbService failed, err is %{public}d.", err);
        return std::map<std::string, Info>();
    }
    err = service->GetDebugInfo(param, debugInfos);
    if (err != E_OK) {
        LOG_ERROR("GetDebugInfo failed, storeName:%{public}s, err = %{public}d",
            SqliteUtils::Anonymous(param.storeName_).c_str(), err);
        return std::map<std::string, Info>();
    }
#endif
    return debugInfos;
}
} // namespace NativeRdb
} // namespace OHOS
