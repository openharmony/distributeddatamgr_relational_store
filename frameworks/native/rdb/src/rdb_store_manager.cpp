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

std::shared_ptr<RdbStoreImpl> RdbStoreManager::GetStoreFromCache(const std::string &path)
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
    return rdbStore;
}

std::shared_ptr<RdbStore> RdbStoreManager::GetRdbStore(
    const RdbStoreConfig &config, int &errCode, int version, RdbOpenCallback &openCallback)
{
    errCode = CheckConfig(config);
    if (errCode != E_OK) {
        return nullptr;
    }
    std::string path;
    errCode = SqliteGlobalConfig::GetDbPath(config, path);
    if (errCode != E_OK) {
        return nullptr;
    }
    // TOD this lock should only work on storeCache_, add one more lock for connectionPool
    std::lock_guard<std::mutex> lock(mutex_);
    std::shared_ptr<RdbStoreImpl> rdbStore = GetStoreFromCache(path);
    if (rdbStore != nullptr && rdbStore->GetConfig() == config) {
        return rdbStore;
    }
    if (rdbStore != nullptr) {
        auto log = RdbStoreConfig::FormatCfg(rdbStore->GetConfig(), config);
        LOG_WARN("Diff config! app[%{public}s:%{public}s] path[%{public}s] cfg[%{public}s]",
            config.GetBundleName().c_str(), config.GetModuleName().c_str(), SqliteUtils::Anonymous(path).c_str(),
            log.c_str());
        Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, E_CONFIG_INVALID_CHANGE, config, log));
        if (rdbStore->GetConfig().IsMemoryRdb() || config.IsMemoryRdb()) {
            errCode = E_CONFIG_INVALID_CHANGE;
            return nullptr;
        }
        storeCache_.erase(path);
        rdbStore = nullptr;
    }
    std::tie(errCode, rdbStore) = OpenStore(config, path);
    if (errCode != E_OK || rdbStore == nullptr) {
        return nullptr;
    }
    if (rdbStore->GetConfig().GetRoleType() == OWNER && !rdbStore->GetConfig().IsReadOnly()) {
        errCode = SetSecurityLabel(rdbStore->GetConfig());
        if (errCode != E_OK) {
            return nullptr;
        }
        (void)rdbStore->ExchangeSlaverToMaster();
        errCode = ProcessOpenCallback(*rdbStore, version, openCallback);
        if (errCode != E_OK) {
            LOG_ERROR("Callback fail, path:%{public}s code:%{public}d", SqliteUtils::Anonymous(path).c_str(), errCode);
            return nullptr;
        }
    }
    if (!rdbStore->GetConfig().IsMemoryRdb()) {
        configCache_.Set(path, GetSyncParam(rdbStore->GetConfig()));
    }
    storeCache_.insert_or_assign(std::move(path), rdbStore);
    return rdbStore;
}

bool RdbStoreManager::IsConfigInvalidChanged(const std::string &path, RdbStoreConfig &config)
{
    if (config.IsMemoryRdb()) {
        return false;
    }
    if (config.GetBundleName().empty()) {
        LOG_WARN("Config has no bundleName, path: %{public}s", SqliteUtils::Anonymous(path).c_str());
        return false;
    }
    Param lastParam = GetSyncParam(config);
    if (!configCache_.Get(path, lastParam) && GetParamFromService(lastParam) != E_OK) {
        LOG_WARN("Not found config cache, path: %{public}s", SqliteUtils::Anonymous(path).c_str());
        return false;
    };
    // The lastParam is possible that the same named db parameters of different paths when GetParamFromService
    if (lastParam.customDir_ != config.GetCustomDir() || lastParam.hapName_ != config.GetModuleName() ||
        lastParam.area_ != config.GetArea()) {
        LOG_WARN("Diff db with the same name! customDir:%{public}s -> %{public}s, hapName:%{public}s -> %{public}s,"
            "area:%{public}d -> %{public}d.", lastParam.customDir_.c_str(), config.GetCustomDir().c_str(),
            lastParam.hapName_.c_str(), config.GetModuleName().c_str(), lastParam.area_, config.GetArea());
        return false;
    }
    if (config.GetSecurityLevel() != SecurityLevel::LAST &&
        static_cast<int32_t>(config.GetSecurityLevel()) < lastParam.level_) {
        LOG_WARN("Illegal change, storePath %{public}s, securityLevel: %{public}d -> %{public}d",
            SqliteUtils::Anonymous(path).c_str(), lastParam.level_, static_cast<int32_t>(config.GetSecurityLevel()));
    }

    if (lastParam.isEncrypt_ != config.IsEncrypt()) {
        LOG_WARN("Reset encrypt, storePath %{public}s, input:%{public}d  original:%{public}d",
            SqliteUtils::Anonymous(path).c_str(), config.IsEncrypt(), lastParam.isEncrypt_);
        config.SetEncryptStatus(lastParam.isEncrypt_);
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
    syncerParam.subUser_ = config.GetSubUser();
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
#if !defined(CROSS_PLATFORM)
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

bool RdbStoreManager::Remove(const std::string &path, bool shouldClose)
{
    std::lock_guard<std::mutex> lock(mutex_);
    configCache_.Delete(path);
    auto it = storeCache_.find(path);
    if (it != storeCache_.end()) {
        auto rdbStore = it->second.lock();
        LOG_INFO("store in use by %{public}ld holders", storeCache_[path].lock().use_count());
        if (rdbStore && shouldClose) {
            rdbStore->Close();
        }
        storeCache_.erase(it); // clean invalid store ptr
        return true;
    }

    return false;
}

int RdbStoreManager::ProcessOpenCallback(RdbStore &rdbStore, int version, RdbOpenCallback &openCallback)
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

bool RdbStoreManager::Delete(const RdbStoreConfig &config, bool shouldClose)
{
    auto path = config.GetPath();
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto tokens = StringUtils::Split(path, "/");
    if (!tokens.empty()) {
        DistributedRdb::RdbSyncerParam param;
        param.bundleName_ = config.GetBundleName();
        param.storeName_ = *tokens.rbegin();
        param.subUser_ = config.GetSubUser();
        auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
        if (err != E_OK || service == nullptr) {
            LOG_DEBUG("GetRdbService failed, err is %{public}d.", err);
            return Remove(path, shouldClose);
        }
        err = service->Delete(param);
        if (err != E_OK) {
            LOG_ERROR("service delete store, storeName:%{public}s, err = %{public}d",
                SqliteUtils::Anonymous(param.storeName_).c_str(), err);
            return Remove(path, shouldClose);
        }
    }
#endif
    return Remove(path, shouldClose);
}

int RdbStoreManager::SetSecurityLabel(const RdbStoreConfig &config)
{
    if (config.IsMemoryRdb()) {
        return E_OK;
    }
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    return SecurityPolicy::SetSecurityLabel(config);
#endif
    return E_OK;
}

int32_t RdbStoreManager::Collector(const RdbStoreConfig &config, DebugInfos &debugInfos, DfxInfo &dfxInfo)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    Param param = GetSyncParam(config);
    auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
    if (err != E_OK || service == nullptr) {
        LOG_DEBUG("GetRdbService failed, err is %{public}d.", err);
        return E_ERROR;
    }

    err = service->GetDebugInfo(param, debugInfos);
    if (err != E_OK) {
        LOG_ERROR("GetDebugInfo failed, storeName:%{public}s, err = %{public}d",
            SqliteUtils::Anonymous(param.storeName_).c_str(), err);
        return E_ERROR;
    }

    err = service->GetDfxInfo(param, dfxInfo);
    if (err != E_OK) {
        LOG_ERROR("GetDfxInfo failed, storeName:%{public}s, err = %{public}d",
            SqliteUtils::Anonymous(param.storeName_).c_str(), err);
        return E_ERROR;
    }

#endif
    return E_OK;
}

int32_t RdbStoreManager::CheckConfig(const RdbStoreConfig &config)
{
    if (config.GetRoleType() == VISITOR_WRITE && !IsPermitted(GetSyncParam(config))) {
        return E_NOT_SUPPORT;
    }
    if (config.IsMemoryRdb()) {
        if (config.IsEncrypt() || config.IsVector() || config.GetRoleType() != OWNER ||
            config.GetHaMode() != HAMode::SINGLE || config.IsSearchable() || config.IsReadOnly() ||
            !config.GetDataGroupId().empty() || !config.GetCustomDir().empty()) {
            LOG_ERROR("not support!config:%{public}s", config.ToString().c_str());
            return E_NOT_SUPPORT;
        }
    }
    return E_OK;
}

std::pair<int32_t, std::shared_ptr<RdbStoreImpl>> RdbStoreManager::OpenStore(
    const RdbStoreConfig &config, const std::string &path)
{
    RdbStoreConfig modifyConfig = config;
    if (modifyConfig.GetRoleType() == OWNER && IsConfigInvalidChanged(path, modifyConfig)) {
        return { E_CONFIG_INVALID_CHANGE, nullptr };
    }

    std::pair<int32_t, std::shared_ptr<RdbStoreImpl>> result = { E_ERROR, nullptr };
    auto &[errCode, store] = result;
    store = std::make_shared<RdbStoreImpl>(modifyConfig, errCode);
    if (errCode != E_OK && modifyConfig.IsEncrypt() != config.IsEncrypt()) {
        LOG_WARN("Failed to OpenStore using modifyConfig. path:%{public}s, rc=%{public}d",
            SqliteUtils::Anonymous(path).c_str(), errCode);
        store = std::make_shared<RdbStoreImpl>(config, errCode); // retry with input config
    }
    return result;
}
} // namespace NativeRdb
} // namespace OHOS
