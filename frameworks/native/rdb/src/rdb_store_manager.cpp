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
#include <sstream>
#include <fstream>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_radar_reporter.h"
#include "rdb_store_impl.h"
#include "rdb_trace.h"
#include "restricted_db_manager.h"
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
#include "rdb_time_utils.h"
#include "sqlite_utils.h"
#include "string_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Reportor = RdbFaultHiViewReporter;
static constexpr const char *SILENT_CONF_PATH = "/system/etc/silent/conf/";
static constexpr const char *IS_SILENT_DB_JSON_PATH = "silentproxy_config.json";
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

RdbStoreManager::RdbStoreManager()
    : configCache_(BUCKET_MAX_SIZE), promiseInfoCache_(PROMISEINFO_CACHE_SIZE), isSilentCache_(BUCKET_MAX_SIZE)
{
}

std::shared_ptr<RdbStoreImpl> RdbStoreManager::GetStoreFromCache(const std::string &path,
    const RdbStoreConfig &config, int &errCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::shared_ptr<RdbStoreImpl> rdbStore = nullptr;
    auto it = storeCache_.find(path);
    if (it == storeCache_.end()) {
        rdbStore = std::make_shared<RdbStoreImpl>(config);
        storeCache_[path] = rdbStore;
        return rdbStore;
    }

    rdbStore = it->second.lock();
    if (rdbStore == nullptr) {
        rdbStore = std::make_shared<RdbStoreImpl>(config);
        storeCache_[path] = rdbStore;
        return rdbStore;
    }

    if (!(rdbStore->GetConfig() == config)) {
        auto log = RdbStoreConfig::FormatCfg(rdbStore->GetConfig(), config);
        LOG_WARN("Diff config! app[%{public}s:%{public}s] path[%{public}s] cfg[%{public}s]",
            config.GetBundleName().c_str(), config.GetModuleName().c_str(), SqliteUtils::Anonymous(path).c_str(),
            log.c_str());
        Reportor::ReportFault(RdbFaultDbFileEvent(RdbFaultType::FT_OPEN, E_CONFIG_INVALID_CHANGE, config, log));
        if (rdbStore->GetConfig().IsMemoryRdb() || config.IsMemoryRdb() ||
            config.GetVersion() >= ConfigVersion::INVALID_CONFIG_CHANGE_NOT_ALLOWED) {
            errCode = E_CONFIG_INVALID_CHANGE;
            rdbStore = nullptr;
            return rdbStore;
        }
        rdbStore = std::make_shared<RdbStoreImpl>(config);
        storeCache_[path] = rdbStore;
    }
    return rdbStore;
}

std::shared_ptr<RdbStore> RdbStoreManager::GetRdbStore(
    const RdbStoreConfig &config, int &errCode, int version, RdbOpenCallback &openCallback)
{
    std::string path;
    errCode = SqliteGlobalConfig::GetDbPath(config, path);
    if (errCode != E_OK) {
        return nullptr;
    }
    errCode = CheckConfig(config, path);
    if (errCode != E_OK) {
        return nullptr;
    }
    std::shared_ptr<RdbStoreImpl> rdbStore = nullptr;
    RdbStoreConfig modifyConfig = config;
    if (config.GetRoleType() == OWNER && IsConfigInvalidChanged(path, modifyConfig)) {
        errCode = E_CONFIG_INVALID_CHANGE;
        rdbStore = nullptr;
        return rdbStore;
    }
    rdbStore = GetStoreFromCache(path, modifyConfig, errCode);
    if (rdbStore == nullptr) {
        return rdbStore;
    }
    bool isNeedAcl = config.IsSearchable() || IsSupportSilent(config).second;
    errCode = rdbStore->Init(version, openCallback, isNeedAcl);
    if (errCode != E_OK) {
        if (modifyConfig.IsEncrypt() != config.IsEncrypt()) {
            rdbStore = nullptr;
            rdbStore = GetStoreFromCache(path, config, errCode);
            if (rdbStore == nullptr) {
                return rdbStore;
            }
            errCode = rdbStore->Init(version, openCallback, isNeedAcl);
        }
        if (errCode != E_OK || rdbStore == nullptr) {
            rdbStore = nullptr;
            return rdbStore;
        }
    }

    if (!rdbStore->GetConfig().IsMemoryRdb()) {
        configCache_.Set(path, GetSyncParam(rdbStore->GetConfig()));
    }
    CheckDBVisitor(config.GetName());
    return rdbStore;
}

void RdbStoreManager::CheckDBVisitor(const std::string &storeName)
{
    auto task = [storeName]() {
        if (!RestrictedDBManager::GetInstance().IsTargetDB(storeName)) {
            return;
        }
#if !defined(CROSS_PLATFORM)
        std::string caller = DistributedRdb::RdbManagerImpl::GetInstance().GetSelfBundleName();
        bool isIllegalAccess = RestrictedDBManager::GetInstance().IsDbAccessOutOfBounds(caller);
        if (isIllegalAccess) {
            LOG_ERROR("database visitor:%{public}s.", caller.c_str());
            Reportor::ReportFault(RdbFaultEvent(RdbFaultType::VISITOR_FAULT,
                E_DFX_VISITOR_VERIFY_FAULT, caller, "database visitor is not target process"));
        }
#endif
    };

    auto poolTask = TaskExecutor::GetInstance().GetExecutor();
    if (poolTask != nullptr) {
        poolTask->Execute(task);
    } else {
        task();
    }
}

std::shared_ptr<RdbStore> RdbStoreManager::GetRdb(const RdbStoreConfig &config)
{
    std::string path;
    int errCode = SqliteGlobalConfig::GetDbPath(config, path);
    if (errCode != E_OK) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    std::shared_ptr<RdbStoreImpl> rdbStore = nullptr;
    auto it = storeCache_.find(path);
    if (it == storeCache_.end()) {
        return nullptr;
    }

    rdbStore = it->second.lock();
    if (rdbStore == nullptr || rdbStore->GetInitStatus() != E_OK) {
        return nullptr;
    }
    return rdbStore;
}

bool RdbStoreManager::SilentProxys::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(silentProxys)], silentProxys);
    return true;
}

bool RdbStoreManager::SilentProxys::Unmarshal(const Serializable::json &node)
{
    GetValue(node, GET_NAME(silentProxys), silentProxys);
    return true;
}

bool RdbStoreManager::SilentProxy::Marshal(Serializable::json &node) const
{
    SetValue(node[GET_NAME(bundleName)], bundleName);
    SetValue(node[GET_NAME(storeNames)], storeNames);
    return true;
}

bool RdbStoreManager::SilentProxy::Unmarshal(const Serializable::json &node)
{
    GetValue(node, GET_NAME(bundleName), bundleName);
    GetValue(node, GET_NAME(storeNames), storeNames);
    return true;
}

std::pair<int32_t, bool> RdbStoreManager::IsSupportSilentFromProxy(const RdbStoreConfig &config)
{
    bool isSilent = false;
    std::ifstream fin(std::string(SILENT_CONF_PATH) + std::string(IS_SILENT_DB_JSON_PATH));
    if (!fin.good()) {
        LOG_ERROR("Failed to open silent json file");
        return {E_ERROR, isSilent};
    }
    std::string jsonStr;
    std::string line;
    while (fin.good()) {
        std::string line;
        std::getline(fin, line);
        jsonStr += line;
    }
    bool isContain = false;
    std::string key = config.GetBundleName() + "proxy";
    std::map<std::string, bool> temp;
    std::string dbName = SqliteUtils::RemoveSuffix(config.GetName());
    RdbStoreManager::SilentProxys silentProxys;
    silentProxys.Unmarshall(jsonStr);
    fin.close();
    for (auto &silentProxy : silentProxys.silentProxys) {
        if (silentProxy.bundleName != config.GetBundleName()) {
            continue;
        }
        isContain = true;
        for (auto &name : silentProxy.storeNames) {
            if (name == dbName) {
                isSilent = true;
            }
            temp[name] = true;
        }
        break;
    }
    if (!isContain || !isSilent) {
        temp[dbName] = false;
    }
    isSilentCache_.Set(key, temp);
    return {E_OK, isSilent};
}

std::pair<int32_t, bool> RdbStoreManager::IsSupportSilentFromService(const RdbStoreConfig &config)
{
#if !defined(CROSS_PLATFORM)
    Param param = GetSyncParam(config);
    auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
    if (err == E_NOT_SUPPORT) {
        return {err, false};
    }
    if (err != E_OK || service == nullptr) {
        LOG_ERROR("GetRdbService failed, err is %{public}d.", err);
        return {err, false};
    }
    auto [errcode, ret] = service->IsSupportSilent(param);
    if (errcode != DistributedRdb::RDB_OK) {
        return {E_ERROR, false};
    }
    std::map<std::string, bool> temp;
    std::string dbName = SqliteUtils::RemoveSuffix(config.GetName());
    std::string key = config.GetBundleName() + "service";
    isSilentCache_.Get(key, temp);
    temp[dbName] = ret;
    isSilentCache_.Set(key, temp);
    return {E_OK, ret};
#endif
    return {E_ERROR, false};
}

std::pair<int32_t, bool> RdbStoreManager::IsSupportSilent(const RdbStoreConfig &config)
{
    std::string key = config.GetBundleName();
    std::map<std::string, bool> cacheConf;
    std::string dbName = SqliteUtils::RemoveSuffix(config.GetName());
    if (!isSilentCache_.Get(key + "proxy", cacheConf)) {
        auto [err, flag] = IsSupportSilentFromProxy(config);
        if (err == E_OK && flag == true) {
            return {err, flag};
        }
    } else {
        auto it = cacheConf.find(dbName);
        if (it == cacheConf.end()) {
            cacheConf[dbName] = false;
            isSilentCache_.Set(key + "proxy", cacheConf);
        }
        if (it != cacheConf.end() && it->second) {
            return {E_OK, it->second};
        }
    }
    std::map<std::string, bool> cacheService;
    if (isSilentCache_.Get(key + "service", cacheService)) {
        auto it = cacheService.find(dbName);
        if (it != cacheService.end()) {
            return {E_OK, it->second};
        }
    }
    return IsSupportSilentFromService(config);
}

bool RdbStoreManager::IsConfigInvalidChanged(const std::string &path, RdbStoreConfig &config)
{
    if (config.IsMemoryRdb()) {
        return false;
    }
    if (config.GetBundleName().empty()) {
        LOG_WARN("no bundleName");
        return false;
    }
    Param lastParam = GetSyncParam(config);
    if (!configCache_.Get(path, lastParam) && GetParamFromService(lastParam) != E_OK) {
        LOG_WARN("Not found config cache, path: %{public}s", SqliteUtils::Anonymous(path).c_str());
        return false;
    };
    configCache_.Set(path, lastParam);
    // The lastParam is possible that the same named db parameters of different paths when GetParamFromService
    if (lastParam.customDir_ != config.GetCustomDir() || lastParam.hapName_ != config.GetModuleName() ||
        lastParam.area_ != config.GetArea()) {
        std::stringstream ss;
        ss << "Diff db with the same name! customDir:" << SqliteUtils::Anonymous(lastParam.customDir_).c_str() << "->"
            << SqliteUtils::Anonymous(config.GetCustomDir()).c_str() << ", hapName:"
            << lastParam.hapName_.c_str() << "->" << config.GetModuleName().c_str() << ", area:"
            << lastParam.area_ << "->" << config.GetArea();
        LOG_WARN("%{public}s", ss.str().c_str());
        Reportor::ReportFault(RdbFaultDbFileEvent(RdbFaultType::FT_OPEN, E_CONFIG_INVALID_CHANGE, config, ss.str()));
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
        config.SetAllowRebuild(false);
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

bool RdbStoreManager::IsPermitted(const DistributedRdb::RdbSyncerParam &param, const std::string &path)
{
#if !defined(CROSS_PLATFORM)
    bool result = false;
    // ToDo: Scenario for handling cache refresh
    if (promiseInfoCache_.Get(path, result)) {
        return true;
    };
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
        promiseInfoCache_.Set(path, true);
        return true;
    }
    LOG_ERROR("failed, bundleName:%{public}s, store:%{public}s, err:%{public}d.", param.bundleName_.c_str(),
        SqliteUtils::Anonymous(param.storeName_).c_str(), err);
#endif
    return false;
}

void RdbStoreManager::Clear()
{
    configCache_.ResetCapacity(0);
    configCache_.ResetCapacity(BUCKET_MAX_SIZE);
    isSilentCache_.ResetCapacity(0);
    isSilentCache_.ResetCapacity(BUCKET_MAX_SIZE);
    promiseInfoCache_.ResetCapacity(0);
    promiseInfoCache_.ResetCapacity(PROMISEINFO_CACHE_SIZE);
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = storeCache_.begin();
    while (iter != storeCache_.end()) {
        auto rdbStore = iter->second.lock();
        if (rdbStore != nullptr && rdbStore.use_count() > 1) {
            LOG_WARN("store[%{public}s] in use by %{public}ld holders",
                SqliteUtils::Anonymous(rdbStore->GetPath()).c_str(), rdbStore.use_count());
        }
        iter = storeCache_.erase(iter);
    }
    storeCache_.clear();
}

void RdbStoreManager::Init()
{
    TaskExecutor::GetInstance().Init();
}

bool RdbStoreManager::Destroy()
{
    Clear();
    return TaskExecutor::GetInstance().Stop();
}

bool RdbStoreManager::Remove(const std::string &path, bool shouldClose)
{
    std::lock_guard<std::mutex> lock(mutex_);
    configCache_.Delete(path);
    auto it = storeCache_.find(path);
    if (it != storeCache_.end()) {
        auto rdbStore = it->second.lock();
        LOG_INFO("store in use by %{public}ld holders", rdbStore.use_count());
        if (rdbStore && shouldClose) {
            rdbStore->Close();
        }
        storeCache_.erase(it); // clean invalid store ptr
        return true;
    }

    return false;
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
        param.area_ = config.GetArea();
        param.hapName_ = config.GetModuleName();
        param.customDir_ = config.GetCustomDir();
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

std::string RdbStoreManager::GetSelfBundleName()
{
#if !defined(CROSS_PLATFORM)
    return DistributedRdb::RdbManagerImpl::GetInstance().GetSelfBundleName();
#endif
    return "";
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

int32_t RdbStoreManager::CheckConfig(const RdbStoreConfig &config, const std::string &path)
{
    if (config.GetRoleType() == VISITOR_WRITE && !IsPermitted(GetSyncParam(config), path)) {
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

} // namespace NativeRdb
} // namespace OHOS
