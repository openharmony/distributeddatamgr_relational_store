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
#include "sqlite_utils.h"
#include "string_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
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
{
}

std::shared_ptr<RdbStore> RdbStoreManager::GetRdbStore(const RdbStoreConfig &config,
    int &errCode, int version, RdbOpenCallback &openCallback)
{
    std::string path;
    // TOD this lock should only work on storeCache_, add one more lock for connectionpool
    std::lock_guard<std::mutex> lock(mutex_);
    if (config.GetRoleType() == VISITOR) {
        path = config.GetVisitorDir();
    } else {
        path = config.GetPath();
    }
    bundleName_ = config.GetBundleName();
    if (storeCache_.find(path) != storeCache_.end()) {
        std::shared_ptr<RdbStoreImpl> rdbStore = storeCache_[path].lock();
        if (rdbStore != nullptr && rdbStore->GetConfig() == config) {
            return rdbStore;
        }
        // TOD reconfigure store should be repeated this
        storeCache_.erase(path);
    }

    std::shared_ptr<RdbStoreImpl> rdbStore = std::make_shared<RdbStoreImpl>(config, errCode);
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreManager GetRdbStore fail to open RdbStore as memory issue, rc=%{public}d", errCode);
        return nullptr;
    }

    if (config.GetRoleType() == OWNER) {
        errCode = SetSecurityLabel(config);
        if (errCode != E_OK) {
            LOG_ERROR("fail, storeName:%{public}s security %{public}d errCode:%{public}d", config.GetName().c_str(),
                config.GetSecurityLevel(), errCode);
            return nullptr;
        }
        errCode = ProcessOpenCallback(*rdbStore, config, version, openCallback);
        if (errCode != E_OK) {
            LOG_ERROR("fail, storeName:%{public}s path:%{public}s ProcessOpenCallback errCode:%{public}d",
                config.GetName().c_str(), config.GetPath().c_str(), errCode);
            return nullptr;
        }
    }

    storeCache_[path] = rdbStore;
    return rdbStore;
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

    if (config.IsReadOnly()) {
        LOG_ERROR("RdbHelper ProcessOpenCallback Can't upgrade read-only store");
        return E_CANNOT_UPDATE_READONLY;
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
        std::lock_guard<std::mutex> lock(mutex_);
        param.bundleName_ = bundleName_;
        TaskExecutor::GetInstance().GetExecutor()->Execute([param]() {
            auto [err, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
            if (err != E_OK || service == nullptr) {
                LOG_DEBUG("GetRdbService failed, err is %{public}d.", err);
                return;
            }
            err = service->Delete(param);
            if (err != E_OK) {
                LOG_ERROR("service delete store, storeName:%{public}s, err = %{public}d",
                    SqliteUtils::Anonymous(param.storeName_).c_str(), err);
            }
        });
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
} // namespace NativeRdb
} // namespace OHOS
