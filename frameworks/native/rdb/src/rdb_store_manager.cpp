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

#include "rdb_store_manager.h"

#include <algorithm>
#include <cinttypes>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_store_impl.h"
#include "rdb_trace.h"
#include "sqlite_global_config.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "rdb_security_manager.h"
#include "security_policy.h"
#endif
#include "sqlite_utils.h"

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
    LOG_ERROR("Start");
    Clear();
}

RdbStoreManager::RdbStoreManager()
{
}

std::shared_ptr<RdbStore> RdbStoreManager::GetRdbStore(const RdbStoreConfig &config,
    int &errCode, int version, RdbOpenCallback &openCallback)
{
    std::string path = config.GetPath();
    std::lock_guard<std::mutex> lock(mutex_); // TODO this lock should only work on storeCache_, add one more lock for connectionpool
    if (storeCache_.find(path) != storeCache_.end()) {
        std::shared_ptr<RdbStoreImpl> rdbStore = storeCache_[path].lock();
        if (rdbStore != nullptr && rdbStore->GetConfig() == config) {
            return rdbStore;
        }
        storeCache_.erase(path); // TODO reconfigure store should be repeated this
    }

    std::shared_ptr<RdbStoreImpl> rdbStore(new (std::nothrow) RdbStoreImpl(config, errCode),
        [this, path](RdbStoreImpl *ptr) {
            LOG_INFO("delete %{public}s as no more used.", SqliteUtils::Anonymous(ptr->GetPath()).c_str());
            delete ptr;
            if (storeCache_.find(path) != storeCache_.end()) { // TODO need add lock to storeCache_
                storeCache_.erase(path);
            }
        });
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreManager GetRdbStore fail to open RdbStore as memory issue, rc=%{public}d", errCode);
        return nullptr;
    }

    if (SetSecurityLabel(config) != E_OK) {
        LOG_ERROR("RdbHelper set security label fail.");
        return nullptr;
    }

    errCode = ProcessOpenCallback(*rdbStore, config, version, openCallback);
    if (errCode != E_OK) {
        LOG_ERROR("RdbHelper GetRdbStore ProcessOpenCallback fail");
        return nullptr;
    }

    storeCache_[path] = rdbStore;
    return rdbStore;
}

void RdbStoreManager::Clear() // TODO delete for no use
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = storeCache_.begin();
    while (iter != storeCache_.end()) {
        iter = storeCache_.erase(iter);
    }
    storeCache_.clear();
}

bool RdbStoreManager::IsInUsing(const std::string &path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (storeCache_.find(path) != storeCache_.end()) {
        if (storeCache_[path].lock()) {
            return true;
        }
        storeCache_.erase(path);
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
int RdbStoreManager::SetSecurityLabel(const RdbStoreConfig &config)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    return SecurityPolicy::SetSecurityLabel(config);
#endif
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
