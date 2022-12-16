/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "rdb_helper.h"

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_store_impl.h"
#include "rdb_trace.h"
#include "sqlite_global_config.h"
#include "unistd.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_security_manager.h"
#include "security_policy.h"
#endif

namespace OHOS {
namespace NativeRdb {
std::shared_ptr<RdbStore> RdbHelper::GetRdbStore(
    const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    SqliteGlobalConfig::InitSqliteGlobalConfig();

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    if (config.IsEncrypt()) {
        RdbSecurityManager::GetInstance().Init(config.GetBundleName(), config.GetPath());
    }
#endif

    std::shared_ptr<RdbStore> rdbStore = RdbStoreManager::GetInstance().GetRdbStore(config, errCode);
    if (rdbStore == nullptr) {
        LOG_ERROR("RdbHelper GetRdbStore fail to open RdbStore");
        return nullptr;
    }

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    errCode = SecurityPolicy::SetSecurityLabel(config);
    if (errCode != E_OK) {
        LOG_ERROR("RdbHelper set security label fail.");
        return nullptr;
    }
#endif

    errCode = ProcessOpenCallback(*rdbStore, config, version, openCallback);
    if (errCode != E_OK) {
        LOG_ERROR("RdbHelper GetRdbStore ProcessOpenCallback fail");
        return nullptr;
    }

    return rdbStore;
}

int RdbHelper::ProcessOpenCallback(
    RdbStore &rdbStore, const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int currentVersion;
    int errCode = rdbStore.GetVersion(currentVersion);
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

void RdbHelper::ClearCache()
{
    RdbStoreManager::GetInstance().Clear();
}


static void DeleteRdbKeyFiles(const std::string &dbFileName)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    RdbSecurityManager::GetInstance().DelRdbSecretDataFile(dbFileName);
#endif
}


int RdbHelper::DeleteRdbStore(const std::string &dbFileName)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (dbFileName.empty()) {
        return E_EMPTY_FILE_NAME;
    }
    RdbStoreManager::GetInstance().Remove(dbFileName);
    if (access(dbFileName.c_str(), F_OK) != 0) {
        return E_OK; // not not exist
    }
    int result = remove(dbFileName.c_str());
    if (result != 0) {
        LOG_ERROR("RdbHelper DeleteRdbStore failed to delete the db file err = %{public}d", errno);
        return E_REMOVE_FILE;
    }

    int errCode = E_OK;
    std::string shmFileName = dbFileName + "-shm";
    if (access(shmFileName.c_str(), F_OK) == 0) {
        result = remove(shmFileName.c_str());
        if (result < 0) {
            LOG_ERROR("RdbHelper DeleteRdbStore failed to delete the shm file err = %{public}d", errno);
            errCode = E_REMOVE_FILE;
        }
    }

    std::string walFileName = dbFileName + "-wal";
    if (access(walFileName.c_str(), F_OK) == 0) {
        result = remove(walFileName.c_str());
        if (result < 0) {
            LOG_ERROR("RdbHelper DeleteRdbStore failed to delete the wal file err = %{public}d", errno);
            errCode = E_REMOVE_FILE;
        }
    }

    std::string journalFileName = dbFileName + "-journal";
    if (access(journalFileName.c_str(), F_OK) == 0) {
        result = remove(journalFileName.c_str());
        if (result < 0) {
            LOG_ERROR("RdbHelper DeleteRdbStore failed to delete the journal file err = %{public}d", errno);
            errCode = E_REMOVE_FILE;
        }
    }
    DeleteRdbKeyFiles(dbFileName);

    return errCode;
}

RdbStoreNode::RdbStoreNode(const std::shared_ptr<RdbStore> &rdbStore) : rdbStore_(rdbStore) {}

RdbStoreNode &RdbStoreNode::operator=(const std::shared_ptr<RdbStore> &store)
{
    if (rdbStore_ == store) {
        return *this;
    }
    rdbStore_ = std::move(store);
    return *this;
}

RdbStoreManager &RdbStoreManager::GetInstance()
{
    static RdbStoreManager manager;
    return manager;
}

RdbStoreManager::~RdbStoreManager()
{
    LOG_ERROR("Start");
    Clear();
    if (timer_ != nullptr) {
        timer_->Shutdown(true);
        timer_ = nullptr;
    }
}

RdbStoreManager::RdbStoreManager()
{
    timer_ = std::make_shared<Utils::Timer>("RdbStoreCloser");
    timer_->Setup();
}

std::shared_ptr<RdbStore> RdbStoreManager::GetRdbStore(const RdbStoreConfig &config, int &errCode)
{
    std::shared_ptr<RdbStore> rdbStore;
    std::string path = config.GetPath();
    std::lock_guard<std::mutex> lock(mutex_);
    if (storeCache_.find(path) == storeCache_.end() || storeCache_[path] == nullptr) {
        rdbStore = RdbStoreImpl::Open(config, errCode);
        if (rdbStore == nullptr) {
            LOG_ERROR("RdbStoreManager GetRdbStore fail to open RdbStore, err is %{public}d", errCode);
            return nullptr;
        }
        storeCache_[path] = std::make_shared<RdbStoreNode>(rdbStore);
        RestartTimer(path, *storeCache_[path]);
    } else {
        RestartTimer(path, *storeCache_[path]);
        rdbStore = storeCache_[path]->rdbStore_;
    }
    return rdbStore;
}

void RdbStoreManager::RestartTimer(const std::string &path, RdbStoreNode &node)
{
    if (timer_ != nullptr) {
        timer_->Unregister(node.timerId_);
        // after 30000ms, auto close.
        node.timerId_ = timer_->Register(std::bind(RdbStoreManager::AutoClose, path, this), 30000, true);
    }
}

void RdbStoreManager::AutoClose(const std::string &path, RdbStoreManager *manager)
{
    manager->Remove(path);
}

void RdbStoreManager::Remove(const std::string &path)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (storeCache_.find(path) == storeCache_.end()) {
        LOG_INFO("has Removed");
        return;
    }
    if (timer_ != nullptr) {
        timer_->Unregister(storeCache_[path]->timerId_);
    }
    storeCache_.erase(path);
}

void RdbStoreManager::Clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = storeCache_.begin();
    while (iter != storeCache_.end()) {
        if (timer_ != nullptr && iter->second != nullptr) {
            timer_->Unregister(iter->second->timerId_);
        }
        iter = storeCache_.erase(iter);
    }
}
} // namespace NativeRdb
} // namespace OHOS
