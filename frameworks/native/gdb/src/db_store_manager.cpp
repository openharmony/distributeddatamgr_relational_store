/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "GdbStoreManager"
#include "db_store_manager.h"

#include <unistd.h>

#include <regex>

#include "aip_errors.h"
#include "db_store_impl.h"
#include "gdb_utils.h"
#include "logger.h"
#include "security_label.h"

namespace OHOS::DistributedDataAip {
StoreManager &StoreManager::GetInstance()
{
    static StoreManager manager;
    return manager;
}

StoreManager::StoreManager() = default;

StoreManager::~StoreManager()
{
    Clear();
}

bool StoreManager::IsValidName(const std::string &name)
{
    const std::regex pattern("^[a-zA-Z0-9_]+$");
    return std::regex_match(name, pattern);
}

bool StoreManager::IsValidSecurityLevel(const int32_t securityLevel)
{
    return securityLevel >= SecurityLevel::S1 && securityLevel <= SecurityLevel::S4;
}

std::shared_ptr<DBStore> StoreManager::GetDBStore(const StoreConfig &config, int &errCode)
{
    if (!IsValidName(config.GetName())) {
        LOG_ERROR("GetDBStore failed. Invalid name");
        errCode = E_GRD_INVAILD_NAME_ERR;
        return nullptr;
    }
    if (!IsValidSecurityLevel(config.GetSecurityLevel())) {
        LOG_ERROR("GetDBStore failed. Invalid securityLevel: %{public}d", config.GetSecurityLevel());
        errCode = E_INVALID_ARGS;
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto path = config.GetFullPath();
    if (storeCache_.find(path) != storeCache_.end()) {
        std::shared_ptr<DBStoreImpl> dbStore = storeCache_[path].lock();
        if (dbStore != nullptr) {
            LOG_ERROR("GetDBStore reuse success.");
            return dbStore;
        }
        storeCache_.erase(path);
    }
    // open and store DBStore
    std::shared_ptr<DBStoreImpl> dbStore = std::make_shared<DBStoreImpl>(config);
    errCode = dbStore->InitConn();
    if (errCode != E_OK) {
        LOG_ERROR("GetDBStore InitConn failed, name=%{public}s, errCode=%{public}d",
            GdbUtils::Anonymous(config.GetName()).c_str(), errCode);
        return nullptr;
    }
    errCode = SetSecurityLabel(config);
    if (errCode != E_OK) {
        LOG_ERROR("GetDBStore SetSecurityLabel failed, errCode=%{public}d", errCode);
        return nullptr;
    }
    storeCache_[path] = dbStore;
    return dbStore;
}

void StoreManager::Clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = storeCache_.begin();
    while (iter != storeCache_.end()) {
        iter = storeCache_.erase(iter);
    }
    storeCache_.clear();
}

bool StoreManager::Delete(const std::string &path)
{
    LOG_DEBUG("Delete file, path=%{public}s", GdbUtils::Anonymous(path).c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    if (storeCache_.find(path) != storeCache_.end()) {
        auto store = storeCache_[path].lock();
        if (store) {
            LOG_WARN("store in use by %{public}ld holders", store.use_count());
            store->Close();
        }
        storeCache_.erase(path); // clean invalid store ptr
    }
    // 鍒犲簱鍔ㄤ綔
    bool deleteResult = true;
    for (auto &suffix : GRD_POST_FIXES) {
        deleteResult = DeleteFile(path + suffix) && deleteResult;
    }
    return deleteResult;
}

bool StoreManager::DeleteFile(const std::string &path)
{
    if (access(path.c_str(), 0) != 0) {
        LOG_WARN("access return, path=%{public}s", GdbUtils::Anonymous(path).c_str());
        return true;
    }
    auto ret = remove(path.c_str());
    if (ret != 0) {
        LOG_ERROR("remove file failed errno %{public}d ret %{public}d %{public}s", errno, ret,
            GdbUtils::Anonymous(path).c_str());
        return false;
    }
    return true;
}

int StoreManager::SetSecurityLabel(const StoreConfig &config)
{
    if (config.GetSecurityLevel() >= SecurityLevel::S1 && config.GetSecurityLevel() <= SecurityLevel::S4) {
        auto toSetLevel = GetSecurityLevelValue(static_cast<SecurityLevel>(config.GetSecurityLevel()));
        auto errCode =
            FileManagement::ModuleSecurityLabel::SecurityLabel::SetSecurityLabel(config.GetFullPath(), toSetLevel)
                ? E_OK
                : E_CONFIG_INVALID_CHANGE;
        if (errCode != E_OK) {
            auto currentLevel = GetFileSecurityLevel(config.GetFullPath());
            LOG_ERROR(
                "Set security level:%{public}s -> %{public}s, result=%{public}d, errno=%{public}d, name=%{public}s.",
                currentLevel.c_str(), toSetLevel.c_str(), errCode, errno,
                GdbUtils::Anonymous(config.GetName()).c_str());
        }
        return errCode;
    }
    return E_OK;
}

std::string StoreManager::GetSecurityLevelValue(SecurityLevel securityLevel)
{
    switch (securityLevel) {
        case SecurityLevel::S1:
            return "s1";
        case SecurityLevel::S2:
            return "s2";
        case SecurityLevel::S3:
            return "s3";
        case SecurityLevel::S4:
            return "s4";
        default:
            return "";
    }
}

std::string StoreManager::GetFileSecurityLevel(const std::string &filePath)
{
    return FileManagement::ModuleSecurityLabel::SecurityLabel::GetSecurityLabel(filePath);
}

} // namespace OHOS::DistributedDataAip