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

#define LOG_TAG "RdbObsManager"

#include "rdb_obs_manager.h"

#include <dlfcn.h>

#include "global_resource.h"
#include "logger.h"
#include "obs_mgr_adapter.h"
#include "rdb_errno.h"
#include "sqlite_utils.h"

namespace OHOS::NativeRdb {
using RdbStoreObserver = DistributedRdb::RdbStoreObserver;
using namespace OHOS::Rdb;
std::mutex RdbObsManager::mutex_;
RdbObsManager::ObsAPIInfo RdbObsManager::apiInfo_;
void *RdbObsManager::handle_ = nullptr;;
RdbObsManager::~RdbObsManager()
{
    auto handle = GetApiInfo();
    if (handle.unregisterFunc == nullptr) {
        LOG_ERROR("dlsym(Unregister) failed");
        return;
    }
    obs_.ForEach([handle](const auto &key, auto &value) {
        for (auto &obs : value) {
            handle.unregisterFunc(key, obs);
        }
        return !value.empty();
    });
}

RdbObsManager::ObsAPIInfo RdbObsManager::GetApiInfo()
{
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    if (handle_ != nullptr) {
        return apiInfo_;
    }
    handle_ = dlopen("librdb_obs_mgr_adapter.z.so", RTLD_LAZY);
    if (handle_ == nullptr) {
        LOG_ERROR("dlopen(librdb_obs_mgr_adapter) failed(%{public}d)!", errno);
        return apiInfo_;
    }
    GlobalResource::RegisterClean(GlobalResource::OBS, CleanUp);
    apiInfo_.registerFunc = reinterpret_cast<RegisterFunc>(dlsym(handle_, "Register"));
    apiInfo_.unregisterFunc = reinterpret_cast<UnregisterFunc>(dlsym(handle_, "Unregister"));
    apiInfo_.notifyFunc = reinterpret_cast<NotifyFunc>(dlsym(handle_, "NotifyChange"));
    apiInfo_.cleanFunc = reinterpret_cast<CleanFunc>(dlsym(handle_, "CleanUp"));
    return apiInfo_;
}

int32_t RdbObsManager::CleanUp()
{
    auto handle = GetApiInfo();
    if (handle.cleanFunc == nullptr) {
        LOG_ERROR("dlsym(CleanUp) fail!");
        return E_ERROR;
    }
    if (!handle.cleanFunc()) {
        return E_ERROR;
    }
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    dlclose(handle_);
    handle_ = nullptr;
    apiInfo_.registerFunc = nullptr;
    apiInfo_.unregisterFunc = nullptr;
    apiInfo_.notifyFunc = nullptr;
    apiInfo_.cleanFunc = nullptr;
    return E_OK;
}

int32_t RdbObsManager::Register(const std::string &uri, std::shared_ptr<RdbStoreObserver> obs)
{
    auto handle = GetApiInfo();
    if (handle.registerFunc == nullptr) {
        LOG_ERROR("dlsym(Register) fail!, uri:%{public}s", SqliteUtils::Anonymous(uri).c_str());
        return E_ERROR;
    }
    auto code = handle.registerFunc(uri, obs);
    if (code == E_OK) {
        obs_.Compute(uri, [obs](const auto &key, auto &value) {
            value.push_back(obs);
            return !value.empty();
        });
        return E_OK;
    }
    return code == static_cast<int32_t>(DuplicateType::DUPLICATE_SUB) ? E_OK : code;
}

int32_t RdbObsManager::Unregister(const std::string &uri, std::shared_ptr<RdbStoreObserver> obs)
{
    auto handle = GetApiInfo();
    if (handle.unregisterFunc == nullptr) {
        LOG_ERROR("dlsym(Unregister) fail!, uri:%{public}s", SqliteUtils::Anonymous(uri).c_str());
        return E_ERROR;
    }
    auto code = handle.unregisterFunc(uri, obs);
    if (code != E_OK) {
        return code;
    }
    obs_.Compute(uri, [obs](const auto &key, auto &value) {
        if (obs == nullptr) {
            value.clear();
        }
        for (auto it = value.begin(); it != value.end();) {
            if (*it == obs) {
                value.erase(it);
                break;
            }
            ++it;
        }
        return !value.empty();
    });
    return code;
}

int32_t RdbObsManager::Notify(const std::string &uri)
{
    auto handle = GetApiInfo();
    if (handle.notifyFunc == nullptr) {
        LOG_ERROR("dlsym(NotifyChange) fail! uri:%{public}s", SqliteUtils::Anonymous(uri).c_str());
        return E_ERROR;
    }
    return handle.notifyFunc(uri);
}

} // namespace OHOS::NativeRdb