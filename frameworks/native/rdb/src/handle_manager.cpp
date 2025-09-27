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

#define LOG_TAG "HandleManager"

#include "handle_manager.h"
#include "logger.h"
#include "rdb_store_manager.h"
#include "sqlite_utils.h"
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
std::unordered_set<std::string> HandleManager::pausedPaths_;
std::mutex HandleManager::mutex_;
HandleManager &HandleManager::GetInstance()
{
    static HandleManager instance;
    return instance;
}

int HandleManager::Register(const RdbStoreConfig &config, std::shared_ptr<CorruptHandler> corruptHandler)
{
    if (corruptHandler == nullptr) {
        LOG_ERROR("register failed: corruptHandler is null.");
        return E_INVALID_ARGS;
    }

    std::string path = config.GetPath();
    if (path.empty()) {
        LOG_ERROR("register failed: invalid database path.");
        return E_INVALID_ARGS;
    }
    auto result = handlers_.ComputeIfAbsent(path, [&corruptHandler](const std::string &key) {
        return corruptHandler;
    });
    if (!result) {
        LOG_ERROR(
            "corruptHandler for path %{public}s has already been registered.", SqliteUtils::Anonymous(path).c_str());
        return E_ERROR;
    }
    return E_OK;
}

int HandleManager::Unregister(const RdbStoreConfig &config)
{
    handlers_.Erase(config.GetPath());
    return E_OK;
}

void HandleManager::PauseCallback(const RdbStoreConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    pausedPaths_.insert(config.GetPath());
}

void HandleManager::ResumeCallback(const RdbStoreConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    pausedPaths_.erase(config.GetPath());
}

std::shared_ptr<CorruptHandler> HandleManager::GetHandler(const RdbStoreConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto [isFound, handler] = handlers_.Find(config.GetPath());
    if (isFound) {
        return handler;
    }
    return nullptr;
}

void HandleManager::HandleCorrupt(const RdbStoreConfig &config)
{
    auto handler = HandleManager::GetInstance().GetHandler(config.GetPath());
    if (handler == nullptr || pausedPaths_.count(config.GetPath()) > 0) {
        return;
    }
    auto taskPool = TaskExecutor::GetInstance().GetExecutor();
    if (taskPool == nullptr) {
        LOG_ERROR("Get thread pool failed");
        return;
    }
    taskPool->Execute([handler, config]() {
        handler->OnCorruptHandler(config);
    });
}

} // namespace NativeRdb
} // namespace OHOS