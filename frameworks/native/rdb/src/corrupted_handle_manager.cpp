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

#define LOG_TAG "CorruptedHandleManager"

#include "corrupted_handle_manager.h"
#include "logger.h"
#include "rdb_platform.h"
#include "rdb_store_manager.h"
#include "sqlite_utils.h"
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
CorruptedHandleManager &CorruptedHandleManager::GetInstance()
{
    static CorruptedHandleManager instance;
    return instance;
}

int CorruptedHandleManager::Register(const RdbStoreConfig &config, std::shared_ptr<CorruptHandler> corruptHandler)
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
        return E_SUB_LIMIT_REACHED;
    }
    return E_OK;
}

int CorruptedHandleManager::Unregister(const RdbStoreConfig &config)
{
    handlers_.Erase(config.GetPath());
    return E_OK;
}

void CorruptedHandleManager::PauseCallback()
{
    uint64_t tid = GetThreadId();
    pausedPaths_.Compute(tid, [](const uint64_t &key, int &value) {
        value++;
        return true;
    });
}

void CorruptedHandleManager::ResumeCallback()
{
    uint64_t tid = GetThreadId();
    pausedPaths_.ComputeIfPresent(tid, [](const uint64_t &key, int &value) {
        value--;
        return value > 0;
    });
}

std::shared_ptr<CorruptHandler> CorruptedHandleManager::GetHandler(const RdbStoreConfig &config)
{
    auto [isFound, handler] = handlers_.Find(config.GetPath());
    if (isFound) {
        return handler;
    }
    return nullptr;
}

void CorruptedHandleManager::HandleCorrupt(const RdbStoreConfig &config)
{
    uint64_t tid = GetThreadId();
    auto [isExist, count] = pausedPaths_.Find(tid);
    auto handler = CorruptedHandleManager::GetInstance().GetHandler(config.GetPath());
    if (handler == nullptr || (isExist && count > 0)) {
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