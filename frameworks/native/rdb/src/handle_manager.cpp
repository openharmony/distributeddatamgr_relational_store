#define LOG_TAG "HandleManager"
#include "handle_manager.h"

#include "logger.h"
#include "rdb_store_manager.h"
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
HandleManager &HandleManager::GetInstance()
{
    static HandleManager instance;
    return instance;
}

int HandleManager::Register(RdbStoreConfig rdbStoreConfig, std::shared_ptr corruptHandler)
{
    if (corruptHandler == nullptr) {
        LOG_ERROR("register failed: corruptHandler is null.");
        return E_INVALID_ARGS;
    }

    std::string path = rdbStoreConfig.GetPath();
    if (path.empty()) {
        LOG_ERROR("register failed: invalid database path.");
        return E_INVALID_ARGS;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = handlers_.find(path);
    if (it != handlers_.end()) {
        LOG_ERROR("corruptHandler for path %{public}s has already been registered.", path.c_str());
        return E_ERROR;
    }
    handlers_[path] = corruptHandler;
    return E_OK;
}

int HandleManager::Unregister(const std::string &path)
{
    std::lock_guardstd::mutex lock(mutex_);
    auto it = handlers_.find(path);
    if (it != handlers_.end()) {
        handlers_.erase(it);
    }
    return E_OK;
}

std::shared_ptr HandleManager::GetHandler(const std::string &path)
{
    std::lock_guardstd::mutex lock(mutex_);
    auto it = handlers_.find(path);
    if (it != handlers_.end()) {
        return it->second;
    }
    return nullptr;
}

void HandleManager::HandleCorrupt(const RdbStoreConfig &config)
{
    auto handler = HandleManager::GetInstance().GetHandler(config.GetPath());
    if (handler != nullptr) {
        auto taskPool = TaskExecutor::GetInstance().GetExecutor();
        if (taskPool == nullptr) {
            LOG_ERROR("Get thread pool failed");
            return;
        }
        auto tmpHandler = handler;
        taskPool->Schedule(std::chrono::milliseconds(100), [tmpHandler]() {
                tmpHandler->OnCorrupt();
        });
    }
}

} // namespace NativeRdb
} // namespace OHOS