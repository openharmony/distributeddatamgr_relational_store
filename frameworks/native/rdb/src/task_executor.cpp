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

#define LOG_TAG "TaskExecutor"
#include "task_executor.h"

#include "logger.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
constexpr int32_t MAX_RETRY = 100;
TaskExecutor::TaskExecutor()
{
    pool_ = std::make_shared<ExecutorPool>(MAX_THREADS, MIN_THREADS);
}

TaskExecutor::~TaskExecutor()
{
    pool_ = nullptr;
}

TaskExecutor &TaskExecutor::GetInstance()
{
    static TaskExecutor instance;
    return instance;
}

void TaskExecutor::Init()
{
    std::unique_lock<decltype(rwMutex_)> lock(rwMutex_);
    if (pool_ != nullptr) {
        return;
    }
    pool_ = std::make_shared<ExecutorPool>(MAX_THREADS, MIN_THREADS);
};

std::shared_ptr<ExecutorPool> TaskExecutor::GetExecutor()
{
    std::shared_lock<decltype(rwMutex_)> lock(rwMutex_);
    return pool_;
}

void TaskExecutor::SetExecutor(std::shared_ptr<ExecutorPool> executor)
{
    std::unique_lock<decltype(rwMutex_)> lock(rwMutex_);
    pool_ = executor;
}

bool TaskExecutor::Stop()
{
    std::shared_ptr<ExecutorPool> pool;
    {
        std::unique_lock<decltype(rwMutex_)> lock(rwMutex_);
        pool = std::move(pool_);
        pool_ = nullptr;
    }
    int32_t retry = 0;
    while (pool.use_count() > 1 && retry++ < MAX_RETRY) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (pool.use_count() > 1) {
        LOG_WARN("There are other threads using the thread pool. count:%{public}ld", pool.use_count());
        return false;
    }
    return true;
};

} // namespace OHOS::NativeRdb
