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

#include "task_executor.h"

namespace OHOS::NativeRdb {
TaskExecutor::TaskExecutor()
{
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
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    if (pool_ != nullptr) {
        return;
    }
    pool_ = std::make_shared<ExecutorPool>(MAX_THREADS, MIN_THREADS, "TaskExecutorRDB");
};

std::shared_ptr<ExecutorPool> TaskExecutor::GetExecutor()
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    if (pool_ == nullptr) {
        pool_ = std::make_shared<ExecutorPool>(MAX_THREADS, MIN_THREADS, "TaskExecutorRDB");
    }
    return pool_;
}

void TaskExecutor::SetExecutor(std::shared_ptr<ExecutorPool> executor)
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    pool_ = executor;
};

bool TaskExecutor::Stop()
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    pool_ = nullptr;
    return true;
}
} // namespace OHOS::NativeRdb
