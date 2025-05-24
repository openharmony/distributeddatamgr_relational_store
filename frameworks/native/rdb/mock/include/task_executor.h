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
#ifndef DISTRIBUTED_NATIVE_RDB_TASK_EXECUTOR_H
#define DISTRIBUTED_NATIVE_RDB_TASK_EXECUTOR_H
#include <chrono>
#include <condition_variable>
#include <functional>
#include <shared_mutex>
namespace OHOS {
class ExecutorPool {
public:
    using TaskId = uint64_t;
    using Task = std::function<void()>;
    using Duration = std::chrono::steady_clock::duration;
    static constexpr Duration INVALID_DURATION = std::chrono::milliseconds(0);
    static constexpr TaskId INVALID_TASK_ID = static_cast<uint64_t>(0l);
    static constexpr uint64_t UNLIMITED_TIMES = std::numeric_limits<uint64_t>::max();
    ExecutorPool(size_t max, size_t min)
    {
    }
    ~ExecutorPool()
    {
    }

    TaskId Execute(Task task)
    {
        return INVALID_TASK_ID;
    }

    TaskId Schedule(Duration delay, Task task)
    {
        return INVALID_TASK_ID;
    }

    TaskId Schedule(Task task, Duration interval)
    {
        return INVALID_TASK_ID;
    }

    TaskId Schedule(Task task, Duration delay, Duration interval)
    {
        return INVALID_TASK_ID;
    }

    TaskId Schedule(Task task, Duration delay, Duration interval, uint64_t times)
    {
        return INVALID_TASK_ID;
    }

    bool Remove(TaskId taskId, bool wait = false)
    {
        return true;
    }

    TaskId Reset(TaskId taskId, Duration interval)
    {
        return INVALID_TASK_ID;
    }
};
namespace NativeRdb {
class TaskExecutor {
public:
    using TaskId = ExecutorPool::TaskId;
    using Task = std::function<void()>;
    using Duration = std::chrono::steady_clock::duration;
    static constexpr TaskId INVALID_TASK_ID = ExecutorPool::INVALID_TASK_ID;

    static TaskExecutor &GetInstance();
    std::shared_ptr<ExecutorPool> GetExecutor();
    void SetExecutor(std::shared_ptr<ExecutorPool> executor);
    bool Stop();

private:
    TaskExecutor();
    ~TaskExecutor();
    mutable std::shared_mutex rwMutex_;
    std::shared_ptr<ExecutorPool> pool_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif // DISTRIBUTED_DATA_TASK_EXECUTOR_H
