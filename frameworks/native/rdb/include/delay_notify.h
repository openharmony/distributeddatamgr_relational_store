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

#ifndef NATIVE_RDB_DELAY_NOTIFY_H
#define NATIVE_RDB_DELAY_NOTIFY_H
#include <map>
#include <string>
#include <functional>
#include <memory>
#include "rdb_types.h"
#include "executor_pool.h"
namespace OHOS::NativeRdb {
class DelayNotify {
public:
    using Task = std::function<int(const DistributedRdb::RdbChangedData &)>;
    ~DelayNotify();
    void SetExecutorPool(std::shared_ptr<ExecutorPool> pool);
    void SetTask(Task task);
    void UpdateNotify(const DistributedRdb::RdbChangedData &changedData);
    void SetAutoSyncInterval(uint32_t autoSyncInterval);
private:
    static constexpr uint32_t FORCE_SYNC_INTERVAL = 100;
    static constexpr uint32_t AUTO_SYNC_INTERVAL = 50;
    ExecutorPool::TaskId delaySyncTaskId_ = ExecutorPool::INVALID_TASK_ID;
    ExecutorPool::TaskId forceSyncTaskId_ = ExecutorPool::INVALID_TASK_ID;
    Task task_;
    std::shared_ptr<ExecutorPool> pool_ = nullptr;
    std::mutex mutex_;
    DistributedRdb::RdbChangedData changedData_;

    void StartTimer();
    void StopTimer();
    void ExecuteTask();
    void RestoreDefaultSyncInterval();
    uint32_t autoSyncInterval_ = AUTO_SYNC_INTERVAL;
};
}
#endif // NATIVE_RDB_DELAY_NOTIFY_H