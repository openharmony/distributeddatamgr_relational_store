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

#include "delay_notify.h"
#include "logger.h"
namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
DelayNotify::~DelayNotify()
{
    if (pool_ == nullptr) {
        return;
    }
    if (forceSyncTaskId_ != Executor::INVALID_TASK_ID) {
        pool_->Remove(forceSyncTaskId_);
    }
    if (delaySyncTaskId_ != Executor::INVALID_TASK_ID) {
        pool_->Remove(delaySyncTaskId_);
    }
    if (task_ != nullptr && changedData_.tableData.size() > 0) {
        pool_->Schedule(std::chrono::milliseconds(AUTO_SYNC_INTERVAL), [task = task_, changedData = changedData_]() {
            auto errCode = task(changedData);
            if (errCode != 0) {
                LOG_ERROR("NotifyDataChange is failed, err is %{public}d.", errCode);
            }
        });
    }
}

void DelayNotify::UpdateNotify(const DistributedRdb::RdbChangedData &changedData)
{
    LOG_DEBUG("Update changed data.");
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [k, v] : changedData.tableData) {
        auto it = changedData_.tableData.find(k);
        if (it != changedData_.tableData.end()) {
            it->second.isTrackedDataChange |= v.isTrackedDataChange;
        } else {
            changedData_.tableData.insert_or_assign(k, v);
        }
    }
    StartTimer();
}

void DelayNotify::SetExecutorPool(std::shared_ptr<ExecutorPool> pool)
{
    pool_ = pool;
}

void DelayNotify::SetTask(Task task)
{
    task_ = std::move(task);
}

void DelayNotify::StartTimer()
{
    if (pool_ == nullptr) {
        return;
    }
    if (forceSyncTaskId_ == Executor::INVALID_TASK_ID) {
        forceSyncTaskId_ = pool_->Schedule(std::chrono::milliseconds(FORCE_SYNC_INTERVAL),
            [this]() { ExecuteTask(); });
    }
    if (delaySyncTaskId_ == Executor::INVALID_TASK_ID) {
        delaySyncTaskId_ = pool_->Schedule(std::chrono::milliseconds(AUTO_SYNC_INTERVAL),
            [this]() { ExecuteTask(); });
    } else {
        delaySyncTaskId_ =
            pool_->Reset(delaySyncTaskId_, std::chrono::milliseconds(AUTO_SYNC_INTERVAL));
    }
}

void DelayNotify::StopTimer()
{
    if (pool_ != nullptr) {
        pool_->Remove(forceSyncTaskId_);
        pool_->Remove(delaySyncTaskId_);
    }
    forceSyncTaskId_ = Executor::INVALID_TASK_ID;
    delaySyncTaskId_ = Executor::INVALID_TASK_ID;
}

void DelayNotify::ExecuteTask()
{
    LOG_DEBUG("Notify data change.");
    std::lock_guard<std::mutex> lock(mutex_);
    StopTimer();
    if (task_ != nullptr && changedData_.tableData.size() > 0) {
        int errCode = task_(changedData_);
        if (errCode != 0) {
            LOG_ERROR("NotifyDataChange is failed, err is %{public}d.", errCode);
            return;
        }
    }
    changedData_.tableData.clear();
}
}