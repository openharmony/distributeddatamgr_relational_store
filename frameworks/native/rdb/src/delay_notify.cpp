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
#define LOG_TAG "DelayNotify"
#include "delay_notify.h"
#include "logger.h"
namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
DelayNotify::DelayNotify() : pauseCount_(0), task_(nullptr), pool_(nullptr)
{
}

DelayNotify::~DelayNotify()
{
    if (pool_ == nullptr) {
        return;
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
        if (!v.isTrackedDataChange) {
            continue;
        }
        auto it = changedData_.tableData.find(k);
        if (it == changedData_.tableData.end()) {
            changedData_.tableData.insert_or_assign(k, v);
        }
    }
    StartTimer();
}

void DelayNotify::SetExecutorPool(std::shared_ptr<ExecutorPool> pool)
{
    if (pool_ != nullptr) {
        return;
    }
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
    if (delaySyncTaskId_ == Executor::INVALID_TASK_ID) {
        delaySyncTaskId_ = pool_->Schedule(std::chrono::milliseconds(autoSyncInterval_),
            [this]() { ExecuteTask(); });
    } else {
        delaySyncTaskId_ =
            pool_->Reset(delaySyncTaskId_, std::chrono::milliseconds(autoSyncInterval_));
    }
}

void DelayNotify::StopTimer()
{
    if (pool_ != nullptr) {
        pool_->Remove(delaySyncTaskId_);
    }
    delaySyncTaskId_ = Executor::INVALID_TASK_ID;
}

void DelayNotify::ExecuteTask()
{
    LOG_DEBUG("Notify data change.");
    DistributedRdb::RdbChangedData changedData;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        changedData.tableData = std::move(changedData_.tableData);
        RestoreDefaultSyncInterval();
        StopTimer();
    }
    if (task_ != nullptr && changedData.tableData.size() > 0) {
        int errCode = task_(changedData);
        if (errCode != 0) {
            LOG_ERROR("NotifyDataChange is failed, err is %{public}d.", errCode);
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& [k, v] : changedData.tableData) {
                changedData_.tableData.insert_or_assign(k, v);
            }
            return;
        }
    }
}

void DelayNotify::SetAutoSyncInterval(uint32_t interval)
{
    autoSyncInterval_ = interval;
}

void DelayNotify::RestoreDefaultSyncInterval()
{
    autoSyncInterval_ = AUTO_SYNC_INTERVAL;
}

void DelayNotify::Pause()
{
    StopTimer();
    pauseCount_.fetch_add(1, std::memory_order_relaxed);
}

void DelayNotify::Resume()
{
    pauseCount_.fetch_sub(1, std::memory_order_relaxed);
    if (pauseCount_.load() == 0) {
        StartTimer();
    }
}

PauseDelayNotify::PauseDelayNotify(std::shared_ptr<DelayNotify> delayNotifier) : delayNotifier_(delayNotifier)
{
    if (delayNotifier_ != nullptr) {
        delayNotifier_->Pause();
        delayNotifier_->SetAutoSyncInterval(AUTO_SYNC_MAX_INTERVAL);
    }
}

PauseDelayNotify::~PauseDelayNotify()
{
    if (delayNotifier_ != nullptr) {
        delayNotifier_->Resume();
    }
}
}