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
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "rdb_types.h"

namespace OHOS {
class ExecutorPool;
namespace NativeRdb {
class DelayNotify : public std::enable_shared_from_this<DelayNotify> {
public:
    using Task = std::function<int(const DistributedRdb::RdbChangedData &, const DistributedRdb::RdbNotifyConfig &)>;
    using Time = std::chrono::steady_clock::time_point;
    DelayNotify();
    ~DelayNotify();
    void SetExecutorPool(std::shared_ptr<ExecutorPool> pool);
    void SetTask(Task task);
    void UpdateNotify(const DistributedRdb::RdbChangedData &changedData, bool isFull = false);
    void SetAutoSyncInterval(uint32_t autoSyncInterval);
    void Pause();
    void Resume();

private:
    static constexpr uint32_t AUTO_SYNC_INTERVAL = 200;
    static constexpr uint32_t MAX_NOTIFY_INTERVAL = 5000;
    static constexpr uint32_t SERVICE_INTERVAL = 10000;
    bool isInitialized_ = false;
    bool isFull_ = false;
    Time lastTimePoint_;
    std::atomic_int32_t pauseCount_;
    uint64_t delaySyncTaskId_ = 0;
    Task task_;
    std::shared_ptr<ExecutorPool> pool_;
    std::mutex mutex_;
    DistributedRdb::RdbChangedData changedData_;

    void StartTimer();
    void StopTimer();
    void ExecuteTask();
    void RestoreDefaultSyncInterval();
    uint32_t autoSyncInterval_ = AUTO_SYNC_INTERVAL;
};

class PauseDelayNotify {
public:
    explicit PauseDelayNotify(std::shared_ptr<DelayNotify> delayNotifier);
    ~PauseDelayNotify();

private:
    static constexpr uint32_t AUTO_SYNC_MAX_INTERVAL = 3000;
    std::shared_ptr<DelayNotify> delayNotifier_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif // NATIVE_RDB_DELAY_NOTIFY_H