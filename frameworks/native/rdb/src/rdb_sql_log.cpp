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

#define LOG_TAG "RdbSqlLog"

#include "rdb_sql_log.h"

#include <thread>

#include "concurrent_map.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_platform.h"
#include "task_executor.h"

namespace OHOS::NativeRdb {
ConcurrentMap<std::string, std::set<std::shared_ptr<SqlErrorObserver>>> SqlLog::observerSets_;
std::unordered_map<uint64_t, int> SqlLog::suspenders_;
std::mutex SqlLog::mutex_;
std::atomic<bool> SqlLog::enabled_ = false;
int SqlLog::Subscribe(const std::string storeId, std::shared_ptr<SqlErrorObserver> observer)
{
    observerSets_.Compute(storeId, [observer](const std::string& key, auto& observers) {
        observers.insert(observer);
        enabled_ = true;
        return true;
    });
    return E_OK;
}

int SqlLog::Unsubscribe(const std::string storeId, std::shared_ptr<SqlErrorObserver> observer)
{
    observerSets_.ComputeIfPresent(storeId,
        [observer](const std::string& key, std::set<std::shared_ptr<SqlErrorObserver>>& observers) {
            observers.erase(observer);
            return observer !=nullptr && !observers.empty();
        });
    observerSets_.DoActionIfEmpty([]() {
        enabled_ = false;
    });
    return E_OK;
}

void SqlLog::Notify(const std::string &storeId, const ExceptionMessage &exceptionMessage)
{
    if (!enabled_) {
        return;
    }
    {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        auto it = suspenders_.find(GetThreadId());
        if (it != suspenders_.end() && (it->second != 0)) {
            return;
        }
    }
    if (!observerSets_.Contains(storeId)) {
        return;
    }
    auto executor = TaskExecutor::GetInstance().GetExecutor();
    if (executor == nullptr) {
        return;
    }
    executor->Execute([exceptionMessage, storeId]() {
        auto it = observerSets_.Find(storeId);
        if (!it.first) {
            return;
        }
        for (const auto &observer: it.second) {
            if (observer) {
                observer->OnErrorLog(exceptionMessage);
            }
        }
    });
}

void SqlLog::Pause()
{
    if (!enabled_) {
        return;
    }
    uint64_t tid = GetThreadId();
    std::lock_guard<std::mutex> lockGuard(mutex_);
    if (suspenders_.find(tid) == suspenders_.end()) {
        suspenders_[tid] = 0;
    }
    suspenders_[tid]++;
}

void SqlLog::Resume()
{
    if (!enabled_) {
        return;
    }
    uint64_t tid = GetThreadId();
    std::lock_guard<std::mutex> lockGuard(mutex_);
    auto it = suspenders_.find(tid);
    if (it != suspenders_.end()) {
        --it->second;
        if (it->second == 0) {
            suspenders_.erase(it);
        }
    }
}

SqlLog::SqlLog()
{
}

SqlLog::~SqlLog()
{
}

}