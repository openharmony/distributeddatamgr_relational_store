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
ConcurrentMap<uint64_t, bool> SqlLog::enabled_;
int SqlLog::Subscribe(const std::string storeId, std::shared_ptr<SqlErrorObserver> observer)
{
    observerSets_.Compute(storeId, [observer](const std::string& key, auto& observers) {
        observers.insert(observer);
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
    return E_OK;
}

void SqlLog::Notify(const std::string &storeId, const ExceptionMessage &exceptionMessage)
{
    if (enabled_.Contains(GetThreadId())) {
        return;
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
    enabled_.Insert(GetThreadId(), true);
}

void SqlLog::Resume()
{
    enabled_.Erase(GetThreadId());
}

SqlLog::SqlLog()
{
}

SqlLog::~SqlLog()
{
}

}