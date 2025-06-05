/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#define LOG_TAG "RdbSqlStatistic"

#include "rdb_sql_statistic.h"

#include <thread>

#include "concurrent_map.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_platform.h"
#include "task_executor.h"
namespace OHOS::DistributedRdb {
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
ConcurrentMap<SqlObserver *, std::shared_ptr<SqlObserver>> SqlStatistic::observers_;
ConcurrentMap<uint64_t, std::shared_ptr<SqlObserver::SqlExecutionInfo>> SqlStatistic::execInfos_;
bool SqlStatistic::enabled_ = false;
std::atomic_uint32_t SqlStatistic::seqId_ = 0;
int SqlStatistic::Subscribe(std::shared_ptr<SqlObserver> observer)
{
    observers_.ComputeIfAbsent(observer.get(), [observer](auto &) {
        enabled_ = true;
        return observer;
    });
    return E_OK;
}

int SqlStatistic::Unsubscribe(std::shared_ptr<SqlObserver> observer)
{
    observers_.Erase(observer.get());
    observers_.DoActionIfEmpty([]() {
        enabled_ = false;
        execInfos_.Clear();
    });
    return E_OK;
}

SqlStatistic::SqlStatistic(const std::string &sql, int32_t step, uint32_t seqId)
{
    if (!enabled_) {
        return;
    }
    step_ = step;
    key_ = seqId == 0 ? GetThreadId() : uint64_t(seqId);
    time_ = std::chrono::steady_clock::now();
    auto it = execInfos_.Find(key_);
    if (it.first) {
        execInfo_ = it.second;
    }

    if (execInfo_ == nullptr && seqId != 0) {
        it = execInfos_.Find(GetThreadId());
        execInfo_ = it.second;
    }

    if (execInfo_ == nullptr) {
        execInfo_ = std::shared_ptr<SqlExecInfo>(new (std::nothrow) SqlExecInfo(), Release);
        execInfos_.Insert(key_, execInfo_);
    }

    if (step_ == STEP_PREPARE && !sql.empty()) {
        execInfo_->sql_.emplace_back(sql);
    }
}

SqlStatistic::~SqlStatistic()
{
    if (!enabled_) {
        return;
    }
    if (execInfo_ == nullptr) {
        return;
    }
    auto interval = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - time_);
    switch (step_) {
        case STEP_WAIT:
            execInfo_->waitTime_ += interval.count();
            break;
        case STEP_PREPARE:
            execInfo_->prepareTime_ += interval.count();
            break;
        case STEP_EXECUTE:
            execInfo_->executeTime_ += interval.count();
            break;
        case STEP_TOTAL:
        case STEP_TOTAL_RES:
            execInfo_->totalTime_ += interval.count();
            execInfos_.Erase(key_);
            break;
        default:
            execInfo_->totalTime_ += interval.count();
            break;
    }
}

void SqlStatistic::Release(SqlExecInfo *execInfo)
{
    if (execInfo == nullptr) {
        return;
    }
    if (execInfo->sql_.empty()) {
        delete execInfo;
        return;
    }
    auto executor = TaskExecutor::GetInstance().GetExecutor();
    if (executor == nullptr) {
        delete execInfo;
        return;
    }
    executor->Execute([info = std::move(*execInfo)]() {
        observers_.ForEachCopies([&info](auto key, std::shared_ptr<SqlObserver> &observer) {
            if (observer == nullptr) {
                return false;
            }
            observer->OnStatistic(info);
            return false;
        });
    });
    delete execInfo;
}
}