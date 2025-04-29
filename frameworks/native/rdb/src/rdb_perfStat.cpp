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

#define LOG_TAG "RdbPerfStat"
#include "rdb_perfStat.h"

#include <thread>

#include "concurrent_map.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_platform.h"
#include "task_executor.h"
#include "sqlite_utils.h"
namespace OHOS::DistributedRdb {
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using SqlExecInfo = SqlObserver::SqlExecutionInfo;

ConcurrentMap<std::string, std::set<std::shared_ptr<SqlObserver>>> PerfStat::observers_;
ConcurrentMap<uint64_t, std::shared_ptr<SqlExecInfo>> PerfStat::execInfos_;
thread_local int32_t PerfStat::suspenders_ = 0;
bool PerfStat::enabled_ = false;
std::atomic_uint32_t PerfStat::seqId_ = 0;
thread_local size_t PerfStat::size_ = 0;
int PerfStat::Subscribe(const std::string &storeId, std::shared_ptr<SqlObserver> observer)
{
    observers_.Compute(storeId, [observer](const auto&, auto& observers) {
        observers.insert(observer);
        enabled_ = true;
        return true;
    });
    return E_OK;
}

int PerfStat::Unsubscribe(const std::string &storeId, std::shared_ptr<SqlObserver> observer)
{
    observers_.ComputeIfPresent(storeId, [observer](const auto& key, auto& observers) {
        observers.erase(observer);
        return !observers.empty();
    });
    observers_.DoActionIfEmpty([]() {
        enabled_ = false;
        execInfos_.Clear();
    });
    return E_OK;
}

uint32_t PerfStat::GenerateId()
{
    return ++seqId_;
}

PerfStat::PerfStat(const std::string &storeId, const std::string &sql, int32_t step, uint32_t seqId, size_t size)
{
    if (!enabled_ || suspenders_ > 0) {
        return;
    }
    auto storeObservers = observers_.Find(storeId);
    if (!storeObservers.first) {
        return;
    }

    step_ = step;
    key_ = (seqId == 0) ? GetThreadId() : uint64_t(seqId);
    time_ = std::chrono::steady_clock::now();

    if (step == STEP_TOTAL || step == STEP_TRANS || step == STEP_TRANS_END) {
        execInfo_ = std::shared_ptr<SqlExecInfo>(new (std::nothrow) SqlExecInfo(), GetRelease(step, seqId, storeId));
        execInfos_.Insert(GetThreadId(), execInfo_);
    } else {
        auto it = execInfos_.Find(key_);
        if (it.first) {
            execInfo_ = it.second;
        }
    }

    if (execInfo_ == nullptr && seqId != 0) {
        auto it = execInfos_.Find(GetThreadId());
        execInfo_ = it.second;
    }

    if (step_ == STEP_TRANS_START && execInfo_ != nullptr) {
        execInfos_.Insert(seqId, execInfo_);
    }

    if ((step_ == STEP_TOTAL || step_ == STEP_TRANS) && size > 0) {
        size_ = size;
    }

    if (step_ == STEP_PREPARE && !sql.empty() && execInfo_ != nullptr) {
        execInfo_->sql_.emplace_back(FormatSql(sql));
    }
}


PerfStat::~PerfStat()
{
    if (!enabled_ || suspenders_ > 0) {
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
            size_ = 0;
        case STEP_TOTAL_RES:
            execInfo_->totalTime_ += interval.count();
            execInfos_.Erase(key_);
            break;
        case STEP_TRANS:
            execInfo_->totalTime_ += interval.count();
            execInfos_.Erase(GetThreadId());
            size_ = 0;
            break;
        case STEP_TRANS_END:
            execInfo_->totalTime_ += interval.count();
            execInfos_.Erase(GetThreadId());
            execInfo_ = nullptr;
            execInfos_.Erase(key_);
            break;
        default:
            execInfo_->totalTime_ += interval.count();
            break;
    }
}

PerfStat::Release PerfStat::GetRelease(int32_t step, uint32_t seqId, const std::string &storeId)
{
    switch (step) {
        case STEP_TRANS:
        case STEP_TRANS_END:
            return [seqId](SqlExecInfo *execInfo) {
                Merge(seqId, execInfo);
            };
        default:
            return [seqId, storeId](SqlExecInfo *execInfo) {
                Notify(execInfo, storeId);
            };
    }
}

void PerfStat::Merge(uint32_t seqId, SqlExecInfo *execInfo)
{
    if (execInfo == nullptr) {
        return;
    }
    if (execInfo->sql_.empty()) {
        delete execInfo;
        return;
    }
    execInfos_.ComputeIfPresent(seqId, [execInfo](const auto &, std::shared_ptr<SqlExecInfo> info) {
        info->totalTime_ += execInfo->totalTime_;
        info->waitTime_ += execInfo->waitTime_;
        info->prepareTime_ += execInfo->prepareTime_;
        info->executeTime_ += execInfo->executeTime_;
        info->sql_.insert(info->sql_.end(), execInfo->sql_.begin(), execInfo->sql_.end());
        return true;
    });
    delete execInfo;
}

void PerfStat::Notify(SqlExecInfo *execInfo, const std::string &storeId)
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
    executor->Execute([info = std::move(*execInfo), storeId]() {
        std::set<std::shared_ptr<SqlObserver>> sqlObservers;
        observers_.ComputeIfPresent(storeId, [&sqlObservers](const auto &, auto &observers) {
            sqlObservers = observers;
            return true;
        });
        for (auto &obs : sqlObservers) {
            if (obs != nullptr) {
                obs->OnStatistic(info);
            }
        }
    });
    delete execInfo;
}
void PerfStat::Pause(uint32_t seqId)
{
    ++suspenders_;
}
void PerfStat::Resume(uint32_t seqId)
{
    if (suspenders_ > 0) {
        --suspenders_;
    }
}

std::string PerfStat::FormatSql(const std::string& sql)
{
    if (size_ == 0) {
        return sql;
    }
    size_t firstPos = sql.find("),(");
    if (firstPos != std::string::npos) {
        std::string newSql = sql.substr(0, firstPos + 1);
        newSql.append(",...,").append(std::to_string(size_));
        return newSql;
    }
    return sql;
}
}