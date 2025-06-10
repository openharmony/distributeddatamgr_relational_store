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

#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_NATIVE_RDB_PERFSTAT_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_NATIVE_RDB_PERFSTAT_H
#include <atomic>
#include <chrono>
#include <shared_mutex>
#include <memory>
#include <list>

#include "rdb_types.h"
#include "rdb_visibility.h"

namespace OHOS {
template<typename _Key, typename _Tp>
class ConcurrentMap;
namespace DistributedRdb {
class PerfStat {
public:
    struct ThreadParam {
        int32_t suspenders_ = 0;
        size_t size_ = 0;
    };
    enum Step : int32_t {
        STEP_TOTAL,
        STEP_TOTAL_REF,
        STEP_TOTAL_RES,
        STEP_WAIT,
        STEP_PREPARE,
        STEP_EXECUTE,
        STEP_TRANS_START,
        STEP_TRANS,
        STEP_TRANS_END,
        STEP_BUTT,
    };
    API_EXPORT static int Subscribe(const std::string &storeId, std::shared_ptr<SqlObserver> observer);
    API_EXPORT static int Unsubscribe(const std::string &storeId, std::shared_ptr<SqlObserver> observer);
    static uint32_t GenerateId();
    static void Pause(uint32_t seqId = 0);
    static void Resume(uint32_t seqId = 0);

    ~PerfStat();
    PerfStat(const std::string &storeId, const std::string &sql, int32_t step, uint32_t seqId = 0, size_t size = 0);

private:
    using SqlExecInfo = SqlObserver::SqlExecutionInfo;
    using Release = std::function<void(SqlExecInfo *)>;
    void FormatSql(const std::string& sql);
    static Release GetRelease(int32_t step, uint32_t seqId, const std::string &storeId);
    static void Merge(uint32_t seqId, SqlExecInfo *execInfo);
    static void Notify(SqlExecInfo *execInfo, const std::string &storeId);
    static bool IsPaused();
    static size_t GetSize();
    static void SetSize(size_t size);
    static ConcurrentMap<std::string, std::set<std::shared_ptr<SqlObserver>>> observers_;
    static ConcurrentMap<uint64_t, std::shared_ptr<SqlExecInfo>> execInfos_;
    static bool enabled_;
    static std::atomic_uint32_t seqId_;
    static std::shared_mutex mutex_;
    static std::map<uint64_t, ThreadParam> threadParams_;

    int32_t step_ = 0;
    uint64_t key_ = 0;
    std::chrono::steady_clock::time_point time_;
    std::shared_ptr<SqlExecInfo> execInfo_;
};
} // namespace DistributedRdb
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_NATIVE_RDB_PERFSTAT_H