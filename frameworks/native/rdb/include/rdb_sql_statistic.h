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

#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_SQL_STATISTIC_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_SQL_STATISTIC_H
#include <atomic>
#include <chrono>
#include <memory>

#include "rdb_types.h"
#include "rdb_visibility.h"

namespace OHOS {
template<typename _Key, typename _Tp>
class ConcurrentMap;
namespace DistributedRdb {
class SqlStatistic {
public:
    enum Step : int32_t {
        STEP_TOTAL,
        STEP_TOTAL_REF,
        STEP_TOTAL_RES,
        STEP_WAIT,
        STEP_PREPARE,
        STEP_EXECUTE,
        STEP_BUTT,
    };
    API_EXPORT static int Subscribe(std::shared_ptr<SqlObserver> observer);
    API_EXPORT static int Unsubscribe(std::shared_ptr<SqlObserver> observer);
    static uint32_t GenerateId();
    SqlStatistic(const std::string &sql, int32_t step, uint32_t seqId = 0);
    ~SqlStatistic();

private:
    using SqlExecInfo = SqlObserver::SqlExecutionInfo;
    static void Release(SqlExecInfo *execInfo);
    static ConcurrentMap<SqlObserver *, std::shared_ptr<SqlObserver>> observers_;
    static ConcurrentMap<uint64_t, std::shared_ptr<SqlExecInfo>> execInfos_;
    static bool enabled_;
    static std::atomic_uint32_t seqId_;
    int32_t step_ = 0;
    uint64_t key_ = 0;
    std::chrono::steady_clock::time_point time_;
    std::shared_ptr<SqlExecInfo> execInfo_;
};
} // namespace DistributedRdb
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_SQL_STATISTIC_H
