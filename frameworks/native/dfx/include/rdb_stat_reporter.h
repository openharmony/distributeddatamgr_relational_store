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

#ifndef RDB_STAT_REPORTER_H
#define RDB_STAT_REPORTER_H

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <string>

#include "connection.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
namespace OHOS::NativeRdb {
enum StatType : int32_t {
    RDB_PERF = 1,
};

enum SubType : int32_t {
    INSERT = 1,
    BATCHINSERT,
    UPDATE,
    DELETE,
    EXECUTESQL,
    EXECUTE,
    BEGINTRANSACTION,
    COMMIT,
    ROLLBACK,
};

enum TimeType : int32_t {
    TIME_LEVEL_FIRST = 1,
    TIME_LEVEL_SECOND,
    TIME_LEVEL_THIRD,
};

class RdbStatReporter {
public:
    RdbStatReporter(
        StatType statType, SubType subType, const RdbStoreConfig &config, const DistributedRdb::RdbSyncerParam &param);
    ~RdbStatReporter();
    static TimeType GetTimeType(uint32_t costTime);
    std::chrono::steady_clock::time_point startTime_;
    DistributedRdb::RdbStatEvent statEvent_;
    DistributedRdb::RdbSyncerParam syncerParam_;
};

} // namespace OHOS::NativeRdb
#endif // RDB_STAT_REPORTER_H