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
#define LOG_TAG "RdbStatReporter"

#include "rdb_stat_reporter.h"

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <unordered_map>

#include "accesstoken_kit.h"
#include "connection.h"
#include "hisysevent_c.h"
#include "ipc_skeleton.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_manager_impl.h"
#include "rdb_time_utils.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
constexpr int32_t TIMEOUT_FIRST = 1500;
constexpr int32_t TIMEOUT_SECOND = 5000;
constexpr int32_t TIMEOUT_THIRD = 10000;
using RdbMgr = DistributedRdb::RdbManagerImpl;

RdbStatReporter::RdbStatReporter(
    StatType statType, SubType subType, const RdbStoreConfig &config, const DistributedRdb::RdbSyncerParam &param)
{
    startTime_ = std::chrono::steady_clock::now();
    statEvent_.statType = static_cast<uint32_t>(statType);
    statEvent_.bundleName = config.GetBundleName();
    statEvent_.storeName = SqliteUtils::Anonymous(config.GetName());
    statEvent_.subType = static_cast<uint32_t>(subType);
    syncerParam_ = param;
}

RdbStatReporter::~RdbStatReporter()
{
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime_).count();
    if (duration >= TIMEOUT_FIRST) {
        statEvent_.costTime = GetTimeType(static_cast<uint32_t>(duration));

        auto [err, service] = RdbMgr::GetInstance().GetRdbService(syncerParam_);
        if (err != E_OK || service == nullptr) {
            LOG_ERROR("GetRdbService failed, err: %{public}d, storeName: %{public}s.", err,
                SqliteUtils::Anonymous(syncerParam_.storeName_).c_str());
            return;
        }
        err = service->ReportStatistic(syncerParam_, statEvent_);
        if (err != E_OK) {
            LOG_ERROR("ReportStatistic failed, err: %{public}d, storeName: %{public}s.", err,
                SqliteUtils::Anonymous(syncerParam_.storeName_).c_str());
        }
    }
}

TimeType RdbStatReporter::GetTimeType(uint32_t costTime)
{
    if (costTime >= TIMEOUT_FIRST && costTime < TIMEOUT_SECOND) {
        return TIME_LEVEL_FIRST;
    } else if (costTime >= TIMEOUT_SECOND && costTime < TIMEOUT_THIRD) {
        return TIME_LEVEL_SECOND;
    }
    return TIME_LEVEL_THIRD;
}

} // namespace OHOS::NativeRdb