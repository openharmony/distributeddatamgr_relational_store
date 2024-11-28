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

#ifndef DISTRIBUTEDDATAMGR_RDB_FAULT_HIVIEW_REPORTER_H
#define DISTRIBUTEDDATAMGR_RDB_FAULT_HIVIEW_REPORTER_H

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <string>

#include "connection.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
namespace OHOS::NativeRdb {
using DebugInfo = OHOS::DistributedRdb::RdbDebugInfo;
struct RdbCorruptedEvent {
    std::string bundleName;
    std::string moduleName;
    std::string storeType;
    std::string storeName;
    uint32_t securityLevel;
    uint32_t pathArea;
    uint32_t encryptStatus;
    uint32_t integrityCheck;
    uint32_t errorCode;
    int32_t systemErrorNo;
    std::string appendix;
    time_t errorOccurTime;
    std::string path;
    std::map<std::string, DebugInfo> debugInfos;
};

class RdbFaultHiViewReporter {
public:
    static RdbCorruptedEvent Create(const RdbStoreConfig &config, int32_t errCode, const std::string &appendix = "");
    static bool RegCollector(Connection::Collector collector);
    static void Report(const RdbCorruptedEvent &eventInfo);
    static void ReportFault(const RdbCorruptedEvent &eventInfo);
    static void ReportRestore(const RdbCorruptedEvent &eventInfo, bool repair = true);
    static std::string Format(const std::map<std::string, DebugInfo> &debugs, const std::string &header);
    static std::string FormatBrief(const std::map<std::string, DebugInfo> &debugs, const std::string &header);
    static bool IsReportCorruptedFault(const std::string &dbPath);

private:
    static void Update(RdbCorruptedEvent &eventInfo, const std::map<std::string, DebugInfo> &infos);
    static std::string GetFileStatInfo(const DebugInfo &debugInfo);
    static void CreateCorruptedFlag(const std::string &dbPath);
    static void DeleteCorruptedFlag(const std::string &dbPath);
    static std::string GetTimeWithMilliseconds(time_t sec, int64_t nsec);
    static std::string GetBundleName(const RdbCorruptedEvent &eventInfo);
    static Connection::Collector collector_;
};
} // namespace OHOS::NativeRdb
#endif //DISTRIBUTEDDATAMGR_RDB_FAULT_HIVIEW_REPORTER_H
