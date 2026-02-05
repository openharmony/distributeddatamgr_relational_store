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
#include "rdb_dfx_errno.h"
#include "rdb_visibility.h"
namespace OHOS::NativeRdb {
using DebugInfo = OHOS::DistributedRdb::RdbDebugInfo;
using DfxInfo = OHOS::DistributedRdb::RdbDfxInfo;
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
    DfxInfo dfxInfo;
};

struct RdbFaultCode {
    int nativeCode;
    uint8_t faultCounter;
};

// Fault Type Define
struct RdbFaultType {
    static constexpr const char *FT_OPEN = "OPEN_DB";
    static constexpr const char *FT_CURD = "CURD_DB";
    static constexpr const char *FT_EX_FILE = "EX_FILE";
    static constexpr const char *FT_EX_HUKS = "EX_HUKS";
    static constexpr const char *FT_CP = "CHECK_POINT";
    static constexpr const char *FT_SQLITE = "SQLITE";
    static constexpr const char *FT_WAL_OVER_LIMIT = "WAL_OVER_LIMIT";
    static constexpr const char *FT_HMAC_FILE = "HMAC_FILE";
    static constexpr const char *VISITOR_FAULT = "VISITOR_FAULT";
    static constexpr const char *BUNDLE_NAME_COMMON = "common";
};

class RdbFaultEvent {
public:
    API_EXPORT RdbFaultEvent(const std::string &faultType, int32_t errorCode, const std::string &bundleName,
        const std::string &custLog);

    std::string GetBundleName() const { return bundleName_; };
    std::string GetFaultType() const { return faultType_; }
    int32_t GetErrCode() const { return errorCode_; }
    std::string GetLogInfo() const { return custLog_; };
    virtual void Report() const;
    API_EXPORT virtual ~RdbFaultEvent();

protected:
    void SetBundleName(const std::string &name) { bundleName_ = name; };

private:
    std::string bundleName_;
    std::string faultType_;
    std::string custLog_;
    int32_t errorCode_;
};

class RdbFaultDbFileEvent : public RdbFaultEvent {
public:
    API_EXPORT RdbFaultDbFileEvent(const std::string &faultType, int32_t errorCode, const RdbStoreConfig &config,
        const std::string &custLog = "", bool printDbInfo = false);

    virtual void Report() const override;
    API_EXPORT virtual ~RdbFaultDbFileEvent();

private:
    std::string BuildLogInfo() const;
    std::string BuildConfigLog() const;

    const RdbStoreConfig &config_;
    bool printDbInfo_;
};

class RdbFaultHiViewReporter {
public:
    using Collector =  int32_t (*)(const RdbStoreConfig &config, std::map<std::string,
        DistributedRdb::RdbDebugInfo>&, DistributedRdb::RdbDfxInfo&);
    static RdbCorruptedEvent Create(const RdbStoreConfig &config, int32_t errCode, const std::string &appendix = "",
        bool needSyncParaFromSrv = true);
    static bool RegCollector(Collector collector);
    static void ReportCorrupted(const RdbCorruptedEvent &eventInfo);
    static void ReportCorruptedOnce(const RdbCorruptedEvent &eventInfo);
    API_EXPORT static void ReportFault(const RdbFaultEvent &faultEvent);
    static void ReportRestore(const RdbCorruptedEvent &eventInfo, bool repair = true);
    static bool IsReportCorruptedFault(const std::string &dbPath);
    static std::string GetBundleName(const std::string &bundleName);
    static void ReportRAGFault(const std::string &errMsg, const std::string &functionName,
        const std::string &bundleName, const int faultType, const int errCode);

private:
    static void Update(std::map<std::string, DebugInfo> &localInfos, const std::map<std::string, DebugInfo> &infos);
    static void CreateCorruptedFlag(const std::string &dbPath);
    static void DeleteCorruptedFlag(const std::string &dbPath);
    static bool IsReportFault(const std::string &bundleName, int32_t errCode);
    static uint8_t *GetFaultCounter(int32_t errCode);
    static Collector collector_;
    static RdbFaultCode faultCounters_[];
    static bool memCorruptReportedFlg_;
};
} // namespace OHOS::NativeRdb
#endif // DISTRIBUTEDDATAMGR_RDB_FAULT_HIVIEW_REPORTER_H
