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

struct RdbFaultCounter {
    uint8_t full{ 0 };
    uint8_t corrupt{ 0 };
    uint8_t perm{ 0 };
    uint8_t busy{ 0 };
    uint8_t noMem{ 0 };
    uint8_t ioErr{ 0 };
    uint8_t cantOpen{ 0 };
    uint8_t constraint{ 0 };
    uint8_t notDb{ 0 };
    uint8_t rootKeyFault{ 0 };
    uint8_t rootKeyNotLoad{ 0 };
    uint8_t workKeyFault{ 0 };
    uint8_t workkeyEencrypt{ 0 };
    uint8_t workKeyDcrypt{ 0 };
    uint8_t setEncrypt{ 0 };
    uint8_t setNewEncrypt{ 0 };
    uint8_t setServiceEncrypt{ 0 };
    uint8_t checkPoint{ 0 };
};

// Fault Type Define
static constexpr const char *FT_OPEN = "OPEN_DB";
static constexpr const char *FT_CURD = "CURD_DB";
static constexpr const char *FT_EX_FILE = "EX_FILE";
static constexpr const char *FT_EX_HUKS = "EX_HUKS";
static constexpr const char *FT_CP = "CHECK_POINT";

class RdbFaultEvent {
public:
    RdbFaultEvent(const std::string &faultType, int32_t errorCode, const std::string &bundleName,
        const std::string &custLog);

public:
    std::string GetBundleName() { return bundleName_; };
    std::string GetFaultType() { return faultType_; }
    int32_t GetErrCode() { return errorCode_; }
    virtual std::string GetLogInfo() { return custLog_; };
    virtual std::string GetModuleName() { return ""; }
    virtual std::string GetStoreName() { return ""; }
    virtual std::string GetBusinessType() { return ""; }

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
    RdbFaultDbFileEvent(const std::string &faultType, int32_t errorCode, const RdbStoreConfig &config,
        const std::string &custLog = "", bool printDbInfo = false);

public:
    std::string GetLogInfo() override;
    std::string GetModuleName() override;
    std::string GetStoreName() override;
    std::string GetBusinessType() override;

private:
    std::string GetConfigLog();
    const RdbStoreConfig &config_;
    bool printDbInfo_;
};
class RdbFaultHiViewReporter {
public:
    static RdbCorruptedEvent Create(const RdbStoreConfig &config, int32_t errCode, const std::string &appendix = "");
    static bool RegCollector(Connection::Collector collector);
    static void ReportCorrupted(const RdbCorruptedEvent &eventInfo);
    static void ReportCorruptedOnce(const RdbCorruptedEvent &eventInfo);
    static void ReportFault(const RdbFaultEvent &faultEvent);
    static void ReportRestore(const RdbCorruptedEvent &eventInfo, bool repair = true);
    static bool IsReportCorruptedFault(const std::string &dbPath);
    static std::string GetBundleName(const std::string &bundleName, const std::string &storeName);

private:
    static void Update(std::map<std::string, DebugInfo> &localInfos, const std::map<std::string, DebugInfo> &infos);
    static void CreateCorruptedFlag(const std::string &dbPath);
    static void DeleteCorruptedFlag(const std::string &dbPath);
    static bool IsReportFault(const std::string &bundleName, int32_t errCode);
    static uint8_t *GetFaultCounter(RdbFaultCounter &counter, int32_t errCode);
    static Connection::Collector collector_;
    static RdbFaultCounter faultCounter_;
};
} // namespace OHOS::NativeRdb
#endif // DISTRIBUTEDDATAMGR_RDB_FAULT_HIVIEW_REPORTER_H
