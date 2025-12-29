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
#define LOG_TAG "RdbFaultHiViewReporter"

#include "rdb_fault_hiview_reporter.h"

#include <fcntl.h>
#include <unistd.h>

#include <chrono>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <limits>

#include "connection.h"
#include "hisysevent_c.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
#include "rdb_time_utils.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
static constexpr const char *CORRUPTED_EVENT = "DATABASE_CORRUPTED";
static constexpr const char *FAULT_EVENT = "DISTRIBUTED_DATA_RDB_FAULT";
static constexpr const char *DISTRIBUTED_DATAMGR = "DISTDATAMGR";
static constexpr const char *DB_CORRUPTED_POSTFIX = ".corruptedflg";
static constexpr int MAX_FAULT_TIMES = 1;
static constexpr const char *RAG_FAULT_EVENT_NAME = "ARKDATA_RAG_FRAMEWORK_FAULT";
RdbFaultHiViewReporter::Collector RdbFaultHiViewReporter::collector_ = nullptr;

RdbFaultCode RdbFaultHiViewReporter::faultCounters_[] = {
    { E_DATABASE_BUSY, 0 },
    { E_CREATE_FOLDER_FAIL, 0 },
    { E_DB_NOT_EXIST, 0 },
    { E_WAL_SIZE_OVER_LIMIT, 0 },
    { E_SQLITE_FULL, 0 },
    { E_SQLITE_ERROR, 0 },
    { E_SQLITE_CORRUPT, 0 },
    { E_SQLITE_PERM, 0 },
    { E_SQLITE_BUSY, 0 },
    { E_SQLITE_LOCKED, 0 },
    { E_SQLITE_NOMEM, 0 },
    { E_SQLITE_IOERR, 0 },
    { E_SQLITE_CANTOPEN, 0 },
    { E_SQLITE_CONSTRAINT, 0 },
    { E_SQLITE_NOT_DB, 0 },
    { E_ROOT_KEY_FAULT, 0 },
    { E_ROOT_KEY_NOT_LOAD, 0 },
    { E_WORK_KEY_FAIL, 0 },
    { E_WORK_KEY_ENCRYPT_FAIL, 0 },
    { E_WORK_KEY_DECRYPT_FAIL, 0 },
    { E_SET_ENCRYPT_FAIL, 0 },
    { E_SET_NEW_ENCRYPT_FAIL, 0 },
    { E_SET_SERVICE_ENCRYPT_FAIL, 0 },
    { E_CHECK_POINT_FAIL, 0 },
    { E_SQLITE_META_RECOVERED, 0 },
    { E_DFX_IS_NOT_CREATE, 0 },
    { E_DFX_IS_DELETE, 0 },
    { E_DFX_IS_RENAME, 0 },
    { E_DFX_IS_NOT_EXIST, 0 },
    { E_DFX_SQLITE_LOG, 0 },
    { E_DFX_BATCH_INSERT_ARGS_SIZE, 0 },
    { E_DFX_GET_JOURNAL_FAIL, 0 },
    { E_DFX_SET_JOURNAL_FAIL, 0 },
    { E_DFX_DUMP_INFO, 0 },
    { E_DFX_GROUPID_INFO, 0 },
    { E_DFX_HUKS_GEN_RANDOM_FAIL, 0 },
    { E_DFX_UPGRADE_KEY_FAIL, 0 },
    { E_DFX_HMAC_KEY_FAIL, 0 },
    { E_DFX_REPLAY_TIMEOUT_FAIL, 0},
    { E_DFX_VISITOR_VERIFY_FAULT, 0 }
};

bool RdbFaultHiViewReporter::memCorruptReportedFlg_ = false;

void RdbFaultHiViewReporter::ReportCorruptedOnce(const RdbCorruptedEvent &eventInfo)
{
    if (IsReportCorruptedFault(eventInfo.path)) {
        RdbCorruptedEvent eventInfoAppend = eventInfo;
        eventInfoAppend.appendix += SqliteUtils::FormatDebugInfo(eventInfoAppend.debugInfos, "");
        eventInfoAppend.appendix += SqliteUtils::FormatDfxInfo(eventInfo.dfxInfo);
        LOG_WARN("Corrupted %{public}s errCode:0x%{public}x [%{public}s]",
            SqliteUtils::Anonymous(eventInfoAppend.storeName).c_str(), eventInfoAppend.errorCode,
            eventInfoAppend.appendix.c_str());
        ReportCorrupted(eventInfoAppend);
        CreateCorruptedFlag(eventInfo.path);
    }
}

void RdbFaultHiViewReporter::ReportRestore(const RdbCorruptedEvent &eventInfo, bool repair)
{
    if (IsReportCorruptedFault(eventInfo.path) && repair) {
        return;
    }
    RdbCorruptedEvent eventInfoAppend = eventInfo;
    eventInfoAppend.appendix += SqliteUtils::FormatDebugInfo(eventInfoAppend.debugInfos, "");
    LOG_INFO("Restored %{public}s errCode:0x%{public}x [%{public}s]",
        SqliteUtils::Anonymous(eventInfo.storeName).c_str(), eventInfo.errorCode, eventInfoAppend.appendix.c_str());
    ReportCorrupted(eventInfoAppend);
    DeleteCorruptedFlag(eventInfo.path);
    memCorruptReportedFlg_ = false;
}

void RdbFaultHiViewReporter::ReportCorrupted(const RdbCorruptedEvent &eventInfo)
{
    std::string bundleName = GetBundleName(eventInfo.bundleName);
    if (bundleName.empty()) {
        return;
    }
    std::string moduleName = eventInfo.moduleName;
    std::string storeType = eventInfo.storeType;
    std::string storeName = eventInfo.storeName;
    uint32_t checkType = eventInfo.integrityCheck;
    std::string appendInfo = eventInfo.appendix;
    std::string occurTime = RdbTimeUtils::GetCurSysTimeWithMs();
    HiSysEventParam params[] = {
        { .name = "BUNDLE_NAME", .t = HISYSEVENT_STRING, .v = { .s = bundleName.data() }, .arraySize = 0 },
        { .name = "MODULE_NAME", .t = HISYSEVENT_STRING, .v = { .s = moduleName.data() }, .arraySize = 0 },
        { .name = "STORE_TYPE", .t = HISYSEVENT_STRING, .v = { .s = storeType.data() }, .arraySize = 0 },
        { .name = "STORE_NAME", .t = HISYSEVENT_STRING, .v = { .s = storeName.data() }, .arraySize = 0 },
        { .name = "SECURITY_LEVEL", .t = HISYSEVENT_UINT32, .v = { .ui32 = eventInfo.securityLevel }, .arraySize = 0 },
        { .name = "PATH_AREA", .t = HISYSEVENT_UINT32, .v = { .ui32 = eventInfo.pathArea }, .arraySize = 0 },
        { .name = "ENCRYPT_STATUS", .t = HISYSEVENT_UINT32, .v = { .ui32 = eventInfo.encryptStatus }, .arraySize = 0 },
        { .name = "INTEGRITY_CHECK", .t = HISYSEVENT_UINT32, .v = { .ui32 = checkType }, .arraySize = 0 },
        { .name = "ERROR_CODE", .t = HISYSEVENT_UINT32, .v = { .ui32 = eventInfo.errorCode }, .arraySize = 0 },
        { .name = "ERRNO", .t = HISYSEVENT_INT32, .v = { .i32 = eventInfo.systemErrorNo }, .arraySize = 0 },
        { .name = "APPENDIX", .t = HISYSEVENT_STRING, .v = { .s = appendInfo.data() }, .arraySize = 0 },
        { .name = "ERROR_TIME", .t = HISYSEVENT_STRING, .v = { .s = occurTime.data() }, .arraySize = 0 },
    };
    auto size = sizeof(params) / sizeof(params[0]);
    OH_HiSysEvent_Write(DISTRIBUTED_DATAMGR, CORRUPTED_EVENT, HISYSEVENT_FAULT, params, size);
}

void RdbFaultHiViewReporter::ReportRAGFault(const std::string &errMsg, const std::string &functionName,
    const std::string &bundleName, const int faultType, const int errCode)
{
    std::string appendix = "";
    HiSysEventParam params[] = {
        { .name = "FAULT_TYPE", .t = HISYSEVENT_INT32,
            .v = { .ui32 =  faultType}, .arraySize = 0 },
        { .name = "ERROR_CODE", .t = HISYSEVENT_INT32,
            .v = { .ui32 =  errCode}, .arraySize = 0 },
        { .name = "ERROR_MESSAGE", .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(errMsg.c_str()) }, .arraySize = 0 },
        { .name = "BUNDLE_NAME", .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(bundleName.c_str()) }, .arraySize = 0 },
        { .name = "FUNCTION_NAME", .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(functionName.c_str()) }, .arraySize = 0 },
        { .name = "APPENDIX", .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(appendix.c_str()) }, .arraySize = 0 },
    };
 
    OH_HiSysEvent_Write(DISTRIBUTED_DATAMGR, RAG_FAULT_EVENT_NAME,
        HISYSEVENT_FAULT, params, sizeof(params) / sizeof(params[0]));
}

bool RdbFaultHiViewReporter::IsReportCorruptedFault(const std::string &dbPath)
{
    if (dbPath.empty() || memCorruptReportedFlg_) {
        return false;
    }

    std::string flagFilename = dbPath + DB_CORRUPTED_POSTFIX;
    if (access(flagFilename.c_str(), F_OK) == 0) {
        return false;
    }
    return true;
}

void RdbFaultHiViewReporter::CreateCorruptedFlag(const std::string &dbPath)
{
    memCorruptReportedFlg_ = true;
    if (dbPath.empty()) {
        return;
    }
    std::string flagFilename = dbPath + DB_CORRUPTED_POSTFIX;
    int fd = creat(flagFilename.c_str(), S_IRUSR | S_IWUSR);
    if (fd == -1) {
        LOG_WARN("Creat corrupted flg fail, flgname=%{public}s, errno=%{public}d",
            SqliteUtils::Anonymous(flagFilename).c_str(), errno);
        return;
    }
    close(fd);
}

void RdbFaultHiViewReporter::DeleteCorruptedFlag(const std::string &dbPath)
{
    if (dbPath.empty()) {
        return;
    }
    std::string flagFilename = dbPath + DB_CORRUPTED_POSTFIX;
    int result = remove(flagFilename.c_str());
    if (result != 0) {
        LOG_WARN("Remove corrupted flg fail, flgname=%{public}s, errno=%{public}d",
            SqliteUtils::Anonymous(flagFilename).c_str(), errno);
    }
}

RdbCorruptedEvent RdbFaultHiViewReporter::Create(
    const RdbStoreConfig &config, int32_t errCode, const std::string &appendix, bool needSyncParaFromSrv)
{
    RdbCorruptedEvent eventInfo;
    eventInfo.bundleName = config.GetBundleName();
    eventInfo.moduleName = config.GetModuleName();
    eventInfo.storeType = config.GetDBType() == DB_SQLITE ? "RDB" : "VECTOR DB";
    eventInfo.storeName = SqliteUtils::Anonymous(config.GetName());
    eventInfo.securityLevel = static_cast<uint32_t>(config.GetSecurityLevel());
    eventInfo.pathArea = static_cast<uint32_t>(config.GetArea());
    eventInfo.encryptStatus = static_cast<uint32_t>(config.IsEncrypt());
    eventInfo.integrityCheck = static_cast<uint32_t>(config.GetIntegrityCheck());
    eventInfo.errorCode = static_cast<uint32_t>(errCode);
    eventInfo.systemErrorNo = errCode == E_OK ? 0 : errno;
    eventInfo.appendix = appendix;
    eventInfo.errorOccurTime = time(nullptr);
    eventInfo.debugInfos = Connection::Collect(config);
    SqliteGlobalConfig::GetDbPath(config, eventInfo.path);
    if (collector_ != nullptr && needSyncParaFromSrv) {
        std::map<std::string, DistributedRdb::RdbDebugInfo> serviceDebugInfos;
        if (collector_(config, serviceDebugInfos, eventInfo.dfxInfo) == E_OK) {
            Update(eventInfo.debugInfos, serviceDebugInfos);
        }
    }
    return eventInfo;
}

bool RdbFaultHiViewReporter::RegCollector(Collector collector)
{
    if (collector_ != nullptr) {
        return false;
    }
    collector_ = collector;
    return true;
}

void RdbFaultHiViewReporter::Update(std::map<std::string, DebugInfo> &localInfos,
    const std::map<std::string, DebugInfo> &infos)
{
    auto &local = localInfos;
    auto lIt = local.begin();
    auto rIt = infos.begin();
    for (; lIt != local.end() && rIt != infos.end();) {
        if (lIt->first == rIt->first) {
            if (lIt->second.inode_ != rIt->second.inode_) {
                lIt->second.oldInode_ = rIt->second.inode_;
            }
            ++lIt;
            ++rIt;
            continue;
        }
        if (lIt->first < rIt->first) {
            ++lIt;
        } else {
            ++rIt;
        }
    }
}

std::string RdbFaultHiViewReporter::GetBundleName(const std::string &bundleName)
{
    if (!bundleName.empty()) {
        return bundleName;
    }
    return RdbHelper::GetSelfBundleName();
}

uint8_t *RdbFaultHiViewReporter::GetFaultCounter(int32_t errCode)
{
    auto it = std::lower_bound(faultCounters_, faultCounters_ + sizeof(faultCounters_) / sizeof(RdbFaultCode), errCode,
        [](const RdbFaultCode& faultCode, int32_t code) {
            return faultCode.nativeCode < code;
        });
    if (it != faultCounters_ + sizeof(faultCounters_) / sizeof(RdbFaultCode) && it->nativeCode == errCode) {
        return &it->faultCounter;
    }
    return nullptr;
}

bool RdbFaultHiViewReporter::IsReportFault(const std::string &bundleName, int32_t errCode)
{
    if (bundleName.empty()) {
        return false;
    }
    uint8_t *counter = GetFaultCounter(errCode);
    if (counter == nullptr) {
        return false;
    }
    if (*counter < UINT8_MAX) {
        (*counter)++;
    }
    return *counter <= MAX_FAULT_TIMES;
}

void RdbFaultHiViewReporter::ReportFault(const RdbFaultEvent &faultEvent)
{
    if (!IsReportFault(faultEvent.GetBundleName(), faultEvent.GetErrCode())) {
        return;
    }
    faultEvent.Report();
}

RdbFaultEvent::RdbFaultEvent(const std::string &faultType, int32_t errorCode, const std::string &bundleName,
    const std::string &custLog)
{
    faultType_ = faultType;
    errorCode_ = errorCode;
    bundleName_ = bundleName;
    custLog_ = custLog;
}

void RdbFaultEvent::Report() const
{
    std::string occurTime = RdbTimeUtils::GetCurSysTimeWithMs();
    std::string bundleName = GetBundleName();
    std::string faultType = GetFaultType();
    std::string appendInfo = GetLogInfo();
    HiSysEventParam params[] = {
        { .name = "FAULT_TIME", .t = HISYSEVENT_STRING, .v = { .s = occurTime.data() }, .arraySize = 0 },
        { .name = "FAULT_TYPE", .t = HISYSEVENT_STRING, .v = { .s = faultType.data() }, .arraySize = 0 },
        { .name = "BUNDLE_NAME", .t = HISYSEVENT_STRING, .v = { .s = bundleName.data() }, .arraySize = 0 },
        { .name = "ERROR_CODE", .t = HISYSEVENT_INT32, .v = { .ui32 = static_cast<uint32_t>(errorCode_) },
            .arraySize = 0 },
        { .name = "APPENDIX", .t = HISYSEVENT_STRING, .v = { .s = appendInfo.data() }, .arraySize = 0 },
    };
    auto size = sizeof(params) / sizeof(params[0]);
    OH_HiSysEvent_Write(DISTRIBUTED_DATAMGR, FAULT_EVENT, HISYSEVENT_FAULT, params, size);
}

RdbFaultDbFileEvent::RdbFaultDbFileEvent(const std::string &faultType, int32_t errorCode, const RdbStoreConfig &config,
    const std::string &custLog, bool printDbInfo)
    : RdbFaultEvent(faultType, errorCode, config.GetBundleName(), custLog), config_(config), printDbInfo_(printDbInfo)
{
}

void RdbFaultDbFileEvent::Report() const
{
    std::string occurTime = RdbTimeUtils::GetCurSysTimeWithMs();
    std::string bundleName = GetBundleName();
    std::string faultType = GetFaultType();
    std::string moduleName = config_.GetModuleName();
    std::string storeName = config_.GetName();
    std::string businessType = config_.GetDBType() == DB_SQLITE ? "SQLITE" : "VECTOR";
    std::string appendInfo = BuildLogInfo();

    HiSysEventParam params[] = {
        { .name = "FAULT_TIME", .t = HISYSEVENT_STRING, .v = { .s = occurTime.data() }, .arraySize = 0 },
        { .name = "FAULT_TYPE", .t = HISYSEVENT_STRING, .v = { .s = faultType.data() }, .arraySize = 0 },
        { .name = "BUNDLE_NAME", .t = HISYSEVENT_STRING, .v = { .s = bundleName.data() }, .arraySize = 0 },
        { .name = "MODULE_NAME", .t = HISYSEVENT_STRING, .v = { .s = moduleName.data() }, .arraySize = 0 },
        { .name = "STORE_NAME", .t = HISYSEVENT_STRING, .v = { .s = storeName.data() }, .arraySize = 0 },
        { .name = "BUSINESS_TYPE", .t = HISYSEVENT_STRING, .v = { .s = businessType.data() }, .arraySize = 0 },
        { .name = "ERROR_CODE", .t = HISYSEVENT_INT32, .v = { .ui32 = static_cast<uint32_t>(GetErrCode())},
            .arraySize = 0 },
        { .name = "APPENDIX", .t = HISYSEVENT_STRING, .v = { .s = appendInfo.data() }, .arraySize = 0 },
    };
    auto size = sizeof(params) / sizeof(params[0]);
    OH_HiSysEvent_Write(DISTRIBUTED_DATAMGR, FAULT_EVENT, HISYSEVENT_FAULT, params, size);
}

std::string RdbFaultDbFileEvent::BuildConfigLog() const
{
    std::string errNoStr = std::to_string(static_cast<uint32_t>(errno));
    std::string dbPath;
    SqliteGlobalConfig::GetDbPath(config_, dbPath);
    std::vector<std::pair<std::string, std::string>> logInfo;
    logInfo.emplace_back("S_L", std::to_string(static_cast<uint32_t>(config_.GetSecurityLevel())));
    logInfo.emplace_back("P_A", std::to_string(static_cast<uint32_t>(config_.GetArea())));
    logInfo.emplace_back("E_S", std::to_string(static_cast<uint32_t>(config_.IsEncrypt())));
    logInfo.emplace_back("I_C", std::to_string(static_cast<uint32_t>(config_.GetIntegrityCheck())));
    logInfo.emplace_back("ENO", errNoStr);
    logInfo.emplace_back("PATH", dbPath);
    std::stringstream oss;
    for (size_t i = 0; i < logInfo.size(); i++) {
        oss << logInfo[i].first << ":" << logInfo[i].second;
        if (i != logInfo.size() - 1) {
            oss << "," << std::endl;
        }
    }
    return oss.str();
}

std::string RdbFaultDbFileEvent::BuildLogInfo() const
{
    std::string appendInfo = GetLogInfo();
    if (GetErrCode() == E_SQLITE_NOT_DB) {
        std::string dbPath;
        SqliteGlobalConfig::GetDbPath(config_, dbPath);
        appendInfo += SqliteUtils::ReadFileHeader(dbPath);
    }
    if (printDbInfo_) {
        RdbCorruptedEvent eventInfo = RdbFaultHiViewReporter::Create(config_, GetErrCode());
        appendInfo += ("\n" + BuildConfigLog() + "\n" + SqliteUtils::FormatDfxInfo(eventInfo.dfxInfo) + "\n" +
            SqliteUtils::FormatDebugInfo(eventInfo.debugInfos, ""));
    }
    return appendInfo;
}
} // namespace OHOS::NativeRdb