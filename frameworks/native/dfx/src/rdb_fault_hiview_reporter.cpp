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

#include "accesstoken_kit.h"
#include "connection.h"
#include "hisysevent_c.h"
#include "ipc_skeleton.h"
#include "logger.h"
#include "rdb_errno.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
#include "rdb_time_utils.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
using namespace Security::AccessToken;
static constexpr const char *CORRUPTED_EVENT = "DATABASE_CORRUPTED";
static constexpr const char *FAULT_EVENT = "DISTRIBUTED_DATA_RDB_FAULT";
static constexpr const char *DISTRIBUTED_DATAMGR = "DISTDATAMGR";
static constexpr const char *DB_CORRUPTED_POSTFIX = ".corruptedflg";
static constexpr int MAX_FAULT_TIMES = 1;
Connection::Collector RdbFaultHiViewReporter::collector_ = nullptr;
RdbFaultCounter RdbFaultHiViewReporter::faultCounter_ = { 0 };

void RdbFaultHiViewReporter::ReportCorruptedOnce(const RdbCorruptedEvent &eventInfo)
{
    if (IsReportCorruptedFault(eventInfo.path)) {
        RdbCorruptedEvent eventInfoAppend = eventInfo;
        eventInfoAppend.appendix += SqliteUtils::FormatDebugInfo(eventInfoAppend.debugInfos, "");
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
}

void RdbFaultHiViewReporter::ReportCorrupted(const RdbCorruptedEvent &eventInfo)
{
    std::string bundleName = GetBundleName(eventInfo.bundleName, eventInfo.storeName);
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

bool RdbFaultHiViewReporter::IsReportCorruptedFault(const std::string &dbPath)
{
    if (dbPath.empty()) {
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
    if (dbPath.empty()) {
        return;
    }
    std::string flagFilename = dbPath + DB_CORRUPTED_POSTFIX;
    int fd = creat(flagFilename.c_str(), S_IRWXU | S_IRWXG);
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
    const RdbStoreConfig &config, int32_t errCode, const std::string &appendix)
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
    if (collector_ != nullptr && !IsReportCorruptedFault(eventInfo.path)) {
        Update(eventInfo.debugInfos, collector_(config));
    }
    return eventInfo;
}

bool RdbFaultHiViewReporter::RegCollector(Connection::Collector collector)
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

std::string RdbFaultHiViewReporter::GetBundleName(const std::string &bundleName, const std::string &storeName)
{
    if (!bundleName.empty()) {
        return bundleName;
    }
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if ((tokenType == TOKEN_NATIVE) || (tokenType == TOKEN_SHELL)) {
        NativeTokenInfo tokenInfo;
        if (AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo) == 0) {
            return tokenInfo.processName;
        }
    }
    return SqliteUtils::Anonymous(storeName);
}

uint8_t *RdbFaultHiViewReporter::GetFaultCounter(RdbFaultCounter &counter, int32_t errCode)
{
    switch (errCode) {
        case E_SQLITE_FULL:
            return &counter.full;
        case E_SQLITE_CORRUPT:
            return &counter.corrupt;
        case E_SQLITE_PERM:
            return &counter.perm;
        case E_SQLITE_BUSY:
            return &counter.busy;
        case E_SQLITE_NOMEM:
            return &counter.noMem;
        case E_SQLITE_IOERR:
            return &counter.ioErr;
        case E_SQLITE_CANTOPEN:
            return &counter.cantOpen;
        case E_SQLITE_CONSTRAINT:
            return &counter.constraint;
        case E_SQLITE_NOT_DB:
            return &counter.notDb;
        case E_ROOT_KEY_FAULT:
            return &counter.rootKeyFault;
        case E_ROOT_KEY_NOT_LOAD:
            return &counter.rootKeyNotLoad;
        case E_WORK_KEY_FAIL:
            return &counter.workKeyFault;
        case E_WORK_KEY_ENCRYPT_FAIL:
            return &counter.workkeyEencrypt;
        case E_WORK_KEY_DECRYPT_FAIL:
            return &counter.workKeyDcrypt;
        case E_SET_ENCRYPT_FAIL:
            return &counter.setEncrypt;
        case E_SET_NEW_ENCRYPT_FAIL:
            return &counter.setNewEncrypt;
        case E_SET_SERVICE_ENCRYPT_FAIL:
            return &counter.setServiceEncrypt;
        case E_CHECK_POINT_FAIL:
            return &counter.checkPoint;
        default:
            return nullptr;
    };
}

bool RdbFaultHiViewReporter::IsReportFault(const std::string &bundleName, int32_t errCode)
{
    if (bundleName.empty()) {
        return false;
    }
    uint8_t *counter = GetFaultCounter(faultCounter_, errCode);
    if (counter == nullptr) {
        return false;
    }
    if (*counter < UCHAR_MAX) {
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
        { .name = "ERROR_CODE", .t = HISYSEVENT_INT32, .v = { .ui32 = errorCode_ }, .arraySize = 0 },
        { .name = "APPENDIX", .t = HISYSEVENT_STRING, .v = { .s = appendInfo.data() }, .arraySize = 0 },
    };
    auto size = sizeof(params) / sizeof(params[0]);
    OH_HiSysEvent_Write(DISTRIBUTED_DATAMGR, FAULT_EVENT, HISYSEVENT_FAULT, params, size);
}

RdbFaultDbFileEvent::RdbFaultDbFileEvent(const std::string &faultType, int32_t errorCode, const RdbStoreConfig &config,
    const std::string &custLog, bool printDbInfo)
    : RdbFaultEvent(faultType, errorCode, "", custLog), config_(config), printDbInfo_(printDbInfo)
{
    SetBundleName(RdbFaultHiViewReporter::GetBundleName(config_.GetBundleName(), config_.GetName()));
}

RdbEmptyBlobEvent::RdbEmptyBlobEvent(const std::string &bundleName)
    : RdbFaultEvent(FT_CURD, E_SQLITE_FULL, "", "The input blob is empty")
{
    std::string bundleName_ = bundleName;
    SetBundleName(bundleName_);
}

void RdbEmptyBlobEvent::Report() const
{
    std::string occurTime = RdbTimeUtils::GetCurSysTimeWithMs();
    std::string bundleName = GetBundleName();
    std::string faultType = GetFaultType();
    std::string appendInfo = GetLogInfo();
    HiSysEventParam params[] = {
        { .name = "FAULT_TIME", .t = HISYSEVENT_STRING, .v = { .s = occurTime.data() }, .arraySize = 0 },
        { .name = "FAULT_TYPE", .t = HISYSEVENT_STRING, .v = { .s = faultType.data() }, .arraySize = 0 },
        { .name = "BUNDLE_NAME", .t = HISYSEVENT_STRING, .v = { .s = bundleName.data() }, .arraySize = 0 },
        { .name = "ERROR_CODE", .t = HISYSEVENT_INT32, .v = { .ui32 = E_SQLITE_FULL }, .arraySize = 0 },
        { .name = "APPENDIX", .t = HISYSEVENT_STRING, .v = { .s = appendInfo.data() }, .arraySize = 0 },
    };
    auto size = sizeof(params) / sizeof(params[0]);
    OH_HiSysEvent_Write(DISTRIBUTED_DATAMGR, FAULT_EVENT, HISYSEVENT_FAULT, params, size);
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
        { .name = "ERROR_CODE", .t = HISYSEVENT_INT32, .v = { .ui32 = GetErrCode()}, .arraySize = 0 },
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
    dbPath = SqliteUtils::Anonymous(dbPath);
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
    std::string dbFileInfo = SqliteUtils::FormatDebugInfo(
        RdbFaultHiViewReporter::Create(config_, GetErrCode()).debugInfos, "");

    if (GetErrCode() == E_SQLITE_NOT_DB) {
        std::string dbPath;
        SqliteGlobalConfig::GetDbPath(config_, dbPath);
        appendInfo += SqliteUtils::ReadFileHeader(dbPath);
    }
    if (printDbInfo_) {
        appendInfo += ("\n" + BuildConfigLog() + "\n" + dbFileInfo);
    }
    return appendInfo;
}
} // namespace OHOS::NativeRdb