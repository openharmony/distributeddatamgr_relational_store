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
#include <ctime>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <unordered_map>

#include "accesstoken_kit.h"
#include "connection.h"
#include "hisysevent_c.h"
#include "ipc_skeleton.h"
#include "logger.h"
#include "rdb_errno.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
using namespace Security::AccessToken;
static constexpr const char *EVENT_NAME = "DATABASE_CORRUPTED";
static constexpr const char *DISTRIBUTED_DATAMGR = "DISTDATAMGR";
static constexpr const char *DB_CORRUPTED_POSTFIX = ".corruptedflg";
static constexpr int MAX_TIME_BUF_LEN = 32;
static constexpr int MILLISECONDS_LEN = 3;
static constexpr int NANO_TO_MILLI = 1000000;
static constexpr int MILLI_PRE_SEC = 1000;
Connection::Collector RdbFaultHiViewReporter::collector_ = nullptr;

void RdbFaultHiViewReporter::ReportFault(const RdbCorruptedEvent &eventInfo)
{
    if (IsReportCorruptedFault(eventInfo.path)) {
        RdbCorruptedEvent eventInfoAppend = eventInfo;
        eventInfoAppend.appendix += Format(eventInfoAppend.debugInfos, "");
        LOG_WARN("Corrupted %{public}s errCode:0x%{public}x [%{public}s]",
            SqliteUtils::Anonymous(eventInfoAppend.storeName).c_str(), eventInfoAppend.errorCode,
            eventInfoAppend.appendix.c_str());
        Report(eventInfoAppend);
        CreateCorruptedFlag(eventInfo.path);
    }
}

void RdbFaultHiViewReporter::ReportRestore(const RdbCorruptedEvent &eventInfo, bool repair)
{
    if (IsReportCorruptedFault(eventInfo.path) && repair) {
        return;
    }
    RdbCorruptedEvent eventInfoAppend = eventInfo;
    eventInfoAppend.appendix += Format(eventInfoAppend.debugInfos, "");
    LOG_INFO("Restored %{public}s errCode:0x%{public}x [%{public}s]",
        SqliteUtils::Anonymous(eventInfo.storeName).c_str(), eventInfo.errorCode, eventInfoAppend.appendix.c_str());
    Report(eventInfoAppend);
    DeleteCorruptedFlag(eventInfo.path);
}

void RdbFaultHiViewReporter::Report(const RdbCorruptedEvent &eventInfo)
{
    std::string bundleName = GetBundleName(eventInfo);
    std::string moduleName = eventInfo.moduleName;
    std::string storeType = eventInfo.storeType;
    std::string storeName = eventInfo.storeName;
    uint32_t checkType = eventInfo.integrityCheck;
    std::string appendInfo = eventInfo.appendix;
    std::string occurTime = GetTimeWithMilliseconds(eventInfo.errorOccurTime, 0);
    char *errorOccurTime = occurTime.data();
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
        { .name = "ERROR_TIME", .t = HISYSEVENT_STRING, .v = { .s = errorOccurTime }, .arraySize = 0 },
    };
    OH_HiSysEvent_Write(DISTRIBUTED_DATAMGR, EVENT_NAME, HISYSEVENT_FAULT, params, sizeof(params) / sizeof(params[0]));
}

std::string RdbFaultHiViewReporter::GetFileStatInfo(const DebugInfo &debugInfo)
{
    std::stringstream oss;
    const uint32_t permission = 0777;
    oss << " dev:0x" << std::hex << debugInfo.dev_ << " ino:0x" << std::hex << debugInfo.inode_;
    if (debugInfo.inode_ != debugInfo.oldInode_ && debugInfo.oldInode_ != 0) {
        oss << "<>0x" << std::hex << debugInfo.oldInode_;
    }
    oss << " mode:0" << std::oct << (debugInfo.mode_ & permission) << " size:" << std::dec << debugInfo.size_
        << " atim:" << GetTimeWithMilliseconds(debugInfo.atime_.sec_, debugInfo.atime_.nsec_)
        << " mtim:" << GetTimeWithMilliseconds(debugInfo.mtime_.sec_, debugInfo.mtime_.nsec_)
        << " ctim:" << GetTimeWithMilliseconds(debugInfo.ctime_.sec_, debugInfo.ctime_.nsec_);
    return oss.str();
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

std::string RdbFaultHiViewReporter::GetTimeWithMilliseconds(time_t sec, int64_t nsec)
{
    std::stringstream oss;
    char buffer[MAX_TIME_BUF_LEN] = { 0 };
    std::tm local_time;
    localtime_r(&sec, &local_time);
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_time);
    oss << buffer << '.' << std::setfill('0') << std::setw(MILLISECONDS_LEN) << (nsec / NANO_TO_MILLI) % MILLI_PRE_SEC;
    return oss.str();
}

RdbCorruptedEvent RdbFaultHiViewReporter::Create(
    const RdbStoreConfig &config, int32_t errCode, const std::string &appendix)
{
    RdbCorruptedEvent eventInfo;
    eventInfo.bundleName = config.GetBundleName();
    eventInfo.moduleName = config.GetModuleName();
    eventInfo.storeType = config.GetDBType() == DB_SQLITE ? "RDB" : "VECTOR DB";
    eventInfo.storeName = config.GetName();
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
    if (collector_ != nullptr) {
        Update(eventInfo, collector_(config));
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

void RdbFaultHiViewReporter::Update(RdbCorruptedEvent &eventInfo, const std::map<std::string, DebugInfo> &infos)
{
    auto &local = eventInfo.debugInfos;
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

std::string RdbFaultHiViewReporter::GetBundleName(const RdbCorruptedEvent &eventInfo)
{
    if (!eventInfo.bundleName.empty()) {
        return eventInfo.bundleName;
    }
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if ((tokenType == TOKEN_NATIVE) || (tokenType == TOKEN_SHELL)) {
        NativeTokenInfo tokenInfo;
        if (AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo) == 0) {
            return tokenInfo.processName;
        }
    }
    return SqliteUtils::Anonymous(eventInfo.storeName);
}

std::string RdbFaultHiViewReporter::Format(const std::map<std::string, DebugInfo> &debugs, const std::string &header)
{
    if (debugs.empty()) {
        return "";
    }
    std::string appendix = header;
    for (auto &[name, debugInfo] : debugs) {
        appendix += "\n" + name + " :" + GetFileStatInfo(debugInfo);
    }
    return appendix;
}

std::string RdbFaultHiViewReporter::FormatBrief(
    const std::map<std::string, DebugInfo> &debugs, const std::string &header)
{
    if (debugs.empty()) {
        return "";
    }
    std::stringstream oss;
    oss << header << ":";
    for (auto &[name, debugInfo] : debugs) {
        oss << "<" << name << ",0x" << std::hex << debugInfo.inode_ << "," << std::dec << debugInfo.size_ << ">";
    }
    return oss.str();
}
} // namespace OHOS::NativeRdb