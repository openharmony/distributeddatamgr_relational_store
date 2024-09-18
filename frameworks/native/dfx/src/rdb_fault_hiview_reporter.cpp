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

#include <iomanip>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <chrono>
#include <ctime>

#include "hisysevent_c.h"
#include "logger.h"
#include "rdb_errno.h"
#include "sqlite_utils.h"

namespace OHOS::NativeRdb {

using namespace OHOS::Rdb;

static constexpr const char *EVENT_NAME = "DATABASE_CORRUPTED";
static constexpr const char *DISTRIBUTED_DATAMGR = "DISTDATAMGR";
static constexpr const char *DB_CORRUPTED_POSTFIX = ".corruptedflg";
static constexpr int MAX_TIME_BUF_LEN = 32;
static constexpr int MILLISECONDS_LEN = 3;
static constexpr int SECOND_TO_MILL_UNIT = 1000;

void RdbFaultHiViewReporter::ReportRdbCorruptedFault(RdbCorruptedEvent &eventInfo, const std::string &dbPath)
{
    if (IsReportCorruptedFault(dbPath)) {
        InnerReportRdbCorrupted(eventInfo);
        CreateCorruptedFlag(dbPath);
    }
}

void RdbFaultHiViewReporter::ReportRdbCorruptedRestore(RdbCorruptedEvent &eventInfo, const std::string &dbPath)
{
    InnerReportRdbCorrupted(eventInfo);
    DeleteCorruptedFlag(dbPath);
}

void RdbFaultHiViewReporter::InnerReportRdbCorrupted(RdbCorruptedEvent &eventInfo)
{
    char *bundleName = eventInfo.bundleName.data();
    char *moduleName = eventInfo.moduleName.data();
    char *storeType = eventInfo.storeType.data();
    char *storeName = eventInfo.storeName.data();
    uint32_t checkType = eventInfo.integrityCheck;
    std::string appendInfo = eventInfo.appendix;
    if (eventInfo.dbFileStatRet >= 0) {
        appendInfo = appendInfo + "\n DB:" + GetFileStatInfo(eventInfo.dbFileStat);
    }
    if (eventInfo.walFileStatRet >= 0) {
        appendInfo = appendInfo + " \n WAL:" + GetFileStatInfo(eventInfo.walFileStat);
    }
    LOG_WARN("storeName: %{public}s, errorCode: %{public}d, appendInfo : %{public}s",
        SqliteUtils::Anonymous(eventInfo.storeName).c_str(), eventInfo.errorCode, appendInfo.c_str());
    std::string occurTime = GetTimeWithMilliseconds(eventInfo.errorOccurTime);
    char *errorOccurTime = occurTime.data();
    HiSysEventParam params[] = {
        { .name = "BUNDLE_NAME", .t = HISYSEVENT_STRING, .v = { .s = bundleName }, .arraySize = 0 },
        { .name = "MODULE_NAME", .t = HISYSEVENT_STRING, .v = { .s = moduleName }, .arraySize = 0 },
        { .name = "STORE_TYPE", .t = HISYSEVENT_STRING, .v = { .s = storeType }, .arraySize = 0 },
        { .name = "STORE_NAME", .t = HISYSEVENT_STRING, .v = { .s = storeName }, .arraySize = 0 },
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

std::string RdbFaultHiViewReporter::GetFileStatInfo(const struct stat &fileStat)
{
    std::stringstream oss;
    const uint32_t permission = 0777;

    oss << " device: " << fileStat.st_dev << " inode: " << fileStat.st_ino
        << " mode: " << fileStat.st_mode & permission << " size: " << fileStat.st_size
        << " natime: " << GetTimeWithMilliseconds(fileStat.st_atime)
        << " smtime: " << GetTimeWithMilliseconds(fileStat.st_mtime)
        << " sctime: " << GetTimeWithMilliseconds(fileStat.st_ctime);
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
        LOG_WARN("creat corrupted flg fail, flgname=%{public}s, errno=%{public}d",
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
        LOG_WARN("remove corrupted flg fail, flgname=%{public}s, errno=%{public}d",
            SqliteUtils::Anonymous(flagFilename).c_str(), errno);
    }
}

std::string RdbFaultHiViewReporter::GetTimeWithMilliseconds(const time_t &time)
{
    std::stringstream oss;
    char buffer[MAX_TIME_BUF_LEN] = {0};
    std::tm local_time;
    localtime_r(&time, &local_time);
    std::chrono::milliseconds ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_time);

    oss << buffer << '.' << std::setfill('0') << std::setw(MILLISECONDS_LEN) << ms.count() % SECOND_TO_MILL_UNIT;
    return oss.str();
}
} // namespace OHOS::NativeRdb