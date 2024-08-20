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

#include "hisysevent_c.h"
#include "logger.h"
#include "rdb_errno.h"

namespace OHOS::NativeRdb {

using namespace OHOS::Rdb;

static constexpr const char *EVENT_NAME = "DATABASE_CORRUPTED";
static constexpr const char *DISTRIBUTED_DATAMGR = "DISTDATAMGR";

void RdbFaultHiViewReporter::ReportRdbCorruptedFault(RdbCorruptedEvent &eventInfo)
{
    char *bundleName = eventInfo.bundleName.data();
    char *moduleName = eventInfo.moduleName.data();
    char *storeType = eventInfo.storeType.data();
    char *storeName = eventInfo.storeName.data();
    uint32_t checkType = eventInfo.integrityCheck;
    std::string appendInfo = eventInfo.appendix;
    if (eventInfo.dbFileStatRet >= 0) {
        appendInfo = appendInfo + " \n DB : \n" + GetFileStatInfo(eventInfo.dbFileStat);
    }
    if (eventInfo.walFileStatRet >= 0) {
        appendInfo = appendInfo + " \n WAL : \n" + GetFileStatInfo(eventInfo.walFileStat);
    }
    LOG_WARN("storeName: %{public}s, errorCode: %{public}d, appendInfo : %{public}s.", storeName, eventInfo.errorCode,
        appendInfo.c_str());
    char *errorOccurTime = GetDateInfo(eventInfo.errorOccurTime).data();
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
    const uint32_t permission = 0777;
    std::stringstream oss;
    oss << " device: " << fileStat.st_dev << " inode: " << fileStat.st_ino
        << " mode: " << (fileStat.st_mode & permission) << " size: " << fileStat.st_size
        << " natime: " << ctime(&fileStat.st_atime) << " smtime: " << ctime(&fileStat.st_mtime)
        << " sctime: " << ctime(&fileStat.st_ctime);
    return oss.str();
}

std::string RdbFaultHiViewReporter::GetDateInfo(time_t time)
{
    std::tm tm = *std::localtime(&time);
    std::stringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}
} // namespace OHOS::NativeRdb