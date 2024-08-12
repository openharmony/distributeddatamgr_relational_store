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

#include <sys/stat.h>

#include <ctime>
#include <string>

#include "rdb_store_config.h"


namespace OHOS::NativeRdb {

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
    int dbFileStatRet;
    struct stat dbFileStat;
    int walFileStatRet;
    struct stat walFileStat;
};

class RdbFaultHiViewReporter {
public:
    static void ReportRdbCorruptedFault(RdbCorruptedEvent &eventInfo);

private:
    static std::string GetFileStatInfo(const struct stat &fileStat);
    static std::string GetDateInfo(time_t time);
};
} // namespace OHOS::NativeRdb
#endif //DISTRIBUTEDDATAMGR_RDB_FAULT_HIVIEW_REPORTER_H
