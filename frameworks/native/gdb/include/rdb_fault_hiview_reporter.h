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

#ifndef DISTRIBUTEDDATAMGR_GDB_FAULT_HIVIEW_REPORTER_H
#define DISTRIBUTEDDATAMGR_GDB_FAULT_HIVIEW_REPORTER_H

#include <string>
#include "rdb_store_config.h"

namespace OHOS::NativeRdb {
// Fault Type Define
static constexpr const char *FT_OPEN = "OPEN_DB";
static constexpr const char *FT_CURD = "CURD_DB";
static constexpr const char *FT_EX_FILE = "EX_FILE";
static constexpr const char *FT_EX_HUKS = "EX_HUKS";
static constexpr const char *FT_CP = "CHECK_POINT";

class RdbFaultEvent {
public:
    RdbFaultEvent(const std::string &faultType, int32_t errorCode, const std::string &bundleName,
        const std::string &custLog) {};
    virtual ~RdbFaultEvent() = default;
};

class RdbFaultDbFileEvent : public RdbFaultEvent {
public:
    RdbFaultDbFileEvent(const std::string &faultType, int32_t errorCode, const RdbStoreConfig &config,
        const std::string &custLog = "", bool printDbInfo = false)
        : RdbFaultEvent(faultType, errorCode, "", custLog), config_(config) {}
private:
    RdbStoreConfig config_;
};

class RdbFaultHiViewReporter {
public:
    static void ReportFault(const RdbFaultEvent &faultEvent) {};
};
} // namespace OHOS::NativeRdb
#endif // DISTRIBUTEDDATAMGR_GDB_FAULT_HIVIEW_REPORTER_H