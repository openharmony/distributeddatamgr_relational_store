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
#include "rdb_fault_hiview_reporter.h"

namespace OHOS::NativeRdb {

void RdbFaultHiViewReporter::ReportRdbCorruptedFault(RdbCorruptedEvent &eventInfo, const std::string &dbPath)
{
    (void)eventInfo;
    (void)dbPath;
}

void RdbFaultHiViewReporter::ReportRdbCorruptedRestore(RdbCorruptedEvent &eventInfo, const std::string &dbPath)
{
    (void)eventInfo;
    (void)dbPath;
}

void RdbFaultHiViewReporter::InnerReportRdbCorrupted(RdbCorruptedEvent &eventInfo)
{
    (void)eventInfo;
}

std::string RdbFaultHiViewReporter::GetFileStatInfo(const struct stat &fileStat)
{
    (void)fileStat;
    return "";
}

bool RdbFaultHiViewReporter::IsReportCorruptedFault(const std::string &dbPath)
{
    return false;
}

void RdbFaultHiViewReporter::CreateCorruptedFlag(const std::string &dbPath)
{
    (void)dbPath;
}

void RdbFaultHiViewReporter::DeleteCorruptedFlag(const std::string &dbPath)
{
    (void)dbPath;
}

std::string RdbFaultHiViewReporter::GetTimeWithMilliseconds(const time_t &time)
{
    (void)time;
    return "";
}
} // namespace OHOS::NativeRdb