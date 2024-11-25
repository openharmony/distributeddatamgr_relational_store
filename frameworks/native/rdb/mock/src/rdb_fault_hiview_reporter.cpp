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

#include "connection.h"
namespace OHOS::NativeRdb {

void RdbFaultHiViewReporter::ReportFault(const RdbCorruptedEvent &eventInfo)
{
    (void)eventInfo;
}

void RdbFaultHiViewReporter::ReportRestore(const RdbCorruptedEvent &eventInfo, bool repair)
{
    (void)eventInfo;
}

void RdbFaultHiViewReporter::Report(const RdbCorruptedEvent &eventInfo)
{
    (void)eventInfo;
}

std::string RdbFaultHiViewReporter::GetFileStatInfo(const DebugInfo &debugInfo)
{
    (void)debugInfo;
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

std::string RdbFaultHiViewReporter::GetTimeWithMilliseconds(time_t sec, int64_t nsec)
{
    (void)sec;
    (void)nsec;
    return "";
}
RdbCorruptedEvent RdbFaultHiViewReporter::Create(
    const RdbStoreConfig &config, int32_t errCode, const std::string &appendix)
{
    RdbCorruptedEvent eventInfo;
    return eventInfo;
}

bool RdbFaultHiViewReporter::RegCollector(Connection::Collector collector)
{
    (void)collector;
    return true;
}
void RdbFaultHiViewReporter::Update(RdbCorruptedEvent &eventInfo, const std::map<std::string, DebugInfo> &infos)
{
    (void)eventInfo;
    (void)infos;
}

std::string RdbFaultHiViewReporter::GetBundleName(const RdbCorruptedEvent &eventInfo)
{
    (void)eventInfo;
    return "";
}

std::string RdbFaultHiViewReporter::Format(const std::map<std::string, DebugInfo> &debugs, const std::string &header)
{
    (void)debugs;
    (void)header;
    return "";
}

std::string RdbFaultHiViewReporter::FormatBrief(
    const std::map<std::string, DebugInfo> &debugs, const std::string &header)
{
    (void)debugs;
    (void)header;
    return "";
}
} // namespace OHOS::NativeRdb