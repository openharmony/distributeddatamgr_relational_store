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

void RdbFaultHiViewReporter::ReportCorruptedOnce(const RdbCorruptedEvent &eventInfo)
{
    (void)eventInfo;
}

void RdbFaultHiViewReporter::ReportRestore(const RdbCorruptedEvent &eventInfo, bool repair)
{
    (void)eventInfo;
}

void RdbFaultHiViewReporter::ReportCorrupted(const RdbCorruptedEvent &eventInfo)
{
    (void)eventInfo;
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

RdbCorruptedEvent RdbFaultHiViewReporter::Create(
    const RdbStoreConfig &config, int32_t errCode, const std::string &appendix, bool needSyncParaFromSrv)
{
    (void)config;
    (void)errCode;
    (void)appendix;
    (void)needSyncParaFromSrv;
    RdbCorruptedEvent eventInfo;
    return eventInfo;
}

bool RdbFaultHiViewReporter::RegCollector(Collector collector)
{
    (void)collector;
    return true;
}
void RdbFaultHiViewReporter::Update(std::map<std::string, DebugInfo> &localInfos,
    const std::map<std::string, DebugInfo> &infos)
{
    (void)localInfos;
    (void)infos;
}

std::string RdbFaultHiViewReporter::GetBundleName(const std::string &bundleName, const std::string &storeName)
{
    (void)bundleName;
    (void)storeName;
    return "";
}

void RdbFaultHiViewReporter::ReportFault(const RdbFaultEvent &faultEvent)
{
    (void)faultEvent;
}

RdbFaultEvent::RdbFaultEvent(const std::string &faultType, int32_t errorCode,
    const std::string &bundleName, const std::string &custLog)
{
    (void)faultType;
    (void)errorCode;
    (void)bundleName;
    (void)custLog;
}

void RdbFaultEvent::Report() const
{
}

RdbFaultDbFileEvent::RdbFaultDbFileEvent(const std::string &faultType, int32_t errorCode, const RdbStoreConfig &config,
    const std::string &custLog, bool printDbInfo) : RdbFaultEvent(faultType, errorCode, "", custLog), config_(config)
{
    (void)printDbInfo;
}

void RdbFaultDbFileEvent::Report() const
{
}
} // namespace OHOS::NativeRdb