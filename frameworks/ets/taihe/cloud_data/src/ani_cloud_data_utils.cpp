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
#define LOG_TAG "AniCloudDataUtils"
#include <map>
#include <string>
#include <optional>
#include <vector>
#include <cmath>
#include <atomic>
#include "ani_cloud_data_utils.h"
#include "logger.h"
#include "ani_error_code.h"

namespace AniCloudData {
using namespace OHOS::Rdb;
using Participant_INNER = OHOS::CloudData::Participant;
const uint32_t INDEX_TWO = 2;

static std::atomic<uint32_t> seqNum_ = 0;
uint32_t GetSeqNum()
{
    uint32_t value = ++seqNum_;
    if (value == 0) {
        value = ++seqNum_;
    }
    return value;
}

void RequestIPC(std::function<void(std::shared_ptr<CloudService>)> work)
{
    auto [state, proxy] = CloudManager::GetInstance().GetCloudService();
    if (proxy == nullptr) {
        if (state != CloudService::SERVER_UNAVAILABLE) {
            state = CloudService::NOT_SUPPORT;
        }
        LOG_ERROR("proxy is NULL");
        ThrowAniError(state);
        return;
    }
    work(proxy);
}

OHOS::CloudData::DBSwitchInfo ConvertTaiheDbSwitchInfo(::ohos::data::cloudData::DBSwitchInfo dbSwitchInfo)
{
    OHOS::CloudData::DBSwitchInfo dbInfo;
    std::map<std::string, bool> info;
    auto tableInfo = dbSwitchInfo.tableInfo;
    if (tableInfo.has_value()) {
        for (auto &item : tableInfo.value()) {
            info.emplace(std::string(item.first), item.second);
        }
        dbInfo.tableInfo = info;
    }
    dbInfo.enable = dbSwitchInfo.enable;
    return dbInfo;
}

OHOS::CloudData::ClearConfig ConvertTaiheClearConfig(::ohos::data::cloudData::ClearConfig clearConfig)
{
    OHOS::CloudData::ClearConfig config;
    std::map<std::string, OHOS::CloudData::DBActionInfo> dbInfo;
    for (auto &item : clearConfig.dbInfo) {
        auto actionInfo = ConvertTaiheDbActionInfo(item.second);
        dbInfo.emplace(std::string(item.first), std::move(actionInfo));
    }
    config.dbInfo = dbInfo;
    return config;
}

OHOS::CloudData::DBActionInfo ConvertTaiheDbActionInfo(::ohos::data::cloudData::DBActionInfo actionInfo)
{
    OHOS::CloudData::DBActionInfo dbActionInfo;
    std::map<std::string, int32_t> info;
    auto tableInfo = actionInfo.tableInfo;
    if (tableInfo.has_value()) {
        for (auto &item : tableInfo.value()) {
            info.emplace(std::string(item.first), item.second.get_value());
        }
        dbActionInfo.tableInfo = info;
    }
    dbActionInfo.action = actionInfo.action.get_value();
    return dbActionInfo;
}

void StatisticInfoConvert(std::map<std::string, StatisticInfos> &in, map<string, array<TaiHeStatisticInfo>> &out)
{
    for (auto &item : in) {
        std::vector<TaiHeStatisticInfo> arrayInfo;
        for (auto &vIt : item.second) {
            arrayInfo.push_back({vIt.table, vIt.inserted, vIt.updated, vIt.normal});
        }
        out.emplace(string(item.first), arrayInfo);
    }
}

void SyncInfoConvert(QueryLastResults &in, map<string, SyncInfo> &out)
{
    using SyncStatus_T = ::ohos::data::cloudData::SyncStatus;
    for (auto &it : in) {
        SyncInfo info = {0, 0, ProgressCode::key_t::UNKNOWN_ERROR};
        info.code = ProgressCode::from_value(it.second.code);
        info.startTime = it.second.startTime;
        info.finishTime = it.second.finishTime;
        info.syncStatus = optional<SyncStatus_T>(std::in_place, SyncStatus_T::from_value(it.second.syncStatus));
        out.emplace(it.first, info);
    }
}

ProgressDetails ProgressDetailConvert(const OHOS::DistributedRdb::ProgressDetail &in)
{
    map<string, ::ohos::data::relationalStore::TableDetails> tdMap;
    for (auto &it : in.details) {
        ::ohos::data::relationalStore::TableDetails td;
        td.upload.total = it.second.upload.total;
        td.upload.successful = it.second.upload.success;
        td.upload.failed = it.second.upload.failed;
        td.upload.remained = it.second.upload.untreated;
        td.download.total = it.second.download.total;
        td.download.successful = it.second.download.success;
        td.download.failed = it.second.download.failed;
        td.download.remained = it.second.download.untreated;
        tdMap.emplace(it.first, td);
    }
    return {Progress::from_value(in.progress), ProgressCode::from_value(in.code), tdMap};
}

void ParticipantConvert(const array_view<TaiHeParticipant> &in, Participants &out)
{
    Participant_INNER inner;
    for (auto it = in.begin(); it != in.end(); ++it) {
        inner.identity = std::string(it->identity);
        if (it->role.has_value()) {
            inner.role = it->role.value().get_value();
        }
        if (it->state.has_value()) {
            inner.state = it->state.value().get_value();
        }
        if (it->privilege.has_value()) {
            if (it->privilege.value().writable.has_value()) {
                inner.privilege.writable = it->privilege.value().writable.value();
            }
            if (it->privilege.value().readable.has_value()) {
                inner.privilege.readable = it->privilege.value().readable.value();
            }
            if (it->privilege.value().creatable.has_value()) {
                inner.privilege.creatable = it->privilege.value().creatable.value();
            }
            if (it->privilege.value().deletable.has_value()) {
                inner.privilege.deletable = it->privilege.value().deletable.value();
            }
            if (it->privilege.value().shareable.has_value()) {
                inner.privilege.shareable = it->privilege.value().shareable.value();
            }
        }
        if (it->attachInfo.has_value()) {
            inner.attachInfo = std::string(it->attachInfo.value());
        }
        out.push_back(inner);
    }
}

void ResultsConvert(const Results &in, TaiHeResult &out)
{
    out.code = std::get<0>(in);
    out.description = optional<string>(std::in_place, std::get<1>(in));
    std::vector<TaiHeResult> subResult;
    for (auto &it : std::get<INDEX_TWO>(in)) {
        subResult.push_back({it.first, optional<string>(std::in_place, it.second)});
    }
    out.value =  optional<ResultValue>(std::in_place, ResultValue::make_resultParticipantsValue(subResult));
}

void QueryResultsConvert(const QueryResults &in, TaiHeResult &out)
{
    using TaiHeRole = ::ohos::data::cloudData::sharing::Role;
    using TaiheState = ::ohos::data::cloudData::sharing::State;
    using TaiHePrivilege = ::ohos::data::cloudData::sharing::Privilege;
    out.code = std::get<0>(in);
    out.description = optional<string>(std::in_place, std::get<1>(in));
    std::vector<TaiHeParticipant> thVec;
    for (auto &it : std::get<INDEX_TWO>(in)) {
        TaiHeParticipant th = {""};
        th.identity = it.identity;
        if (it.role != OHOS::CloudData::Role::ROLE_NIL) {
            th.role = optional<TaiHeRole>(std::in_place, TaiHeRole::from_value(it.role));
        }
        if (it.state != OHOS::CloudData::Confirmation::CFM_NIL) {
            th.state = optional<TaiheState>(std::in_place, TaiheState::from_value(it.state));
        }
        th.attachInfo = optional<string>(std::in_place, it.attachInfo);
        TaiHePrivilege pri;
        pri.writable = optional<bool>(std::in_place, it.privilege.writable);
        pri.readable = optional<bool>(std::in_place, it.privilege.readable);
        pri.creatable = optional<bool>(std::in_place, it.privilege.creatable);
        pri.deletable = optional<bool>(std::in_place, it.privilege.deletable);
        pri.shareable = optional<bool>(std::in_place, it.privilege.shareable);
        th.privilege = optional<TaiHePrivilege>(std::in_place, pri);
        thVec.push_back(th);
    }
    out.value =  optional<ResultValue>(std::in_place, ResultValue::make_participantsValue(thVec));
}
}  // namespace
