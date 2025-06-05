/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "CloudServiceProxy"
#include "cloud_service_proxy.h"

#include "itypes_util.h"
#include "logger.h"

namespace OHOS::CloudData {
using namespace OHOS::Rdb;

#define IPC_SEND(code, reply, ...)                                              \
    ({                                                                          \
        int32_t __status = SUCCESS;                                             \
        do {                                                                    \
            MessageParcel request;                                              \
            if (!request.WriteInterfaceToken(GetDescriptor())) {                \
                __status = IPC_PARCEL_ERROR;                                    \
                break;                                                          \
            }                                                                   \
            if (!ITypesUtil::Marshal(request, ##__VA_ARGS__)) {                 \
                __status = IPC_PARCEL_ERROR;                                    \
                break;                                                          \
            }                                                                   \
            MessageOption option;                                               \
            auto result = remote_->SendRequest((code), request, reply, option); \
            if (result != 0) {                                                  \
                __status = IPC_ERROR;                                           \
                break;                                                          \
            }                                                                   \
                                                                                \
            ITypesUtil::Unmarshal(reply, __status);                             \
        } while (0);                                                            \
        __status;                                                               \
    })

CloudServiceProxy::CloudServiceProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<ICloudService>(object)
{
    remote_ = Remote();
}

int32_t CloudServiceProxy::EnableCloud(const std::string &id, const std::map<std::string, int32_t> &switches)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_ENABLE_CLOUD, reply, id, switches);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x id:%{public}.6s size:%{public}zu", status, id.c_str(), switches.size());
    }
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::DisableCloud(const std::string &id)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_DISABLE_CLOUD, reply, id);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x id:%{public}.6s", status, id.c_str());
    }
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::ChangeAppSwitch(const std::string &id, const std::string &bundleName, int32_t appSwitch)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_CHANGE_APP_SWITCH, reply, id, bundleName, appSwitch);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x id:%{public}.6s bundleName:%{public}s switch:%{public}d", status, id.c_str(),
            bundleName.c_str(), appSwitch);
    }
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::Clean(const std::string &id, const std::map<std::string, int32_t> &actions)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_CLEAN, reply, id, actions);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x id:%{public}.6s size:%{public}zu", status, id.c_str(), actions.size());
    }
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::NotifyDataChange(const std::string &id, const std::string &bundleName)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_NOTIFY_DATA_CHANGE, reply, id, bundleName);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x id:%{public}.6s bundleName:%{public}s", status, id.c_str(), bundleName.c_str());
    }
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::SetGlobalCloudStrategy(Strategy strategy, const std::vector<CommonType::Value> &values)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_SET_GLOBAL_CLOUD_STRATEGY, reply, strategy, values);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x strategy:%{public}d values size:%{public}zu", status,
            static_cast<uint32_t>(strategy), values.size());
    }
    return static_cast<Status>(status);
}

std::pair<int32_t, std::vector<NativeRdb::ValuesBucket>> CloudServiceProxy::AllocResourceAndShare(
    const std::string &storeId, const DistributedRdb::PredicatesMemo &predicates,
    const std::vector<std::string> &columns, const std::vector<Participant> &participants)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_ALLOC_RESOURCE_AND_SHARE, reply, storeId, predicates, columns, participants);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x storeName:%{public}.6s", status, storeId.c_str());
    }
    std::vector<NativeRdb::ValuesBucket> valueBuckets;
    ITypesUtil::Unmarshal(reply, valueBuckets);
    return { static_cast<Status>(status), valueBuckets };
}

int32_t CloudServiceProxy::NotifyDataChange(const std::string &eventId, const std::string &extraData, int32_t userId)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_NOTIFY_DATA_CHANGE_EXT, reply, eventId, extraData, userId);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x eventId:%{public}.6s extraData:%{public}.6s", status, eventId.c_str(),
            extraData.c_str());
    }
    return static_cast<Status>(status);
}

std::pair<int32_t, std::map<std::string, StatisticInfos>> CloudServiceProxy::QueryStatistics(
    const std::string &id, const std::string &bundleName, const std::string &storeId)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_QUERY_STATISTICS, reply, id, bundleName, storeId);
    if (status != SUCCESS) {
        LOG_ERROR(
            "Status:0x%{public}x bundleName:%{public}.6s storeId:%{public}.6s", status, id.c_str(), storeId.c_str());
    }
    std::map<std::string, StatisticInfos> infos;
    ITypesUtil::Unmarshal(reply, infos);
    return { status, infos };
}

int32_t CloudServiceProxy::Share(const std::string &sharingRes, const Participants &participants, Results &results)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_SHARE, reply, sharingRes, participants);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x sharingRes:%{public}.6s participants:%{public}zu", status, sharingRes.c_str(),
            participants.size());
    }
    ITypesUtil::Unmarshal(reply, results);
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::Unshare(const std::string &sharingRes, const Participants &participants, Results &results)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_UNSHARE, reply, sharingRes, participants);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x sharingRes:%{public}.6s participants:%{public}zu", status, sharingRes.c_str(),
            participants.size());
    }
    ITypesUtil::Unmarshal(reply, results);
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::Exit(const std::string &sharingRes, std::pair<int32_t, std::string> &result)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_EXIT, reply, sharingRes);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x sharingRes:%{public}.6s", status, sharingRes.c_str());
    }
    ITypesUtil::Unmarshal(reply, result);
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::ChangePrivilege(
    const std::string &sharingRes, const Participants &participants, Results &results)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_CHANGE_PRIVILEGE, reply, sharingRes, participants);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x sharingRes:%{public}.6s participants:%{public}zu", status, sharingRes.c_str(),
            participants.size());
    }
    ITypesUtil::Unmarshal(reply, results);
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::Query(const std::string &sharingRes, QueryResults &results)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_QUERY, reply, sharingRes);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x sharingRes:%{public}.6s", status, sharingRes.c_str());
    }
    ITypesUtil::Unmarshal(reply, results);
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::QueryByInvitation(const std::string &invitation, QueryResults &results)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_QUERY_BY_INVITATION, reply, invitation);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x invitation:%{public}.6s", status, invitation.c_str());
    }
    ITypesUtil::Unmarshal(reply, results);
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::ConfirmInvitation(
    const std::string &invitation, int32_t confirmation, std::tuple<int32_t, std::string, std::string> &result)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_CONFIRM_INVITATION, reply, invitation, confirmation);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x invitation:%{public}.6s", status, invitation.c_str());
    }
    ITypesUtil::Unmarshal(reply, result);
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::ChangeConfirmation(
    const std::string &sharingRes, int32_t confirmation, std::pair<int32_t, std::string> &result)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_CHANGE_CONFIRMATION, reply, sharingRes, confirmation);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x sharingRes:%{public}.6s", status, sharingRes.c_str());
    }
    ITypesUtil::Unmarshal(reply, result);
    return static_cast<Status>(status);
}

int32_t CloudServiceProxy::SetCloudStrategy(Strategy strategy, const std::vector<CommonType::Value> &values)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_SET_CLOUD_STRATEGY, reply, strategy, values);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x strategy:%{public}d values size:%{public}zu", status,
            static_cast<uint32_t>(strategy), values.size());
    }
    return static_cast<Status>(status);
}

std::pair<int32_t, QueryLastResults> CloudServiceProxy::QueryLastSyncInfo(
    const std::string &id, const std::string &bundleName, const std::string &storeId)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_QUERY_LAST_SYNC_INFO, reply, id, bundleName, storeId);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x id:%{public}.6s bundleName:%{public}s storeId:%{public}.3s", status, id.c_str(),
            bundleName.c_str(), storeId.c_str());
    }
    QueryLastResults results;
    ITypesUtil::Unmarshal(reply, results);
    return { status, results };
}

int32_t CloudServiceProxy::DoAsync(const std::string &bundleName, const std::string &storeId, Option option)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_CLOUD_SYNC, reply, bundleName, storeId, option);
    if (status != SUCCESS) {
        LOG_ERROR(
            "Status:0x%{public}x bundleName:%{public}s storeId:%{public}.3s syncMode:%{public}d seqNum:%{public}u",
            status, bundleName.c_str(), storeId.c_str(), option.syncMode, option.seqNum);
    }
    return status;
}

int32_t CloudServiceProxy::InitNotifier(const std::string &bundleName, sptr<IRemoteObject> notifier)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(TRANS_INIT_NOTIFIER, reply, bundleName, notifier);
    if (status != SUCCESS) {
        LOG_ERROR("Status:0x%{public}x bundleName:%{public}s", status, bundleName.c_str());
    }
    return status;
}

int32_t CloudServiceProxy::InitNotifier(const std::string &bundleName)
{
    if (notifiers_.find(bundleName) != notifiers_.end()) {
        return SUCCESS;
    }
    sptr<RdbNotifierStub> notifier = new (std::nothrow) RdbNotifierStub(
        [this](uint32_t seqNum, Details &&result) {
            OnSyncComplete(seqNum, std::move(result));
        }, nullptr, nullptr);
    if (notifier == nullptr) {
        LOG_ERROR("create notifier failed, bundleName = %{public}s", bundleName.c_str());
        return ERROR;
    }
    auto status = InitNotifier(bundleName, notifier->AsObject());
    if (status != SUCCESS) {
        LOG_ERROR("init notifier failed, bundleName = %{public}s", bundleName.c_str());
        return status;
    }
    notifiers_.emplace(bundleName, notifier);
    return SUCCESS;
}

void CloudServiceProxy::OnSyncComplete(uint32_t seqNum, Details &&result)
{
    syncCallbacks_.ComputeIfPresent(seqNum, [&result](const auto &key, const AsyncDetail &callback) {
        auto finished = result.empty() || (result.begin()->second.progress == SYNC_FINISH);
        if (callback != nullptr) {
            callback(std::move(result));
        }
        return !finished;
    });
}

int32_t CloudServiceProxy::CloudSync(const std::string &bundleName, const std::string &storeId,
    const Option &option, const AsyncDetail &async)
{
    LOG_INFO("cloud sync start, bundleName = %{public}s, seqNum = %{public}u", bundleName.c_str(), option.seqNum);
    if (bundleName.empty() || storeId.empty() || option.syncMode  < DistributedRdb::TIME_FIRST ||
        option.syncMode  > DistributedRdb::CLOUD_FIRST || async == nullptr) {
        LOG_ERROR("invalid args, bundleName = %{public}s", bundleName.c_str());
        return INVALID_ARGUMENT;
    }
    auto status = InitNotifier(bundleName);
    if (status != SUCCESS) {
        LOG_ERROR("init notifier failed, bundleName = %{public}s", bundleName.c_str());
        return status;
    }
    if (!syncCallbacks_.Insert(option.seqNum, async)) {
        LOG_ERROR("register progress failed, bundleName = %{public}s", bundleName.c_str());
        return ERROR;
    }
    status = DoAsync(bundleName, storeId, option);
    if (status != SUCCESS) {
        syncCallbacks_.Erase(option.seqNum);
    }
    return status;
}
} // namespace OHOS::CloudData
