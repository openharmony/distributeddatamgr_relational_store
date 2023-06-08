/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define LOG_TAG "RdbServiceProxy"

#include "rdb_service_proxy.h"
#include "itypes_util.h"
#include "log_print.h"
#include "sqlite_utils.h"

namespace OHOS::DistributedRdb {
using SqliteUtils = OHOS::NativeRdb::SqliteUtils;
#define IPC_SEND(code, reply, ...)                                          \
({                                                                          \
    int32_t __status = RDB_OK;                                              \
    do {                                                                    \
        MessageParcel request;                                              \
        if (!request.WriteInterfaceToken(GetDescriptor())) {                \
            __status = RDB_ERROR;                                           \
            break;                                                          \
        }                                                                   \
        if (!ITypesUtil::Marshal(request, ##__VA_ARGS__)) {                 \
            __status = RDB_ERROR;                                           \
            break;                                                          \
        }                                                                   \
        MessageOption option;                                               \
        auto result = remote_->SendRequest((code), request, reply, option); \
        if (result != 0) {                                                  \
            __status = RDB_ERROR;                                           \
            break;                                                          \
        }                                                                   \
                                                                            \
        ITypesUtil::Unmarshal(reply, __status);                             \
    } while (0);                                                            \
    __status;                                                               \
})

RdbServiceProxy::RdbServiceProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IRdbService>(object)
{
    remote_ = Remote();
}

void RdbServiceProxy::OnSyncComplete(uint32_t seqNum, Details &&result)
{
    syncCallbacks_.ComputeIfPresent(seqNum, [&result] (const auto& key, const AsyncDetail & callback) {
        auto finished = result.empty() || (result.begin()->second.progress == SYNC_FINISH);
        ZLOGD("Sync complete, seqNum%{public}d, result size:%{public}zu", key, result.size());
        callback(std::move(result));
        return !finished;
    });
}

void RdbServiceProxy::OnDataChange(const Origin &origin, const PrimaryFields &primaries, ChangeInfo &&changeInfo)
{
    auto name = RemoveSuffix(origin.store);
    observers_.ComputeIfPresent(name,
        [&origin, &primaries, info = std::move(changeInfo)](const auto &key, const ObserverMapValue &value) mutable {
            auto size = value.first.size();
            for (const auto &observer : value.first) {
                size--;
                observer->OnChange(origin, primaries, (size > 0) ? ChangeInfo(info) : std::move(info));
            }
            return true;
        });
}

std::string RdbServiceProxy::ObtainDistributedTableName(const std::string &device, const std::string &table)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_OBTAIN_TABLE, reply, device, table);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, device:%{public}.6s, table:%{public}s", status,
            SqliteUtils::Anonymous(device).c_str(), SqliteUtils::Anonymous(table).c_str());
        return "";
    }
    return reply.ReadString();
}

int32_t RdbServiceProxy::InitNotifier(const RdbSyncerParam &param)
{
    notifier_ = new (std::nothrow) RdbNotifierStub(
        [this] (uint32_t seqNum, Details &&result) {
            OnSyncComplete(seqNum, std::move(result));
        },
        [this](const Origin &origin, const PrimaryFields &primaries, ChangeInfo &&changeInfo) {
            OnDataChange(origin, primaries, std::move(changeInfo));
        });
    if (notifier_ == nullptr) {
        ZLOGE("create notifier failed");
        return RDB_ERROR;
    }

    if (InitNotifier(param, notifier_->AsObject()) != RDB_OK) {
        notifier_ = nullptr;
        return RDB_ERROR;
    }

    ZLOGI("success");
    return RDB_OK;
}

int32_t RdbServiceProxy::InitNotifier(const RdbSyncerParam &param, sptr<IRemoteObject> notifier)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_INIT_NOTIFIER, reply, param, notifier);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s", status, param.bundleName_.c_str());
    }
    return status;
}

uint32_t RdbServiceProxy::GetSeqNum()
{
    uint32_t value = ++seqNum_;
    if (value == 0) {
        value = ++seqNum_;
    }
    return value;
}

std::pair<int32_t, Details> RdbServiceProxy::DoSync(const RdbSyncerParam& param, const Option &option,
                                const PredicatesMemo &predicates)
{
    std::pair<int32_t, Details> result{RDB_ERROR, {}};
    MessageParcel reply;
    auto &[status, details] = result;
    status = IPC_SEND(RDB_SERVICE_CMD_SYNC, reply, param, option, predicates);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
        return result;
    }

    if (!ITypesUtil::Unmarshal(reply, details)) {
        ZLOGE("read result failed");
        status = RDB_ERROR;
        return result;
    }
    return result;
}

int32_t RdbServiceProxy::DoSync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates,
    const AsyncDetail &async)
{
    auto [status, details] = DoSync(param, option, predicates);
    if (status != RDB_OK) {
        ZLOGI("failed");
        return RDB_ERROR;
    }
    ZLOGI("success");

    if (async != nullptr) {
        async(std::move(details));
    }
    return RDB_OK;
}

int32_t RdbServiceProxy::DoAsync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_ASYNC, reply, param, option, predicates);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s, seqNum:%{public}u", status,
            param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str(), option.seqNum);
    }
    return status;
}

int32_t RdbServiceProxy::DoAsync(const RdbSyncerParam& param, const Option &option,
                                 const PredicatesMemo &predicates, const AsyncDetail & callback)
{
    Option asyncOption = option;
    if (callback != nullptr) {
        asyncOption.seqNum = GetSeqNum();
        if (!syncCallbacks_.Insert(asyncOption.seqNum, callback)) {
            ZLOGI("insert callback failed");
            return RDB_ERROR;
        }
    }
    ZLOGI("num=%{public}u", asyncOption.seqNum);
    if (DoAsync(param, asyncOption, predicates) != RDB_OK) {
        ZLOGE("failed");
        syncCallbacks_.Erase(asyncOption.seqNum);
        return RDB_ERROR;
    }

    ZLOGI("success");
    return RDB_OK;
}

int32_t RdbServiceProxy::SetDistributedTables(const RdbSyncerParam& param, const std::vector<std::string> &tables, int32_t type)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_SET_DIST_TABLE, reply, param, tables);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

int32_t RdbServiceProxy::Sync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates,
                              const AsyncDetail &async)
{
    if (option.isAsync) {
        return DoAsync(param, option, predicates, async);
    }
    return DoSync(param, option, predicates, async);
}

std::string RdbServiceProxy::RemoveSuffix(const std::string& name)
{
    std::string suffix(".db");
    auto pos = name.rfind(suffix);
    if (pos == std::string::npos || pos < name.length() - suffix.length()) {
        return name;
    }
    return { name, 0, pos };
}

int32_t RdbServiceProxy::Subscribe(const RdbSyncerParam &param, const SubscribeOption &option,
                                   RdbStoreObserver *observer)
{
    if (option.mode < SubscribeMode::REMOTE || option.mode >= SUBSCRIBE_MODE_MAX) {
        ZLOGE("subscribe mode invalid");
        return RDB_ERROR;
    }
    if (DoSubscribe(param, option) != RDB_OK) {
        ZLOGI("communicate to server failed");
        return RDB_ERROR;
    }
    auto name = RemoveSuffix(param.storeName_);
    observers_.Compute(
        name, [observer] (const auto& key, ObserverMapValue& value) {
            for (const auto& element : value.first) {
                if (element == observer) {
                    ZLOGE("duplicate observer");
                    return true;
                }
            }
            value.first.push_back(observer);
            return true;
        });
    return RDB_OK;
}

int32_t RdbServiceProxy::DoSubscribe(const RdbSyncerParam &param, const SubscribeOption &option)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_SUBSCRIBE, reply, param, option);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

int32_t RdbServiceProxy::UnSubscribe(const RdbSyncerParam &param, const SubscribeOption &option,
                                     RdbStoreObserver *observer)
{
    DoUnSubscribe(param);
    auto name = RemoveSuffix(param.storeName_);
    observers_.ComputeIfPresent(
        name, [observer](const auto& key, ObserverMapValue& value) {
            ZLOGI("before remove size=%{public}d", static_cast<int>(value.first.size()));
            value.first.remove(observer);
            ZLOGI("after  remove size=%{public}d", static_cast<int>(value.first.size()));
            return !(value.first.empty());
    });
    return RDB_OK;
}

int32_t RdbServiceProxy::DoUnSubscribe(const RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_UNSUBSCRIBE, reply, param);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

int32_t RdbServiceProxy::RemoteQuery(const RdbSyncerParam& param, const std::string& device, const std::string& sql,
                                     const std::vector<std::string>& selectionArgs, sptr<IRemoteObject>& resultSet)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_REMOTE_QUERY, reply, param, device, sql, selectionArgs);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s, device:%{public}.6s",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str(), device.c_str());
        return status;
    }

    sptr<IRemoteObject> remote = reply.ReadRemoteObject();
    if (remote == nullptr) {
        ZLOGE("read remote object is null");
        return RDB_ERROR;
    }
    resultSet = remote;
    return RDB_OK;
}

RdbServiceProxy::ObserverMap RdbServiceProxy::ExportObservers()
{
    return observers_;
}

void RdbServiceProxy::ImportObservers(ObserverMap &observers)
{
    ZLOGI("enter");
    SubscribeOption option {SubscribeMode::REMOTE};
    observers.ForEach([this, &option](const std::string& key, const ObserverMapValue& value) {
        for (auto& observer : value.first) {
            Subscribe(value.second, option, observer);
        }
        return false;
    });
}

int32_t RdbServiceProxy::GetSchema(const RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_GET_SCHEMA, reply, param);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s", status, param.bundleName_.c_str(),
            param.storeName_.c_str());
    }
    return status;
}
} // namespace OHOS::DistributedRdb
