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

namespace OHOS::DistributedRdb {
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

void RdbServiceProxy::OnSyncComplete(uint32_t seqNum, const SyncResult &result)
{
    syncCallbacks_.ComputeIfPresent(seqNum, [&result] (const auto& key, const SyncCallback& callback) {
        callback(result);
        return true;
    });
    syncCallbacks_.Erase(seqNum);
}

void RdbServiceProxy::OnDataChange(const std::string& storeName, const std::vector<std::string> &devices)
{
    auto name = RemoveSuffix(storeName);
    observers_.ComputeIfPresent(
        name, [&devices] (const auto& key, const ObserverMapValue& value) {
            for (const auto& observer : value.first) {
                observer->OnChange(devices);
            }
            return true;
        });
}

std::string RdbServiceProxy::ObtainDistributedTableName(const std::string &device, const std::string &table)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_OBTAIN_TABLE, reply, device, table);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, device:%{public}.6s, table:%{public}s", status, device.c_str(), table.c_str());
        return "";
    }
    return reply.ReadString();
}

int32_t RdbServiceProxy::InitNotifier(const RdbSyncerParam &param)
{
    notifier_ = new (std::nothrow) RdbNotifierStub(
        [this] (uint32_t seqNum, const SyncResult& result) {
            OnSyncComplete(seqNum, result);
        },
        [this] (const std::string& storeName, const std::vector<std::string>& devices) {
            OnDataChange(storeName, devices);
        }
    );
    if (notifier_ == nullptr) {
        ZLOGE("create notifier failed");
        return RDB_ERROR;
    }

    if (InitNotifier(param, notifier_->AsObject().GetRefPtr()) != RDB_OK) {
        notifier_ = nullptr;
        return RDB_ERROR;
    }

    ZLOGI("success");
    return RDB_OK;
}

int32_t RdbServiceProxy::InitNotifier(const RdbSyncerParam &param, const sptr<IRemoteObject> notifier)
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
    return seqNum_++;
}

int32_t RdbServiceProxy::DoSync(const RdbSyncerParam& param, const SyncOption &option,
                                const RdbPredicates &predicates, SyncResult& result)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_SYNC, reply, param, option, predicates);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), param.storeName_.c_str());
        return status;
    }

    if (!ITypesUtil::Unmarshal(reply, result)) {
        ZLOGE("read result failed");
        return RDB_ERROR;
    }
    return RDB_OK;
}

int32_t RdbServiceProxy::DoSync(const RdbSyncerParam& param, const SyncOption &option,
                                const RdbPredicates &predicates, const SyncCallback& callback)
{
    SyncResult result;
    if (DoSync(param, option, predicates, result) != RDB_OK) {
        ZLOGI("failed");
        return RDB_ERROR;
    }
    ZLOGI("success");

    if (callback != nullptr) {
        callback(result);
    }
    return RDB_OK;
}

int32_t RdbServiceProxy::DoAsync(const RdbSyncerParam& param, uint32_t seqNum, const SyncOption &option,
                                 const RdbPredicates &predicates)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_ASYNC, reply, param, seqNum, option, predicates);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s, seqNum:%{public}u",
            status, param.bundleName_.c_str(), param.storeName_.c_str(), seqNum);
    }
    return status;
}

int32_t RdbServiceProxy::DoAsync(const RdbSyncerParam& param, const SyncOption &option,
                                 const RdbPredicates &predicates, const SyncCallback& callback)
{
    uint32_t num = GetSeqNum();
    if (!syncCallbacks_.Insert(num, callback)) {
        ZLOGI("insert callback failed");
        return RDB_ERROR;
    }
    ZLOGI("num=%{public}u", num);

    if (DoAsync(param, num, option, predicates) != RDB_OK) {
        ZLOGE("failed");
        syncCallbacks_.Erase(num);
        return RDB_ERROR;
    }

    ZLOGI("success");
    return RDB_OK;
}

int32_t RdbServiceProxy::SetDistributedTables(const RdbSyncerParam& param, const std::vector<std::string> &tables)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_SET_DIST_TABLE, reply, param, tables);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), param.storeName_.c_str());
    }
    return status;
}

int32_t RdbServiceProxy::Sync(const RdbSyncerParam& param, const SyncOption &option,
                              const RdbPredicates &predicates, const SyncCallback &callback)
{
    if (option.isBlock) {
        return DoSync(param, option, predicates, callback);
    }
    return DoAsync(param, option, predicates, callback);
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
    if (option.mode != SubscribeMode::REMOTE) {
        ZLOGE("subscribe mode invalid");
        return RDB_ERROR;
    }
    if (DoSubscribe(param) != RDB_OK) {
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

int32_t RdbServiceProxy::DoSubscribe(const RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CMD_SUBSCRIBE, reply, param);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), param.storeName_.c_str());
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
            status, param.bundleName_.c_str(), param.storeName_.c_str());
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
            status, param.bundleName_.c_str(), param.storeName_.c_str(), device.c_str());
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
int32_t RdbServiceProxy::CreateRDBTable(
    const RdbSyncerParam &param, const std::string &writePermission, const std::string &readPermission)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_CREATE_RDB_TABLE, reply, param, writePermission, readPermission);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s,"
            "writePermission:%{public}.6s, readPermission:%{public}.6s",
            status, param.bundleName_.c_str(), param.storeName_.c_str(),
            writePermission.c_str(), readPermission.c_str());
    }
    return status;
}

int32_t RdbServiceProxy::DestroyRDBTable(const RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(RDB_SERVICE_DESTROY_RDB_TABLE, reply, param);
    if (status != RDB_OK) {
        ZLOGE("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), param.storeName_.c_str());
    }
    return status;
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
