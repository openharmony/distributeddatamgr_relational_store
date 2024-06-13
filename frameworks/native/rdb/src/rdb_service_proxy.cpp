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
#include "logger.h"
#include "sqlite_utils.h"
#include "result_set_proxy.h"

namespace OHOS::DistributedRdb {
using namespace OHOS::Rdb;
using SqliteUtils = OHOS::NativeRdb::SqliteUtils;
using RdbServiceCode = OHOS::DistributedRdb::RelationalStore::RdbServiceInterfaceCode;

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

std::string RdbServiceProxy::ObtainDistributedTableName(const std::string &device, const std::string &table)
{
    return "";
}

int32_t RdbServiceProxy::InitNotifier(const RdbSyncerParam &param)
{
    notifier_ = new (std::nothrow) RdbNotifierStub(
        [this] (uint32_t seqNum, Details &&result) {
            OnSyncComplete(seqNum, std::move(result));
        },
        [this] (std::string storeName, Details &&result) {
            OnSyncComplete(storeName, std::move(result));
        },
        [this](const Origin &origin, const PrimaryFields &primaries, ChangeInfo &&changeInfo) {
            OnDataChange(origin, primaries, std::move(changeInfo));
        });
    if (notifier_ == nullptr) {
        LOG_ERROR("create notifier failed");
        return RDB_ERROR;
    }

    if (InitNotifier(param, notifier_->AsObject()) != RDB_OK) {
        notifier_ = nullptr;
        LOG_ERROR("init notifier error");
        return RDB_ERROR;
    }

    return RDB_OK;
}

int32_t RdbServiceProxy::InitNotifier(const RdbSyncerParam &param, sptr<IRemoteObject> notifier)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(
        static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_INIT_NOTIFIER), reply, param, notifier);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s", status, param.bundleName_.c_str());
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
    status = IPC_SEND(static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_SYNC), reply, param, option, predicates);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
        return result;
    }

    if (!ITypesUtil::Unmarshal(reply, details)) {
        LOG_ERROR("read result failed");
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
        LOG_INFO("failed");
        return RDB_ERROR;
    }
    LOG_INFO("success");
    if (async != nullptr) {
        async(std::move(details));
    }
    return RDB_OK;
}

int32_t RdbServiceProxy::DoAsync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(
        static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_ASYNC), reply, param, option, predicates);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s, seqNum:%{public}u", status,
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
            LOG_ERROR("bundleName:%{public}s, storeName:%{public}s, insert callback failed", param.bundleName_.c_str(),
                SqliteUtils::Anonymous(param.storeName_).c_str());
            return RDB_ERROR;
        }
    }
    LOG_INFO("bundleName:%{public}s, storeName:%{public}s, num=%{public}u, start DoAsync", param.bundleName_.c_str(),
        SqliteUtils::Anonymous(param.storeName_).c_str(), asyncOption.seqNum);
    if (DoAsync(param, asyncOption, predicates) != RDB_OK) {
        syncCallbacks_.Erase(asyncOption.seqNum);
        return RDB_ERROR;
    }
    return RDB_OK;
}

int32_t RdbServiceProxy::SetDistributedTables(const RdbSyncerParam& param, const std::vector<std::string> &tables,
    const std::vector<Reference> &references, int32_t type)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(
        static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_SET_DIST_TABLE), reply, param, tables, references, type);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s, type:%{public}d",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str(), type);
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
    if (observer == nullptr) {
        return RDB_ERROR;
    }
    if (option.mode < SubscribeMode::REMOTE || option.mode >= SUBSCRIBE_MODE_MAX) {
        LOG_ERROR("subscribe mode invalid");
        return RDB_ERROR;
    }
    if (DoSubscribe(param, option) != RDB_OK) {
        return RDB_ERROR;
    }
    auto name = RemoveSuffix(param.storeName_);
    observers_.Compute(name, [observer, &param, &option](const auto &key, std::list<ObserverParam> &value) {
        for (const auto &element : value) {
            if (element.observer == observer) {
                LOG_ERROR("duplicate observer, storeName:%{public}s", SqliteUtils::Anonymous(key).c_str());
                return true;
            }
        }
        value.push_back({ observer, param.bundleName_, option });
        return true;
    });
    return RDB_OK;
}

int32_t RdbServiceProxy::DoSubscribe(const RdbSyncerParam &param, const SubscribeOption &option)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(
        static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_SUBSCRIBE), reply, param, option);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

int32_t RdbServiceProxy::UnSubscribe(const RdbSyncerParam &param, const SubscribeOption &option,
                                     RdbStoreObserver *observer)
{
    if (observer == nullptr) {
        LOG_ERROR("observer is null");
        return RDB_ERROR;
    }
    if (DoUnSubscribe(param) != RDB_OK) {
        return RDB_ERROR;
    }
    auto name = RemoveSuffix(param.storeName_);
    observers_.ComputeIfPresent(name, [observer](const auto &key, std::list<ObserverParam> &value) {
        LOG_INFO("before remove size=%{public}d", static_cast<int>(value.size()));
        value.remove_if([observer](const ObserverParam &param) {
            return param.observer == observer;
        });
        LOG_INFO("after  remove size=%{public}d", static_cast<int>(value.size()));
        return !(value.empty());
    });
    return RDB_OK;
}

int32_t RdbServiceProxy::DoUnSubscribe(const RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_UNSUBSCRIBE), reply, param);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

std::pair<int32_t, std::shared_ptr<RdbServiceProxy::ResultSet>> RdbServiceProxy::RemoteQuery(
    const RdbSyncerParam &param, const std::string &device, const std::string &sql,
    const std::vector<std::string> &selectionArgs)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(
        static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_REMOTE_QUERY), reply, param, device, sql, selectionArgs);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s, device:%{public}.6s", status,
            param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str(),
            SqliteUtils::Anonymous(device).c_str());
        return { status, nullptr };
    }

    sptr<IRemoteObject> remote = reply.ReadRemoteObject();
    if (remote == nullptr) {
        LOG_ERROR("read remote object is null");
        return { RDB_ERROR, nullptr };
    }
    sptr<NativeRdb::ResultSetProxy> instance = new NativeRdb::ResultSetProxy(remote);
    return { RDB_OK, std::shared_ptr<ResultSet>(instance.GetRefPtr(), [holder = instance](const auto *) {}) };
}

RdbServiceProxy::Observers RdbServiceProxy::ExportObservers()
{
    return observers_;
}

void RdbServiceProxy::ImportObservers(Observers &observers)
{
    observers.ForEach([this](const std::string &key, const std::list<ObserverParam> &value) {
        RdbSyncerParam syncerParam;
        for (const auto &param : value) {
            syncerParam.bundleName_ = param.bundleName;
            syncerParam.storeName_ = key;
            Subscribe(syncerParam, param.subscribeOption, param.observer);
        }
        return false;
    });
}

int32_t RdbServiceProxy::BeforeOpen(RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_BEFORE_OPEN), reply, param);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s", status, param.bundleName_.c_str(),
            SqliteUtils::Anonymous(param.storeName_).c_str());
        return status;
    }
    if (!ITypesUtil::Unmarshal(reply, param)) {
        LOG_ERROR("read result failed");
        status = RDB_ERROR;
    }
    return status;
}

int32_t RdbServiceProxy::AfterOpen(const RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_AFTER_OPEN), reply, param);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s", status, param.bundleName_.c_str(),
            SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

int32_t RdbServiceProxy::Delete(const RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_DELETE), reply, param);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s", status, param.bundleName_.c_str(),
            SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

std::pair<int32_t, std::shared_ptr<RdbServiceProxy::ResultSet>> RdbServiceProxy::QuerySharingResource(
    const RdbSyncerParam &param, const PredicatesMemo &predicates, const std::vector<std::string> &columns)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_QUERY_SHARING_RESOURCE), reply,
        param, predicates, columns);
    sptr<IRemoteObject> remote;
    bool success = ITypesUtil::Unmarshal(reply, remote);
    if (status != RDB_OK || !success || remote == nullptr) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s, success:%{public}d, remote is "
                  "%{public}s nullptr",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str(), success,
            remote != nullptr ? "not" : "");
        return { RDB_ERROR, {} };
    }
    sptr<NativeRdb::ResultSetProxy> instance = new NativeRdb::ResultSetProxy(remote);
    return { RDB_OK, std::shared_ptr<ResultSet>(instance.GetRefPtr(), [instance](const auto *) {}) };
}

int32_t RdbServiceProxy::RegisterAutoSyncCallback(
    const RdbSyncerParam &param, std::shared_ptr<DetailProgressObserver> observer)
{
    if (observer == nullptr || param.storeName_.empty()) {
        LOG_ERROR("bundleName:%{public}s, storeName:%{public}s, syncObserver is nullptr", param.bundleName_.c_str(),
            SqliteUtils::Anonymous(param.storeName_).c_str());
        return RDB_ERROR;
    }
    int32_t status = RDB_OK;
    auto name = RemoveSuffix(param.storeName_);
    syncObservers_.Compute(name, [this, &param, &status, observer](const auto &store, auto &observers) {
        for (const auto &element : observers) {
            if (element.get() == observer.get()) {
                LOG_ERROR("duplicate observer, storeName:%{public}s", SqliteUtils::Anonymous(store).c_str());
                return true;
            }
        }
        status = DoRegister(param);
        if (status == RDB_OK) {
            observers.push_back(observer);
        }
        return !observers.empty();
    });
    return status;
}

int32_t RdbServiceProxy::DoRegister(const RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(
        static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_REGISTER_AUTOSYNC_PROGRESS_OBSERVER), reply, param);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s", status, param.bundleName_.c_str(),
            SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

int32_t RdbServiceProxy::UnregisterAutoSyncCallback(
    const RdbSyncerParam &param, std::shared_ptr<DetailProgressObserver> observer)
{
    if (observer == nullptr || param.storeName_.empty()) {
        LOG_ERROR("bundleName:%{public}s, storeName:%{public}s, syncObserver is nullptr", param.bundleName_.c_str(),
            SqliteUtils::Anonymous(param.storeName_).c_str());
        return RDB_ERROR;
    }
    int32_t status = RDB_OK;
    auto name = RemoveSuffix(param.storeName_);
    syncObservers_.ComputeIfPresent(name, [this, &param, &status, observer](const auto &storeName, auto &observers) {
        for (auto it = observers.begin(); it != observers.end();) {
            if (it->get() != observer.get()) {
                ++it;
                continue;
            }
            status = DoUnRegister(param);
            if (status == RDB_OK) {
                it = observers.erase(it);
            }
        }
        return !observers.empty();
    });
    return status;
}

int32_t RdbServiceProxy::DoUnRegister(const RdbSyncerParam &param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(
        static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_UNREGISTER_AUTOSYNC_PROGRESS_OBSERVER), reply, param);
    if (status != RDB_OK) {
        LOG_ERROR("status:%{public}d, bundleName:%{public}s, storeName:%{public}s", status, param.bundleName_.c_str(),
            SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

void RdbServiceProxy::OnDataChange(
    const Origin &origin, const RdbServiceProxy::PrimaryFields &primaries, RdbServiceProxy::ChangeInfo &&changeInfo)
{
    LOG_DEBUG("store:%{public}s data change from :%{public}s, dataType:%{public}d, origin:%{public}d.",
        SqliteUtils::Anonymous(origin.store).c_str(),
        origin.id.empty() ? "empty" : SqliteUtils::Anonymous(*origin.id.begin()).c_str(),
        origin.dataType, origin.origin);
    auto name = RdbServiceProxy::RemoveSuffix(origin.store);
    observers_.ComputeIfPresent(name, [&origin, &primaries, info = std::move(changeInfo)](
                                         const auto &key, const std::list<ObserverParam> &value) mutable {
        auto size = value.size();
        for (const auto &params : value) {
            params.observer->OnChange(origin, primaries, --size > 0 ? ChangeInfo(info) : std::move(info));
        }
        return !value.empty();
    });
}

void RdbServiceProxy::OnSyncComplete(uint32_t seqNum, Details &&result)
{
    syncCallbacks_.ComputeIfPresent(seqNum, [&result] (const auto& key, const AsyncDetail& callback) {
        auto finished = result.empty() || (result.begin()->second.progress == SYNC_FINISH);
        LOG_DEBUG("Sync complete, seqNum%{public}d, result size:%{public}zu", key, result.size());
        if (callback!=nullptr) {
            callback(std::move(result));
        }
        return !finished;
    });
}

void RdbServiceProxy::OnSyncComplete(const std::string &storeName, Details &&result)
{
    syncObservers_.ComputeIfPresent(storeName, [&result](const auto &key, const auto &observers) {
        LOG_DEBUG("Sync complete, storeName%{public}s, result size:%{public}zu", SqliteUtils::Anonymous(key).c_str(),
            result.size());
        for (const auto &observer : observers) {
            if (observer != nullptr) {
                observer->ProgressNotification(result);
            }
        }
        return true;
    });
}

int32_t RdbServiceProxy::NotifyDataChange(const RdbSyncerParam &param, const RdbChangedData &rdbChangedData)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_NOTIFY_DATA_CHANGE),
        reply, param, rdbChangedData);
    if (status != RDB_OK) {
        LOG_ERROR("RdbServiceProxy NotifyDataChange fail, status:%{public}d, "
                  "bundleName:%{public}s, storeName:%{public}s",
            status, param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

int32_t RdbServiceProxy::Disable(const RdbSyncerParam& param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_DISABLE), reply, param);
    if (status != RDB_OK) {
        LOG_ERROR("fail, status:%{public}d, bundleName:%{public}s, storeName:%{public}s", status,
            param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}

int32_t RdbServiceProxy::Enable(const RdbSyncerParam& param)
{
    MessageParcel reply;
    int32_t status = IPC_SEND(static_cast<uint32_t>(RdbServiceCode::RDB_SERVICE_CMD_ENABLE), reply, param);
    if (status != RDB_OK) {
        LOG_ERROR("fail, status:%{public}d, bundleName:%{public}s, storeName:%{public}s", status,
            param.bundleName_.c_str(), SqliteUtils::Anonymous(param.storeName_).c_str());
    }
    return status;
}
} // namespace OHOS::DistributedRdb