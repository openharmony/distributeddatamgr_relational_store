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

#ifndef RDB_JSKIT_NAPI_RDB_STORE_H
#define RDB_JSKIT_NAPI_RDB_STORE_H

#include <list>
#include <memory>
#include <mutex>

#include "js_proxy.h"
#include "js_uv_queue.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_rdb_error.h"
#include "napi_rdb_store_observer.h"
#include "rdb_helper.h"
#include "rdb_store.h"
#include "rdb_types.h"

namespace OHOS {
namespace RelationalStoreJsKit {
using Descriptor = std::function<std::vector<napi_property_descriptor>(void)>;
class RdbStoreProxy : public JSProxy::JSProxy<NativeRdb::RdbStore> {
public:
    static void Init(napi_env env, napi_value exports);
    static napi_value NewInstance(napi_env env, std::shared_ptr<NativeRdb::RdbStore> value, bool isSystemAppCalled);
    RdbStoreProxy();
    ~RdbStoreProxy();
    RdbStoreProxy(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    RdbStoreProxy &operator=(std::shared_ptr<NativeRdb::RdbStore> rdbStore);
    bool IsSystemAppCalled();

private:
    static napi_value Initialize(napi_env env, napi_callback_info info);
    static napi_value Delete(napi_env env, napi_callback_info info);
    static napi_value Update(napi_env env, napi_callback_info info);
    static napi_value Insert(napi_env env, napi_callback_info info);
    static napi_value BatchInsert(napi_env env, napi_callback_info info);
    static napi_value Query(napi_env env, napi_callback_info info);
    static napi_value RemoteQuery(napi_env env, napi_callback_info info);
    static napi_value QuerySql(napi_env env, napi_callback_info info);
    static napi_value ExecuteSql(napi_env env, napi_callback_info info);
    static napi_value Execute(napi_env env, napi_callback_info info);
    static napi_value Backup(napi_env env, napi_callback_info info);
    static napi_value Count(napi_env env, napi_callback_info info);
    static napi_value Replace(napi_env env, napi_callback_info info);
    static napi_value Attach(napi_env env, napi_callback_info info);
    static napi_value Detach(napi_env env, napi_callback_info info);
    static napi_value GetPath(napi_env env, napi_callback_info info);
    static napi_value IsMemoryRdb(napi_env env, napi_callback_info info);
    static napi_value IsHoldingConnection(napi_env env, napi_callback_info info);
    static napi_value IsReadOnly(napi_env env, napi_callback_info info);
    static napi_value BeginTransaction(napi_env env, napi_callback_info info);
    static napi_value BeginTrans(napi_env env, napi_callback_info info);
    static napi_value RollBack(napi_env env, napi_callback_info info);
    static napi_value RollBackByTxId(napi_env env, napi_callback_info info);
    static napi_value Commit(napi_env env, napi_callback_info info);
    static napi_value QueryByStep(napi_env env, napi_callback_info info);
    static napi_value IsInTransaction(napi_env env, napi_callback_info info);
    static napi_value IsOpen(napi_env env, napi_callback_info info);
    static napi_value GetVersion(napi_env env, napi_callback_info info);
    static napi_value GetRebuilt(napi_env env, napi_callback_info info);
    static napi_value SetVersion(napi_env env, napi_callback_info info);
    static napi_value Restore(napi_env env, napi_callback_info info);
    static napi_value SetDistributedTables(napi_env env, napi_callback_info info);
    static napi_value ObtainDistributedTableName(napi_env env, napi_callback_info info);
    static napi_value Sync(napi_env env, napi_callback_info info);
    static napi_value CloudSync(napi_env env, napi_callback_info info);
    static napi_value GetModifyTime(napi_env env, napi_callback_info info);
    static napi_value CleanDirtyData(napi_env env, napi_callback_info info);
    static napi_value OnEvent(napi_env env, napi_callback_info info);
    static napi_value OffEvent(napi_env env, napi_callback_info info);
    static napi_value Notify(napi_env env, napi_callback_info info);
    static napi_value QuerySharingResource(napi_env env, napi_callback_info info);
    static napi_value Close(napi_env env, napi_callback_info info);
    static Descriptor GetDescriptors();
    static void AddSyncFunctions(std::vector<napi_property_descriptor> &properties);
    static napi_value ModifyLockStatus(napi_env env, napi_callback_info info, bool isLock);
    static napi_value LockRow(napi_env env, napi_callback_info info);
    static napi_value UnlockRow(napi_env env, napi_callback_info info);
    static napi_value QueryLockedRow(napi_env env, napi_callback_info info);

    static constexpr int EVENT_HANDLE_NUM = 2;
    static constexpr int WAIT_TIME_DEFAULT = 2;
    static constexpr int WAIT_TIME_LIMIT = 300;

    napi_value OnRemote(napi_env env, size_t argc, napi_value *argv);
    napi_value OnLocal(napi_env env, const DistributedRdb::SubscribeOption &option, napi_value callback);
    napi_value RegisteredObserver(napi_env env, const DistributedRdb::SubscribeOption &option,
        std::map<std::string, std::list<std::shared_ptr<NapiRdbStoreObserver>>> &observers, napi_value callback);

    napi_value OffRemote(napi_env env, size_t argc, napi_value *argv);
    napi_value OffLocal(napi_env env, const DistributedRdb::SubscribeOption &option, napi_value callback);
    napi_value UnRegisteredObserver(napi_env env, const DistributedRdb::SubscribeOption &option,
        std::map<std::string, std::list<std::shared_ptr<NapiRdbStoreObserver>>> &observers, napi_value callback);

    class SyncObserver
        : public DistributedRdb::DetailProgressObserver, public std::enable_shared_from_this<SyncObserver> {
    public:
        SyncObserver(napi_env env, napi_value callback, std::shared_ptr<AppDataMgrJsKit::UvQueue> uvQueue);
        virtual ~SyncObserver();
        bool operator==(napi_value value);
        void ProgressNotification(const DistributedRdb::Details &details) override;

    private:
        napi_env env_ = nullptr;
        napi_ref callback_ = nullptr;
        std::shared_ptr<AppDataMgrJsKit::UvQueue> queue_ = nullptr;
    };

    napi_value RegisterSyncCallback(napi_env env, size_t argc, napi_value *argv);
    napi_value UnregisterSyncCallback(napi_env env, size_t argc, napi_value *argv);

    using EventHandle = napi_value (RdbStoreProxy::*)(napi_env, size_t, napi_value *);
    struct HandleInfo {
        std::string_view event;
        EventHandle handle;
    };
    static constexpr HandleInfo onEventHandlers_[EVENT_HANDLE_NUM] = {
        { "dataChange", &RdbStoreProxy::OnRemote },
        { "autoSyncProgress", &RdbStoreProxy::RegisterSyncCallback }
    };
    static constexpr HandleInfo offEventHandlers_[EVENT_HANDLE_NUM] = {
        { "dataChange", &RdbStoreProxy::OffRemote },
        { "autoSyncProgress", &RdbStoreProxy::UnregisterSyncCallback }
    };

    bool isSystemAppCalled_ = false;
    std::shared_ptr<AppDataMgrJsKit::UvQueue> queue_;
    std::list<std::shared_ptr<NapiRdbStoreObserver>> observers_[DistributedRdb::SUBSCRIBE_MODE_MAX];
    std::map<std::string, std::list<std::shared_ptr<NapiRdbStoreObserver>>> localObservers_;
    std::map<std::string, std::list<std::shared_ptr<NapiRdbStoreObserver>>> localSharedObservers_;
    std::list<std::shared_ptr<SyncObserver>> syncObservers_;
};
} // namespace RelationalStoreJsKit
} // namespace OHOS

#endif // RDB_JSKIT_NAPI_RDB_STORE_H
