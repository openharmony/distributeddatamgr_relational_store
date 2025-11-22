/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <mutex>

#include "js_proxy.h"
#include "js_uv_queue.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_rdb_error.h"
#include "rdb_helper.h"
#include "rdb_store.h"

namespace OHOS {
namespace RelationalStoreJsKit {
using Descriptor = std::function<std::vector<napi_property_descriptor>(void)>;
class NapiRdbStoreObserver;
class NapiStatisticsObserver;
class NapiPerfStatObserver;
class NapiLogObserver;
struct NapiRdbStoreData;
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
    static Descriptor GetDescriptors();
    static void AddSyncFunctions(std::vector<napi_property_descriptor> &properties);
    static napi_value Initialize(napi_env env, napi_callback_info info);
    static napi_value Delete(napi_env env, napi_callback_info info);
    static napi_value Update(napi_env env, napi_callback_info info);
    static napi_value Insert(napi_env env, napi_callback_info info);
    static napi_value BatchInsert(napi_env env, napi_callback_info info);
    static napi_value BatchInsertWithConflictResolution(napi_env env, napi_callback_info info);
    static napi_value Query(napi_env env, napi_callback_info info);
    static napi_value QueryWithoutRowCount(napi_env env, napi_callback_info info);
    static napi_value QuerySqlWithoutRowCount(napi_env env, napi_callback_info info);
    static napi_value QuerySql(napi_env env, napi_callback_info info);
    static napi_value QuerySync(napi_env env, napi_callback_info info);
    static napi_value ExecuteSql(napi_env env, napi_callback_info info);
    static napi_value Execute(napi_env env, napi_callback_info info);
    static napi_value Backup(napi_env env, napi_callback_info info);
    static napi_value Replace(napi_env env, napi_callback_info info);
    static napi_value Attach(napi_env env, napi_callback_info info);
    static napi_value Detach(napi_env env, napi_callback_info info);
    static napi_value GetPath(napi_env env, napi_callback_info info);
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
    static napi_value Close(napi_env env, napi_callback_info info);
    static napi_value CreateTransaction(napi_env env, napi_callback_info info);
    static napi_value Rekey(napi_env env, napi_callback_info info);
    static napi_value RekeyEx(napi_env env, napi_callback_info info);
    static napi_value SetLocale(napi_env env, napi_callback_info info);
    static napi_value OnEvent(napi_env env, napi_callback_info info);
    static napi_value OffEvent(napi_env env, napi_callback_info info);

    static constexpr int EVENT_HANDLE_NUM = 3;
    napi_value RegisteredObserver(napi_env env, const DistributedRdb::SubscribeOption &option,  napi_value callback);
    napi_value UnRegisteredObserver(napi_env env, const DistributedRdb::SubscribeOption &option, napi_value callback);
    napi_value OnStatistics(napi_env env, size_t argc, napi_value *argv);
    napi_value OffStatistics(napi_env env, size_t argc, napi_value *argv);
    napi_value OnErrorLog(napi_env env, size_t argc, napi_value *argv);
    napi_value OffErrorLog(napi_env env, size_t argc, napi_value *argv);
    napi_value OnPerfStat(napi_env env, size_t argc, napi_value *argv);
    napi_value OffPerfStat(napi_env env, size_t argc, napi_value *argv);
    using EventHandle = napi_value (RdbStoreProxy::*)(napi_env, size_t, napi_value *);
    struct HandleInfo {
        std::string_view event;
        EventHandle handle;
    };
    static constexpr HandleInfo onEventHandlers_[EVENT_HANDLE_NUM] = {
        { "statistics", &RdbStoreProxy::OnStatistics },
        { "perfStat", &RdbStoreProxy::OnPerfStat },
        { "sqliteErrorOccurred", &RdbStoreProxy::OnErrorLog },
    };
    static constexpr HandleInfo offEventHandlers_[EVENT_HANDLE_NUM] = {
        { "statistics", &RdbStoreProxy::OffStatistics },
        { "perfStat", &RdbStoreProxy::OffPerfStat },
        { "sqliteErrorOccurred", &RdbStoreProxy::OffErrorLog },
    };
    static void UnregisterAll(
        std::shared_ptr<NativeRdb::RdbStore> rdbStore, std::shared_ptr<NapiRdbStoreData> napiRdbStoreData);
    std::shared_ptr<NapiRdbStoreData> StealNapiRdbStoreData();

    int32_t dbType = NativeRdb::DB_SQLITE;
    std::mutex mutex_;
    bool isSystemAppCalled_ = false;
    std::shared_ptr<AppDataMgrJsKit::UvQueue> queue_;
    std::list<std::shared_ptr<NapiPerfStatObserver>> perfStats_;
    std::shared_ptr<NapiRdbStoreData> napiRdbStoreData_ = nullptr;
    static constexpr int WAIT_TIME_DEFAULT = 2;
    static constexpr int WAIT_TIME_LIMIT = 300;
};
} // namespace RelationalStoreJsKit
} // namespace OHOS

#endif // RDB_JSKIT_NAPI_RDB_STORE_H
