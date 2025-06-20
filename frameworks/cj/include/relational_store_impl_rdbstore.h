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

#ifndef RELATIONAL_STORE_IMPL_RDBSTORE_FFI_H
#define RELATIONAL_STORE_IMPL_RDBSTORE_FFI_H

#include <list>

#include "cj_lambda.h"
#include "ffi_remote_data.h"
#include "napi_base_context.h"
#include "napi_rdb_js_utils.h"
#include "rdb_common.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "relational_store_impl_resultsetproxy.h"
#include "relational_store_utils.h"

namespace OHOS {
namespace Relational {
class RdbStoreObserverImpl : public DistributedRdb::RdbStoreObserver {
public:
    enum FuncType : int32_t { NoParam = 0, ParamArrStr, ParamChangeInfo };
    RdbStoreObserverImpl(std::function<void()> *callback, const std::function<void()> &callbackRef);
    RdbStoreObserverImpl(int64_t id, FuncType type, int32_t mode = DistributedRdb::REMOTE);
    ~RdbStoreObserverImpl() override = default;
    void OnChange() override
    {
        m_callbackRef();
    };
    void OnChange(const std::vector<std::string> &devices) override
    {
        carrStrFunc(devices);
    };
    void OnChange(const DistributedRdb::Origin &origin, const PrimaryFields &fields,
        DistributedRdb::RdbStoreObserver::ChangeInfo &&changeInfo) override
    {
        if (mode_ != DistributedRdb::CLOUD_DETAIL && mode_ != DistributedRdb::LOCAL_DETAIL) {
            RdbStoreObserver::OnChange(origin, fields, std::move(changeInfo));
            return;
        }
        changeInfoFunc(origin, fields, std::move(changeInfo));
    };

    int64_t GetCallBackId()
    {
        return callbackId;
    };
    std::function<void()> *GetCallBack();

private:
    std::function<void()> *m_callback = nullptr;
    std::function<void()> m_callbackRef = nullptr;
    int32_t mode_ = DistributedRdb::REMOTE;
    int64_t callbackId = 0;
    FuncType funcType = NoParam;
    std::function<void()> func = nullptr;
    std::function<void(const std::vector<std::string> &devices)> carrStrFunc = nullptr;
    std::function<void(const DistributedRdb::Origin &origin, const PrimaryFields &fields,
        DistributedRdb::RdbStoreObserver::ChangeInfo &&changeInfo)>
        changeInfoFunc = nullptr;
};

class SyncObserverImpl : public DistributedRdb::DetailProgressObserver {
public:
    SyncObserverImpl(int64_t id);
    ~SyncObserverImpl() override = default;
    void ProgressNotification(const DistributedRdb::Details &details) override
    {
        func(details);
    };

    int64_t GetCallBackId()
    {
        return callbackId;
    };

private:
    int64_t callbackId;
    std::function<void(const DistributedRdb::Details &details)> func;
};

class RdbStoreImpl : public OHOS::FFI::FFIData {
public:
    OHOS::FFI::RuntimeType *GetRuntimeType() override
    {
        return GetClassType();
    }

    explicit RdbStoreImpl(std::shared_ptr<OHOS::NativeRdb::RdbStore> rdbStore);

    std::shared_ptr<NativeRdb::ResultSet> Query(RdbPredicatesImpl &predicates, char **column, int64_t columnSize);
    std::shared_ptr<NativeRdb::ResultSet> RemoteQuery(
        char *device, RdbPredicatesImpl &predicates, char **column, int64_t columnSize);
    int Delete(RdbPredicatesImpl &predicates, int32_t *errCode);
    int32_t SetDistributedTables(char **tables, int64_t tablesSize);
    int32_t SetDistributedTables(char **tables, int64_t tablesSize, int32_t type);
    int32_t SetDistributedTables(
        char **tables, int64_t tablesSize, int32_t type, DistributedRdb::DistributedConfig &distributedConfig);
    int32_t Commit();
    int32_t RollBack();
    int32_t BeginTransaction();
    int32_t Backup(const char *destName);
    int32_t Restore(const char *srcName);
    char *ObtainDistributedTableName(const char *device, const char *table);
    int32_t Emit(const char *event);
    int64_t Insert(const char *table, ValuesBucket valuesBucket, int32_t conflict, int32_t *errCode);
    int32_t BatchInsert(int64_t &insertNum, const char *tableName, ValuesBucket *valuesBuckets, int64_t valuesSize);
    void ExecuteSql(const char *sql, int32_t *errCode);
    int32_t CleanDirtyData(const char *tableName, uint64_t cursor);
    CArrSyncResult Sync(int32_t mode, RdbPredicatesImpl &predicates);
    int32_t Update(ValuesBucket valuesBucket, RdbPredicatesImpl &predicates,
        NativeRdb::ConflictResolution conflictResolution, int32_t *errCode);
    std::shared_ptr<NativeRdb::ResultSet> QuerySql(const char *sql, ValueType *bindArgs, int64_t size);
    void ExecuteSql(const char *sql, ValueType *bindArgs, int64_t bindArgsSize, int32_t *errCode);
    int32_t RegisterObserver(const char *event, bool interProcess, std::function<void()> *callback,
        const std::function<void()> &callbackRef);
    int32_t RegisteredObserver(DistributedRdb::SubscribeOption option,
        std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers,
        std::function<void()> *callback, const std::function<void()> &callbackRef);
    int32_t RegisterObserverArrStr(int32_t subscribeType, int64_t callbackId);
    int32_t RegisterObserverChangeInfo(int32_t subscribeType, int64_t callbackId);
    int32_t RegisterObserverProgressDetails(int64_t callbackId);
    bool HasRegisteredObserver(
        std::function<void()> *callback, std::list<std::shared_ptr<RdbStoreObserverImpl>> &observers);
    int32_t UnRegisterObserver(const char *event, bool interProcess, std::function<void()> *callback);
    int32_t UnRegisterAllObserver(const char *event, bool interProcess);
    int32_t UnRegisteredObserver(DistributedRdb::SubscribeOption option,
        std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers,
        std::function<void()> *callback);
    int32_t UnRegisteredAllObserver(DistributedRdb::SubscribeOption option,
        std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers);
    int32_t UnRegisterObserverArrStrChangeInfo(int32_t subscribeType, int64_t callbackId);
    int32_t UnRegisterObserverArrStrChangeInfoAll(int32_t subscribeType);
    int32_t UnRegisterObserverProgressDetails(int64_t callbackId);
    int32_t UnRegisterObserverProgressDetailsAll();
    int32_t CloudSync(int32_t mode, CArrStr tables, int64_t callbackId);
    int32_t GetVersion(int32_t &errCode);
    void SetVersion(int32_t value, int32_t &errCode);
    ModifyTime GetModifyTime(char *cTable, char *cColumnName, CArrPRIKeyType &cPrimaryKeys, int32_t &errCode);
    int32_t GetRebuilt();
    int64_t InsertEx(const char *table, ValuesBucketEx valuesBucket, int32_t conflict, int32_t *errCode);
    int32_t UpdateEx(ValuesBucketEx valuesBucket, RdbPredicatesImpl &predicates,
        NativeRdb::ConflictResolution conflictResolution, int32_t *errCode);
    int32_t BatchInsertEx(int64_t &insertNum, const char *tableName, ValuesBucketEx *valuesBuckets, int64_t valuesSize);
    std::shared_ptr<NativeRdb::ResultSet> QuerySqlEx(const char *sql, ValueTypeEx *bindArgs, int64_t size);
    void ExecuteSqlEx(const char *sql, ValueTypeEx *bindArgs, int64_t bindArgsSize, int32_t *errCode);

private:
    friend class OHOS::FFI::RuntimeType;
    friend class OHOS::FFI::TypeBase;
    static OHOS::FFI::RuntimeType *GetClassType();
    std::vector<OHOS::NativeRdb::ValueObject> bindArgs;
    std::shared_ptr<OHOS::NativeRdb::RdbStore> rdbStore_;
    std::vector<uint8_t> newKey;
    std::list<std::shared_ptr<RdbStoreObserverImpl>> observers_[DistributedRdb::SUBSCRIBE_MODE_MAX];
    std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> localObservers_;
    std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> localSharedObservers_;
    std::list<std::shared_ptr<SyncObserverImpl>> syncObservers_;
};

int64_t GetRdbStore(OHOS::AbilityRuntime::Context *context, StoreConfig config, int32_t *errCode);

int64_t GetRdbStoreEx(OHOS::AbilityRuntime::Context *context, const StoreConfigEx *config, int32_t *errCode);

void DeleteRdbStore(OHOS::AbilityRuntime::Context *context, const char *name, int32_t *errCode);

void DeleteRdbStoreConfig(OHOS::AbilityRuntime::Context *context, StoreConfig config, int32_t *errCode);

void DeleteRdbStoreConfigEx(OHOS::AbilityRuntime::Context *context, const StoreConfigEx *config, int32_t *errCode);
} // namespace Relational
} // namespace OHOS

#endif
