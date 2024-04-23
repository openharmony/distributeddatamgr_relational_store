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
#include "relational_store_impl_resultsetproxy.h"
#include "relational_store_utils.h"
#include "rdb_store_config.h"
#include "ffi_remote_data.h"
#include "napi_base_context.h"
#include "rdb_store.h"
#include "rdb_types.h"
#include "rdb_common.h"
#include "napi_rdb_js_utils.h"
#include "cj_lambda.h"

namespace OHOS {
namespace Relational {
    class RdbStoreObserverImpl : public OHOS::DistributedRdb::RdbStoreObserver {
    public:
        RdbStoreObserverImpl(std::function<void()> *callback, const std::function<void()>& callbackRef);
        ~RdbStoreObserverImpl() override = default;
        void OnChange() override;
        void OnChange(const std::vector<std::string> &devices) override
        {
            return;
        };
        void OnChange(const DistributedRdb::Origin &origin, const PrimaryFields &fields,
            ChangeInfo &&changeInfo) override
        {
            OnChange(origin.id);
        };
        std::function<void()> *GetCallBack();
    private:
        std::function<void()> *m_callback;
        std::function<void()> m_callbackRef;
    };

    class RdbStoreImpl : public OHOS::FFI::FFIData {
    public:
        OHOS::FFI::RuntimeType* GetRuntimeType() override
        {
            return GetClassType();
        }

        explicit RdbStoreImpl(std::shared_ptr<OHOS::NativeRdb::RdbStore> rdbStore);

        std::shared_ptr<NativeRdb::ResultSet> Query(RdbPredicatesImpl &predicates, char** column, int64_t columnSize);
        std::shared_ptr<NativeRdb::ResultSet> RemoteQuery(char* device, RdbPredicatesImpl &predicates, char** column,
            int64_t columnSize);
        int Delete(RdbPredicatesImpl &predicates, int32_t *errCode);
        void SetDistributedTables(char** tables, int64_t tablesSize);
        void SetDistributedTables(char** tables, int64_t tablesSize, int32_t type);
        void SetDistributedTables(char** tables, int64_t tablesSize, int32_t type,
            DistributedRdb::DistributedConfig &distributedConfig);
        int32_t Commit();
        int32_t RollBack();
        int32_t BeginTransaction();
        int32_t Backup(const char* destName);
        int32_t Restore(const char* srcName);
        char* ObtainDistributedTableName(const char* device, const char* table);
        int32_t Emit(const char* event);
        int64_t Insert(const char* table, ValuesBucket valuesBucket, int32_t conflict, int32_t *errCode);
        int32_t BatchInsert(int64_t &insertNum, const char* tableName, ValuesBucket* valuesBuckets, int64_t valuesSize);
        void ExecuteSql(const char* sql, int32_t *errCode);
        int32_t CleanDirtyData(const char* tableName, uint64_t cursor);
        CArrSyncResult Sync(int32_t mode, RdbPredicatesImpl &predicates);
        int32_t Update(ValuesBucket valuesBucket, RdbPredicatesImpl &predicates,
            NativeRdb::ConflictResolution conflictResolution, int32_t *errCode);
        std::shared_ptr<NativeRdb::ResultSet> QuerySql(const char *sql, ValueType *bindArgs, int64_t size);
        void ExecuteSql(const char* sql, ValueType* bindArgs, int64_t bindArgsSize, int32_t *errCode);
        int32_t RegisterObserver(const char *event, bool interProcess, std::function<void()> *callback,
            const std::function<void()>& callbackRef);
        int32_t RegisteredObserver(DistributedRdb::SubscribeOption option, std::map<std::string,
            std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers,
        std::function<void()> *callback, const std::function<void()>& callbackRef);
        bool HasRegisteredObserver(std::function<void()> *callback,
            std::list<std::shared_ptr<RdbStoreObserverImpl>> &observers);
        int32_t UnRegisterObserver(const char *event, bool interProcess, std::function<void()> *callback);
        int32_t UnRegisterAllObserver(const char *event, bool interProcess);
        int32_t UnRegisteredObserver(DistributedRdb::SubscribeOption option, std::map<std::string,
            std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers,
        std::function<void()> *callback);
        int32_t UnRegisteredAllObserver(DistributedRdb::SubscribeOption option, std::map<std::string,
            std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers);

        std::vector<OHOS::NativeRdb::ValueObject> bindArgs;
        std::shared_ptr<OHOS::NativeRdb::RdbStore> rdbStore_;
        std::vector<uint8_t> newKey;
        std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> localObservers_;
        std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> localSharedObservers_;
    private:
        friend class OHOS::FFI::RuntimeType;
        friend class OHOS::FFI::TypeBase;
        static OHOS::FFI::RuntimeType* GetClassType();
    };

    int64_t GetRdbStore(OHOS::AbilityRuntime::Context* context, StoreConfig config,
        int32_t *errCode);

    void DeleteRdbStore(OHOS::AbilityRuntime::Context* context, const char* name,
        int32_t *errCode);

    void DeleteRdbStoreConfig(OHOS::AbilityRuntime::Context* context, StoreConfig config,
        int32_t *errCode);
}
}

#endif

