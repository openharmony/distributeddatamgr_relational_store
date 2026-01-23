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

#ifndef OHOS_RELATION_STORE_RDBSTORE_IMPL_H
#define OHOS_RELATION_STORE_RDBSTORE_IMPL_H

#include "ani_rdb_utils.h"

namespace OHOS {
namespace RdbTaihe {
using namespace taihe;
using namespace ohos::data::relationalStore;
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RdbTaihe;
using ValueType = ohos::data::relationalStore::ValueType;
using ValueObject = OHOS::NativeRdb::ValueObject;
using NativeDistributedTableMode = OHOS::DistributedRdb::DistributedTableMode;
using NativeDistributedConfig = OHOS::DistributedRdb::DistributedConfig;
using NativeDistributedTableType = OHOS::DistributedRdb::DistributedTableType;

class RdbStoreImpl {
public:
    RdbStoreImpl();
    explicit RdbStoreImpl(ani_object context, StoreConfig const &config);
    int32_t GetVersion();
    void SetVersion(int32_t veriosn);
    RebuildType GetRebuilt();
    void SetRebuilt(RebuildType type);
    int64_t InsertWithConflict(string_view table, map_view<string, ValueType> values, ConflictResolution conflict);
    int64_t InsertWithValue(string_view table, map_view<string, ValueType> values);
    int64_t InsertSync(
        string_view table, map_view<string, ValueType> values, optional_view<ConflictResolution> conflict);
    int64_t BatchInsertSync(string_view table, array_view<map<string, ValueType>> values);
    int64_t UpdateWithPredicate(map_view<string, ValueType> values, weak::RdbPredicates predicates);
    int64_t UpdateSync(map_view<string, ValueType> values, weak::RdbPredicates predicates,
        optional_view<ConflictResolution> conflict);
    int64_t UpdateDataShareSync(
        ::taihe::string_view table, ::ohos::data::relationalStore::ValuesBucket const &values, uintptr_t predicates);
    int64_t DeleteSync(weak::RdbPredicates predicates);
    int64_t DeleteDataShareSync(::taihe::string_view table, uintptr_t predicates);
    ResultSet QueryWithPredicate(weak::RdbPredicates predicates);
    ResultSet QueryWithColumn(weak::RdbPredicates predicates, array_view<string> columns);
    ResultSet QueryWithOptionalColumn(weak::RdbPredicates predicates, optional_view<array<string>> columns);
    ResultSet QuerySync(weak::RdbPredicates predicates, optional_view<array<string>> columns);
    LiteResultSet QueryWithoutRowCountSync(weak::RdbPredicates predicates, optional_view<array<string>> columns);
    LiteResultSet QuerySqlWithoutRowCountSync(string_view sql, optional_view<array<ValueType>> bindArgs);
    ResultSet QueryDataShareSync(::taihe::string_view table, uintptr_t predicates);
    ResultSet QueryDataShareWithColumnSync(
        string_view table, uintptr_t predicates, optional_view<array<::taihe::string>> columns);
    ResultSet QuerySqlWithSql(string_view sql);
    ResultSet QuerySqlWithArgs(string_view sql, array_view<ValueType> bindArgs);
    ResultSet QuerySqlSync(string_view sql, optional_view<array<ValueType>> bindArgs);
    ModifyTime GetModifyTimeSync(
        string_view table, string_view columnName, array_view<PRIKeyType> primaryKeys);
    void CleanDirtyDataWithCursor(string_view table, uint64_t cursor);
    void CleanDirtyDataWithTable(string_view table);
    void CleanDirtyDataWithOptionCursor(string_view table, optional_view<uint64_t> cursor);
    ResultSet QuerySharingResourceWithOptionColumn(weak::RdbPredicates predicates,
        optional_view<array<string>> columns);
    ResultSet QuerySharingResourceWithPredicate(weak::RdbPredicates predicates);
    ResultSet QuerySharingResourceWithColumn(weak::RdbPredicates predicates, array_view<string> columns);
    void ExecuteSqlWithSql(string_view sql);
    void ExecuteSqlWithArgs(string_view sql, array_view<ValueType> bindArgs);
    void ExecuteSqlWithOptionArgs(string_view sql, optional_view<array<ValueType>> bindArgs);
    ValueType ExecuteWithOptionArgs(string_view sql, optional_view<array<ValueType>> args);
    ValueType ExecuteWithTxId(string_view sql, int64_t txId, optional_view<array<ValueType>> args);
    ValueType ExecuteSync(string_view sql, optional_view<array<ValueType>> args);
    void BeginTransaction();
    int64_t BeginTransSync();
    void Commit();
    void CommitWithTxId(int64_t txId);
    void RollBack();
    void RollbackSync(int64_t txId);
    void BackupSync(string_view destName);
    void RestoreWithSrcName(string_view srcName);
    void RestoreWithVoid();
    void SetDistributedTablesWithTables(array_view<string> tables);
    void SetDistributedTablesWithType(array_view<string> tables, DistributedType type);
    void SetDistributedTablesWithConfig(
        array_view<string> tables, DistributedType type, DistributedConfig const &config);
    void SetDistributedTablesWithOptionConfig(
        array_view<string> tables, optional_view<DistributedType> type, optional_view<DistributedConfig> config);
    string ObtainDistributedTableNameSync(string_view device, string_view table);
    array<map<string, int32_t>> SyncSync(SyncMode mode, weak::RdbPredicates predicates);
    void CloudSyncWithProgress(SyncMode mode, callback_view<void(ProgressDetails const &)> progress);
    void CloudSyncWithTable(
        SyncMode mode, array_view<string> tables, callback_view<void(ProgressDetails const &)> progress);
    void CloudSyncWithPredicates(
        SyncMode mode, weak::RdbPredicates predicates, callback_view<void(ProgressDetails const &)> progress);
    ResultSet RemoteQuerySync(
        string_view device, string_view table, weak::RdbPredicates predicates, array_view<string> columns);
    void OnDataChangeWithChangeInfo(ohos::data::relationalStore::SubscribeType type,
        taihe::callback_view<void(taihe::array_view<::ohos::data::relationalStore::ChangeInfo> info)> callback,
        uintptr_t opq);
    void OnDataChangeWithDevices(ohos::data::relationalStore::SubscribeType type,
        taihe::callback_view<void(taihe::array_view<::taihe::string> info)> callback,
        uintptr_t opq);
    void OffDataChangeInner(ohos::data::relationalStore::SubscribeType type, taihe::optional_view<uintptr_t> opq);
    void OnAutoSyncProgressInner(
        taihe::callback_view<void(ohos::data::relationalStore::ProgressDetails const& info)> callback, uintptr_t opq);
    void OffAutoSyncProgressInner(optional_view<uintptr_t> opq);
    void OnStatisticsInner(
        taihe::callback_view<void(ohos::data::relationalStore::SqlExecutionInfo const& info)> callback, uintptr_t opq);
    void OffStatisticsInner(optional_view<uintptr_t> opq);
    void OnCommon(taihe::string_view event, bool interProcess, callback_view<void()> callback, uintptr_t opq);
    void OffCommon(taihe::string_view event, bool interProcess, optional_view<uintptr_t> opq);
    void Emit(string_view event);
    void CloseSync();
    int32_t AttachWithWaitTime(string_view fullPath, string_view attachName, taihe::optional_view<int32_t> waitTime);
    int32_t AttachWithContext(
        uintptr_t context, StoreConfig const &config, string_view attachName, optional_view<int32_t> waitTime);
    int32_t DetachSync(string_view attachName, optional_view<int32_t> waitTime);
    void LockRowSync(weak::RdbPredicates predicates);
    void UnlockRowSync(weak::RdbPredicates predicates);
    ResultSet QueryLockedRowSync(weak::RdbPredicates predicates, optional_view<array<string>> columns);
    uint32_t LockCloudContainerSync();
    void UnlockCloudContainerSync();
    Transaction CreateTransactionSync(optional_view<::ohos::data::relationalStore::TransactionOptions> options);
    Result BatchInsertWithReturningSync(string_view table, array_view<ValuesBucket> values,
        ReturningConfig const &config, optional_view<ConflictResolution> conflict);
    Result UpdateWithReturningSync(ValuesBucket values, weak::RdbPredicates predicates,
        ReturningConfig const &config, optional_view<ConflictResolution> conflict);
    Result DeleteWithReturningSync(weak::RdbPredicates predicates, ReturningConfig const &config);
    int64_t BatchInsertWithConflictResolutionSync(taihe::string_view table,
        taihe::array_view<ohos::data::relationalStore::ValuesBucket> values,
        ohos::data::relationalStore::ConflictResolution conflict);

protected:
    void RegisterListener(std::string const &event, OHOS::DistributedRdb::SubscribeMode &mode,
        ani_rdbutils::VarCallbackType &cb, uintptr_t opq);
    int RegisterDataChangeObserver(
        OHOS::DistributedRdb::SubscribeMode &type, ani_rdbutils::VarCallbackType &cb, ani_ref callbackRef);
    int RegisterSyncProgressObserver(ani_rdbutils::VarCallbackType &cb, ani_ref callbackRef);
    int RegisterStatisticObserver(ani_rdbutils::VarCallbackType &cb, ani_ref callbackRef);
    int RegisterCommonEventObserver(std::string const &event, OHOS::DistributedRdb::SubscribeMode &mode,
        ani_rdbutils::VarCallbackType &cb, ani_ref callbackRef);
    void UnregisterListener(std::string const &event, OHOS::DistributedRdb::SubscribeMode &mode,
        ::taihe::optional_view<uintptr_t> opq, bool &isUpdateFlag);
    int UnRegisterObserver(
        OHOS::DistributedRdb::SubscribeOption &option, ::taihe::optional_view<uintptr_t> opq, bool &isUpdateFlag);
    int UnRegisterObserverExistOpq(
        OHOS::DistributedRdb::SubscribeOption &option, ani_ref jsCallbackRef, bool &isUpdateFlag);
    void UnRegisterAll();

private:
    std::shared_ptr<OHOS::NativeRdb::RdbStore> nativeRdbStore_;
    bool isSystemApp_ = false;
    std::recursive_mutex cbMapMutex_;
    std::map<std::string, std::vector<std::shared_ptr<ani_rdbutils::DataObserver>>> jsCbMap_;
};
} // namespace RdbTaihe
} // namespace OHOS

#endif // OHOS_RELATION_STORE_RDBSTORE_IMPL_H