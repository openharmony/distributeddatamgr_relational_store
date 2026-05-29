/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <cstdlib>

#include "cj_lambda.h"
#include "napi_rdb_js_utils.h"
#include "rdb_errno.h"
#include "relational_store_impl_rdbpredicatesproxy.h"
#include "relational_store_impl_rdbstore.h"
#include "relational_store_impl_resultsetproxy.h"
#include "relational_store_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
extern "C" {
FFI_EXPORT int64_t FfiOHOSRelationalStoreQuery(
    int64_t id, int64_t predicatesId, char **columns, int64_t columnsSize, int32_t *errCode)
{
    if (columns == nullptr && columnsSize != 0) {
        *errCode = -1;
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativeRdbPredicates == nullptr) {
        *errCode = -1;
        return -1;
    }
    auto resultSet = nativeRdbStore->Query(*nativeRdbPredicates, columns, columnsSize);
    if (resultSet == nullptr) {
        *errCode = RelationalStoreJsKit::E_INNER_ERROR;
        return -1;
    } else {
        *errCode = RelationalStoreJsKit::OK;
    }
    auto nativeResultSet = FFIData::Create<ResultSetImpl>(resultSet);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetID();
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreRemoteQuery(
    int64_t id, char *device, char *table, int64_t predicatesId, char **columns, int64_t columnsSize)
{
    (void)table;
    if (columns == nullptr && columnsSize != 0) {
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    auto resultSet = nativeRdbStore->RemoteQuery(device, *nativeRdbPredicates, columns, columnsSize);
    if (resultSet == nullptr) {
        return -1;
    }
    auto nativeResultSet = FFIData::Create<ResultSetImpl>(resultSet);
    if (nativeResultSet == nullptr) {
        return -1;
    }
    return nativeResultSet->GetID();
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreDelete(int64_t id, int64_t predicatesId, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativeRdbPredicates == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->Delete(*nativeRdbPredicates, errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreSetDistributedTables(int64_t id, char **tables, int64_t tablesSize)
{
    if (tables == nullptr && tablesSize != 0) {
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->SetDistributedTables(tables, tablesSize);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreSetDistributedTablesType(int64_t id, char **tables,
    int64_t tablesSize, int32_t type)
{
    if (tables == nullptr && tablesSize != 0) {
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->SetDistributedTables(tables, tablesSize, type);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreSetDistributedTablesConfig(
    int64_t id, char **tables, int64_t tablesSize, int32_t type, RetDistributedConfig distributedConfig)
{
    if (tables == nullptr && tablesSize != 0) {
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    DistributedRdb::DistributedConfig config{ distributedConfig.autoSync };
    return nativeRdbStore->SetDistributedTables(tables, tablesSize, type, config);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreSetDistributedTablesConfigExt(
    int64_t id, char **tables, int64_t tablesSize, int32_t type, RetDistributedConfigExt distributedConfig)
{
    if (tables == nullptr && tablesSize != 0) {
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    DistributedRdb::DistributedConfig config;
    config.autoSync = distributedConfig.autoSync;
    config.asyncDownloadAsset = distributedConfig.asyncDownloadAsset;
    config.enableCloud = distributedConfig.enableCloud;
    config.tableType = distributedConfig.tableType;
    return nativeRdbStore->SetDistributedTables(tables, tablesSize, type, config);
}

FFI_EXPORT char *FfiOHOSRelationalStoreObtainDistributedTableName(int64_t id, const char *device, char *table)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return nullptr;
    }
    return nativeRdbStore->ObtainDistributedTableName(device, table);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreBackUp(int64_t id, const char *destName)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Backup(destName);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreReStore(int64_t id, const char *srcName)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Restore(srcName);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreCommit(int64_t id)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Commit();
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreCommitWithTxId(int64_t id, int64_t txId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Commit(txId);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreRollBack(int64_t id)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->RollBack();
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreBeginTransaction(int64_t id)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->BeginTransaction();
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreInsert(
    int64_t id, const char *table, ValuesBucket valuesBucket, int32_t conflict, int32_t *errCode)
{
    if ((valuesBucket.key == nullptr || valuesBucket.value == nullptr) && valuesBucket.size != 0) {
        *errCode = -1;
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->Insert(table, valuesBucket, conflict, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreInsertEx(
    int64_t id, const char *table, ValuesBucketEx valuesBucket, int32_t conflict, int32_t *errCode)
{
    if ((valuesBucket.key == nullptr || valuesBucket.value == nullptr) && valuesBucket.size != 0) {
        *errCode = -1;
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->InsertEx(table, valuesBucket, conflict, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreUpdate(int64_t id, ValuesBucket valuesBucket, int64_t predicatesId,
    NativeRdb::ConflictResolution conflictResolution, int32_t *errCode)
{
    if ((valuesBucket.key == nullptr || valuesBucket.value == nullptr) && valuesBucket.size != 0) {
        *errCode = -1;
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    auto nativeRdbSPredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativeRdbStore == nullptr || nativeRdbSPredicates == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->Update(valuesBucket, *nativeRdbSPredicates, conflictResolution, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreUpdateEx(int64_t id, ValuesBucketEx valuesBucket, int64_t predicatesId,
    NativeRdb::ConflictResolution conflictResolution, int32_t *errCode)
{
    if ((valuesBucket.key == nullptr || valuesBucket.value == nullptr) && valuesBucket.size != 0) {
        *errCode = -1;
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    auto nativeRdbSPredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativeRdbStore == nullptr || nativeRdbSPredicates == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->UpdateEx(valuesBucket, *nativeRdbSPredicates, conflictResolution, errCode);
}

FFI_EXPORT void FfiOHOSRelationalStoreExecuteSql(int64_t id, const char *sql, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return;
    }
    nativeRdbStore->ExecuteSql(sql, errCode);
}

FFI_EXPORT CArrSyncResult FfiOHOSRelationalStoreSync(int64_t id, int32_t mode, int64_t predicatesId, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativeRdbStore == nullptr || nativeRdbPredicates == nullptr) {
        *errCode = -1;
        return CArrSyncResult{ nullptr, nullptr, 0 };
    }
    return nativeRdbStore->Sync(mode, *nativeRdbPredicates);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreCleanDirtyData(int64_t id, const char *tableName, uint64_t cursor)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->CleanDirtyData(tableName, cursor);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreBatchInsert(
    int64_t id, const char *tableName, ValuesBucket *values, int64_t valuesSize, int64_t *insertNum)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->BatchInsert(*insertNum, tableName, values, valuesSize);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreBatchInsertEx(
    int64_t id, const char *tableName, ValuesBucketEx *values, int64_t valuesSize, int64_t *insertNum)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->BatchInsertEx(*insertNum, tableName, values, valuesSize);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreQuerySql(
    int64_t id, const char *sql, ValueType *bindArgs, int64_t size, int32_t *errCode)
{
    if (bindArgs == nullptr && size != 0) {
        *errCode = -1;
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = RelationalStoreJsKit::E_INNER_ERROR;
        return -1;
    }
    auto resultSet = nativeRdbStore->QuerySql(sql, bindArgs, size);
    if (resultSet == nullptr) {
        *errCode = RelationalStoreJsKit::E_INNER_ERROR;
        return -1;
    } else {
        *errCode = RelationalStoreJsKit::OK;
    }
    auto nativeResultSet = FFIData::Create<ResultSetImpl>(resultSet);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetID();
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreQuerySqlEx(int64_t id, const char *sql, ValueTypeEx *bindArgs, int64_t size,
    int32_t *errCode)
{
    if (bindArgs == nullptr && size != 0) {
        *errCode = -1;
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = RelationalStoreJsKit::E_INNER_ERROR;
        return -1;
    }
    auto resultSet = nativeRdbStore->QuerySqlEx(sql, bindArgs, size);
    if (resultSet == nullptr) {
        *errCode = RelationalStoreJsKit::E_INNER_ERROR;
        return -1;
    } else {
        *errCode = RelationalStoreJsKit::OK;
    }
    auto nativeResultSet = FFIData::Create<ResultSetImpl>(resultSet);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetID();
}

FFI_EXPORT void FfiOHOSRelationalStoreExecuteSqlBindArgs(
    int64_t id, char *sql, ValueType *bindArgs, int64_t bindArgsSize, int32_t *errCode)
{
    if (bindArgs == nullptr && bindArgsSize != 0) {
        *errCode = -1;
        return;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return;
    }
    nativeRdbStore->ExecuteSql(sql, bindArgs, bindArgsSize, errCode);
}

FFI_EXPORT void FfiOHOSRelationalStoreExecuteSqlBindArgsEx(
    int64_t id, char *sql, ValueTypeEx *bindArgs, int64_t bindArgsSize, int32_t *errCode)
{
    if (bindArgs == nullptr && bindArgsSize != 0) {
        *errCode = -1;
        return;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return;
    }
    nativeRdbStore->ExecuteSqlEx(sql, bindArgs, bindArgsSize, errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOn(
    int64_t id, const char *event, bool interProcess, int64_t callback, void (*callbackRef)())
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    auto onChange = [lambda = CJLambda::Create(callbackRef)]() -> void { lambda(); };
    return nativeRdbStore->RegisterObserver(event, interProcess, callback, onChange);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOnArrStr(int64_t id, int32_t subscribeType, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->RegisterObserverArrStr(subscribeType, callbackId);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOnChangeInfo(int64_t id, int32_t subscribeType, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->RegisterObserverChangeInfo(subscribeType, callbackId);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOnProgressDetails(int64_t id, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->RegisterObserverProgressDetails(callbackId);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOff(int64_t id, const char *event, bool interProcess, int64_t callback)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserver(event, interProcess, callback);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffAll(int64_t id, const char *event, bool interProcess)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterAllObserver(event, interProcess);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffArrStrChangeInfo(int64_t id, int32_t subscribeType, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserverArrStrChangeInfo(subscribeType, callbackId);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffArrStrChangeInfoAll(int64_t id, int32_t subscribeType)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserverArrStrChangeInfoAll(subscribeType);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffProgressDetails(int64_t id, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserverProgressDetails(callbackId);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffProgressDetailsAll(int64_t id)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserverProgressDetailsAll();
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreEmit(int64_t id, const char *event)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Emit(event);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreCloudSync(int64_t id, int32_t mode, CArrStr tables, int64_t callbackId)
{
    if (tables.head == nullptr && tables.size != 0) {
        return -1;
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->CloudSync(mode, tables, callbackId);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetVersion(int64_t id, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->GetVersion(*errCode);
}

FFI_EXPORT void FfiOHOSRelationalStoreSetVersion(int64_t id, int32_t value, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return;
    }
    nativeRdbStore->SetVersion(value, *errCode);
}

FFI_EXPORT ModifyTime FfiOHOSRelationalStoreGetModifyTime(
    int64_t id, char *cTable, char *cColumnName, CArrPRIKeyType cPrimaryKeys, int32_t *errCode)
{
    if (cPrimaryKeys.head == nullptr && cPrimaryKeys.size != 0) {
        *errCode = -1;
        return ModifyTime{ 0 };
    }
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return ModifyTime{ 0 };
    }
    return nativeRdbStore->GetModifyTime(cTable, cColumnName, cPrimaryKeys, *errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreRdbStoreGetRebuilt(int64_t id, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return 0;
    }
    return nativeRdbStore->GetRebuilt();
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreBatchInsertWithConflictResolution(int64_t id,
    const char *tableName, ValuesBucketEx *valuesBuckets, int64_t valuesSize, int32_t conflict, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->BatchInsertWithConflictResolution(tableName, valuesBuckets, valuesSize, conflict, errCode);
}

FFI_EXPORT ValueTypeEx FfiOHOSRelationalStoreExecute(int64_t id, const char *sql,
    ValueTypeEx *bindArgs, int64_t bindArgsSize, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return ValueTypeEx{};
    }
    return nativeRdbStore->Execute(sql, bindArgs, bindArgsSize, errCode);
}

FFI_EXPORT ValueTypeEx FfiOHOSRelationalStoreExecuteWithTxId(int64_t id, const char *sql,
    ValueTypeEx *bindArgs, int64_t bindArgsSize, int64_t txId, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return ValueTypeEx{};
    }
    return nativeRdbStore->Execute(sql, bindArgs, bindArgsSize, txId, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreBeginTrans(int64_t id, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->BeginTrans(errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreRdbStoreClose(int64_t id)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Close();
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreAttach(int64_t id, const char *fullPath,
    const char *attachName, int32_t waitTime, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->Attach(fullPath, attachName, waitTime, errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreAttachConfig(int64_t id, OHOS::AbilityRuntime::Context *context,
    StoreConfigEx *config, const char *attachName, int32_t waitTime, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->AttachConfig(context, config, attachName, waitTime, errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreDetach(int64_t id, const char *attachName,
    int32_t waitTime, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->Detach(attachName, waitTime, errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreResultSetGetColumnType(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto resultSet = FFIData::GetData<ResultSetImpl>(id);
    if (resultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return resultSet->GetColumnType(columnIndex, rtnCode);
}

FFI_EXPORT RowDataEx FfiOHOSRelationalStoreResultSetGetCurrentRowData(int64_t id, int32_t *rtnCode)
{
    auto resultSet = FFIData::GetData<ResultSetImpl>(id);
    if (resultSet == nullptr) {
        *rtnCode = -1;
        return RowDataEx{ nullptr, 0 };
    }
    return resultSet->GetCurrentRowData(rtnCode);
}

FFI_EXPORT RowsDataEx FfiOHOSRelationalStoreResultSetGetRowsData(int64_t id,
    int32_t maxCount, int32_t position, int32_t *rtnCode)
{
    auto resultSet = FFIData::GetData<ResultSetImpl>(id);
    if (resultSet == nullptr) {
        *rtnCode = -1;
        return RowsDataEx{ nullptr, 0 };
    }
    return resultSet->GetRowsData(maxCount, position, rtnCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreQueryWithoutRowCount(int64_t id, int64_t predicatesId,
    char **columns, int64_t columnsSize, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    auto nativePredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativePredicates == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->QueryWithoutRowCount(*nativePredicates, columns, columnsSize, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreQuerySqlWithoutRowCount(int64_t id, const char *sql,
    ValueTypeEx *bindArgs, int64_t size, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->QuerySqlWithoutRowCount(sql, bindArgs, size, errCode);
}

FFI_EXPORT ReturningResult FfiOHOSRelationalStoreBatchInsertWithReturning(int64_t id,
    const char *tableName, ValuesBucketEx *valuesBuckets, int64_t valuesSize, ReturningConfig config,
    int32_t conflict, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    return nativeRdbStore->BatchInsertWithReturning(tableName, valuesBuckets, valuesSize, config, conflict, errCode);
}

FFI_EXPORT ReturningResult FfiOHOSRelationalStoreUpdateWithReturning(int64_t id,
    ValuesBucketEx valuesBucket, int64_t predicatesId, ReturningConfig config,
    int32_t conflict, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    auto nativePredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativePredicates == nullptr) {
        *errCode = -1;
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    return nativeRdbStore->UpdateWithReturning(valuesBucket, *nativePredicates, config, conflict, errCode);
}

FFI_EXPORT ReturningResult FfiOHOSRelationalStoreDeleteWithReturning(int64_t id,
    int64_t predicatesId, ReturningConfig config, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    auto nativePredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativePredicates == nullptr) {
        *errCode = -1;
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    return nativeRdbStore->DeleteWithReturning(*nativePredicates, config, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreCreateTransaction(int64_t id, int32_t transactionType, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->CreateTransaction(transactionType, errCode);
}
}
} // namespace Relational
} // namespace OHOS