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

#include "relational_store_ffi.h"

#include <cstdint>
#include <cstdlib>

#include "cj_lambda.h"
#include "napi_rdb_js_utils.h"
#include "rdb_errno.h"
#include "relational_store_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
extern "C" {
int64_t FfiOHOSRelationalStoreGetRdbStore(OHOS::AbilityRuntime::Context *context, StoreConfig config, int32_t *errCode)
{
    return GetRdbStore(context, config, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreGetRdbStoreEx(OHOS::AbilityRuntime::Context *context,
    const StoreConfigEx *config, int32_t *errCode)
{
    return GetRdbStoreEx(context, config, errCode);
}

void FfiOHOSRelationalStoreDeleteRdbStore(OHOS::AbilityRuntime::Context *context, const char *name, int32_t *errCode)
{
    DeleteRdbStore(context, name, errCode);
}

void FfiOHOSRelationalStoreDeleteRdbStoreConfig(
    OHOS::AbilityRuntime::Context *context, StoreConfig config, int32_t *errCode)
{
    DeleteRdbStoreConfig(context, config, errCode);
}

void FfiOHOSRelationalStoreDeleteRdbStoreConfigEx(
    OHOS::AbilityRuntime::Context *context, const StoreConfigEx *config, int32_t *errCode)
{
    DeleteRdbStoreConfigEx(context, config, errCode);
}

int64_t FfiOHOSRelationalStoreRdbPredicatesConstructor(const char *tableName)
{
    auto nativeRdbPredicates = FFIData::Create<RdbPredicatesImpl>(tableName);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    return nativeRdbPredicates->GetID();
}

int32_t FfiOHOSRelationalStoreInDevices(int64_t id, const char **devicesArray, int64_t devicesSize)
{
    if (devicesArray == nullptr && devicesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->InDevices(devicesArray, devicesSize);
    return 0;
}

int32_t FfiOHOSRelationalStoreInAllDevices(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->InAllDevices();
    return 0;
}

int32_t FfiOHOSRelationalStoreBeginWrap(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->BeginWrap();
    return 0;
}

int32_t FfiOHOSRelationalStoreEndWrap(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->EndWrap();
    return 0;
}

int32_t FfiOHOSRelationalStoreOr(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Or();
    return 0;
}

int32_t FfiOHOSRelationalStoreAnd(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->And();
    return 0;
}

int32_t FfiOHOSRelationalStoreContains(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Contains(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreBeginsWith(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->BeginsWith(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreEndsWith(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->EndsWith(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreIsNull(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->IsNull(field);
    return 0;
}

int32_t FfiOHOSRelationalStoreIsNotNull(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->IsNotNull(field);
    return 0;
}

int32_t FfiOHOSRelationalStoreLike(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Like(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreGlob(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Glob(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreOrderByAsc(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->OrderByAsc(field);
    return 0;
}

int32_t FfiOHOSRelationalStoreOrderByDesc(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->OrderByDesc(field);
    return 0;
}

int32_t FfiOHOSRelationalStoreDistinct(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Distinct();
    return 0;
}

int32_t FfiOHOSRelationalStoreLimitAs(int64_t id, int32_t value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LimitAs(value);
    return 0;
}

int32_t FfiOHOSRelationalStoreOffsetAs(int64_t id, int32_t rowOffset)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->OffsetAs(rowOffset);
    return 0;
}

int32_t FfiOHOSRelationalStoreGroupBy(int64_t id, const char **fieldsArray, int64_t fieldsSize)
{
    if (fieldsArray == nullptr && fieldsSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GroupBy(fieldsArray, fieldsSize);
    return 0;
}

int32_t FfiOHOSRelationalStoreIndexedBy(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->IndexedBy(field);
    return 0;
}

int32_t FfiOHOSRelationalStoreLessThanOrEqualTo(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LessThanOrEqualTo(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLessThanOrEqualToEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LessThanOrEqualToEx(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreEqualTo(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->EqualTo(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreEqualToEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->EqualToEx(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreGreaterThanOrEqualTo(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GreaterThanOrEqualTo(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGreaterThanOrEqualToEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GreaterThanOrEqualToEx(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreGreaterThan(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GreaterThan(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGreaterThanEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GreaterThanEx(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreNotBetween(int64_t id, const char *field, ValueType lowValue, ValueType highValue)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotBetween(field, lowValue, highValue);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotBetweenEx(int64_t id, const char *field, const ValueTypeEx *lowValue,
    const ValueTypeEx *highValue)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotBetweenEx(field, lowValue, highValue);
    return 0;
}

int32_t FfiOHOSRelationalStoreLessThan(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LessThan(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLessThanEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LessThanEx(field, value);
    return 0;
}

int32_t FfiOHOSRelationalStoreBetween(int64_t id, const char *field, ValueType lowValue, ValueType highValue)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Between(field, lowValue, highValue);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreBetweenEx(int64_t id, const char *field, const ValueTypeEx *lowValue,
    const ValueTypeEx *highValue)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->BetweenEx(field, lowValue, highValue);
    return 0;
}

int32_t FfiOHOSRelationalStoreIn(int64_t id, const char *field, ValueType *values, int64_t valuesSize)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->In(field, values, valuesSize);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreInEx(int64_t id, const char *field, ValueTypeEx *values, int64_t valuesSize)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->InEx(field, values, valuesSize);
    return 0;
}

int32_t FfiOHOSRelationalStoreNotIn(int64_t id, const char *field, ValueType *values, int64_t valuesSize)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotIn(field, values, valuesSize);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotInEx(int64_t id, const char *field, ValueTypeEx *values, int64_t valuesSize)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotInEx(field, values, valuesSize);
    return 0;
}

int32_t FfiOHOSRelationalStoreNotEqualTo(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotEqualTo(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotEqualToEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotEqualToEx(field, value);
    return 0;
}


int64_t FfiOHOSRelationalStoreQuery(
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

int64_t FfiOHOSRelationalStoreRemoteQuery(
    int64_t id, char *device, int64_t predicatesId, char **columns, int64_t columnsSize)
{
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

int64_t FfiOHOSRelationalStoreDelete(int64_t id, int64_t predicatesId, int32_t *errCode)
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

int32_t FfiOHOSRelationalStoreSetDistributedTables(int64_t id, char **tables, int64_t tablesSize)
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

int32_t FfiOHOSRelationalStoreSetDistributedTablesType(int64_t id, char **tables, int64_t tablesSize, int32_t type)
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

int32_t FfiOHOSRelationalStoreSetDistributedTablesConfig(
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

char *FfiOHOSRelationalStoreObtainDistributedTableName(int64_t id, const char *device, char *table)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return nullptr;
    }
    return nativeRdbStore->ObtainDistributedTableName(device, table);
}

int32_t FfiOHOSRelationalStoreBackUp(int64_t id, const char *destName)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Backup(destName);
}

int32_t FfiOHOSRelationalStoreReStore(int64_t id, const char *srcName)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Restore(srcName);
}

int32_t FfiOHOSRelationalStoreCommit(int64_t id)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Commit();
}

int32_t FfiOHOSRelationalStoreRollBack(int64_t id)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->RollBack();
}

int32_t FfiOHOSRelationalStoreBeginTransaction(int64_t id)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->BeginTransaction();
}

int64_t FfiOHOSRelationalStoreInsert(
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

int64_t FfiOHOSRelationalStoreUpdate(int64_t id, ValuesBucket valuesBucket, int64_t predicatesId,
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

void FfiOHOSRelationalStoreExecuteSql(int64_t id, const char *sql, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return;
    }
    nativeRdbStore->ExecuteSql(sql, errCode);
}

CArrSyncResult FfiOHOSRelationalStoreSync(int64_t id, int32_t mode, int64_t predicatesId, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativeRdbStore == nullptr || nativeRdbPredicates == nullptr) {
        *errCode = -1;
        return CArrSyncResult{ nullptr, nullptr, 0 };
    }
    return nativeRdbStore->Sync(mode, *nativeRdbPredicates);
}

CArrStr FfiOHOSRelationalStoreGetAllColumnNames(int64_t id)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        return CArrStr{ nullptr, 0 };
    }
    return nativeResultSet->GetAllColumnNames();
}

int32_t FfiOHOSRelationalStoreGetColumnCount(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetColumnCount();
}

int32_t FfiOHOSRelationalStoreGetRowCount(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetRowCount();
}

int32_t FfiOHOSRelationalStoreGetRowIndex(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeResultSet->GetRowIndex();
}

bool FfiOHOSRelationalStoreIsAtFirstRow(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsAtFirstRow();
}

bool FfiOHOSRelationalStoreIsAtLastRow(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsAtLastRow();
}

bool FfiOHOSRelationalStoreIsEnded(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsEnded();
}

bool FfiOHOSRelationalStoreIsStarted(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsStarted();
}

bool FfiOHOSRelationalStoreIsClosed(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return false;
    }
    *errCode = 0;
    return nativeResultSet->IsClosed();
}

double FfiOHOSRelationalStoreGetDouble(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return nativeResultSet->GetDouble(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreGoToRow(int64_t id, int32_t position, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToRow(position, rtnCode);
}

bool FfiOHOSRelationalStoreGoToPreviousRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToPreviousRow(rtnCode);
}

bool FfiOHOSRelationalStoreGoToLastRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToLastRow(rtnCode);
}

char *FfiOHOSRelationalStoreGetColumnName(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return nullptr;
    }
    return nativeResultSet->GetColumnName(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreIsColumnNull(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->IsColumnNull(columnIndex, rtnCode);
}

Asset FfiOHOSRelationalStoreGetAsset(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return Asset{ nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 0 };
    }
    return nativeResultSet->GetAsset(columnIndex, rtnCode);
}

int32_t FfiOHOSRelationalStoreClose(int64_t id)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        return -1;
    }
    return nativeResultSet->Close();
}

int32_t FfiOHOSRelationalStoreGetColumnIndex(int64_t id, char *columnName, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return nativeResultSet->GetColumnIndex(columnName, rtnCode);
}

char *FfiOHOSRelationalStoreGetString(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return nullptr;
    }
    return nativeResultSet->GetString(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreGoToFirstRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToFirstRow(rtnCode);
}

int64_t FfiOHOSRelationalStoreGetLong(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return -1;
    }
    return nativeResultSet->GetLong(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreGoToNextRow(int64_t id, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoToNextRow(rtnCode);
}

CArrUI8 FfiOHOSRelationalStoreGetBlob(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return CArrUI8{ nullptr, 0 };
    }
    return nativeResultSet->GetBlob(columnIndex, rtnCode);
}

bool FfiOHOSRelationalStoreGoTo(int64_t id, int32_t offset, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return false;
    }
    return nativeResultSet->GoTo(offset, rtnCode);
}

Assets FfiOHOSRelationalStoreGetAssets(int64_t id, int32_t columnIndex, int32_t *rtnCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *rtnCode = -1;
        return Assets{ nullptr, 0 };
    }
    return nativeResultSet->GetAssets(columnIndex, rtnCode);
}

ValuesBucket FfiOHOSRelationalStoreGetRow(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return ValuesBucket{ nullptr, nullptr, 0 };
    }
    return nativeResultSet->GetRow(errCode);
}

FFI_EXPORT ValuesBucketEx FfiOHOSRelationalStoreGetRowEx(int64_t id, int32_t *errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return ValuesBucketEx{ nullptr, nullptr, 0 };
    }
    return nativeResultSet->GetRowEx(errCode);
}

FFI_EXPORT ValueTypeEx FfiOHOSRelationalStoreResultSetGetValue(int64_t id, int32_t columnIndex, int32_t* errCode)
{
    auto nativeResultSet = FFIData::GetData<ResultSetImpl>(id);
    if (nativeResultSet == nullptr) {
        *errCode = -1;
        return ValueTypeEx{ 0 };
    }
    return nativeResultSet->GetValue(columnIndex, errCode);
}

int32_t FfiOHOSRelationalStoreCleanDirtyData(int64_t id, const char *tableName, uint64_t cursor)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->CleanDirtyData(tableName, cursor);
}

int32_t FfiOHOSRelationalStoreBatchInsert(
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

int64_t FfiOHOSRelationalStoreQuerySql(int64_t id, const char *sql, ValueType *bindArgs, int64_t size, int32_t *errCode)
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

void FfiOHOSRelationalStoreExecuteSqlBindArgs(
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

int32_t FfiOHOSRelationalStoreOn(
    int64_t id, const char *event, bool interProcess, int64_t callback, void (*callbackRef)())
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    auto onChange = [lambda = CJLambda::Create(callbackRef)]() -> void { lambda(); };
    return nativeRdbStore->RegisterObserver(event, interProcess, callback, onChange);
}

int32_t FfiOHOSRelationalStoreOnArrStr(int64_t id, int32_t subscribeType, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->RegisterObserverArrStr(subscribeType, callbackId);
}

int32_t FfiOHOSRelationalStoreOnChangeInfo(int64_t id, int32_t subscribeType, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->RegisterObserverChangeInfo(subscribeType, callbackId);
}

int32_t FfiOHOSRelationalStoreOnProgressDetails(int64_t id, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->RegisterObserverProgressDetails(callbackId);
}

int32_t FfiOHOSRelationalStoreOff(int64_t id, const char *event, bool interProcess, int64_t callback)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserver(event, interProcess, callback);
}

int32_t FfiOHOSRelationalStoreOffAll(int64_t id, const char *event, bool interProcess)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterAllObserver(event, interProcess);
}

int32_t FfiOHOSRelationalStoreOffArrStrChangeInfo(int64_t id, int32_t subscribeType, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserverArrStrChangeInfo(subscribeType, callbackId);
}

int32_t FfiOHOSRelationalStoreOffArrStrChangeInfoAll(int64_t id, int32_t subscribeType)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserverArrStrChangeInfoAll(subscribeType);
}

int32_t FfiOHOSRelationalStoreOffProgressDetails(int64_t id, int64_t callbackId)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserverProgressDetails(callbackId);
}

int32_t FfiOHOSRelationalStoreOffProgressDetailsAll(int64_t id)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->UnRegisterObserverProgressDetailsAll();
}

int32_t FfiOHOSRelationalStoreEmit(int64_t id, const char *event)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        return -1;
    }
    return nativeRdbStore->Emit(event);
}

int32_t FfiOHOSRelationalStoreCloudSync(int64_t id, int32_t mode, CArrStr tables, int64_t callbackId)
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

int32_t FfiOHOSRelationalStoreGetVersion(int64_t id, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->GetVersion(*errCode);
}

void FfiOHOSRelationalStoreSetVersion(int64_t id, int32_t value, int32_t *errCode)
{
    auto nativeRdbStore = FFIData::GetData<RdbStoreImpl>(id);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return;
    }
    nativeRdbStore->SetVersion(value, *errCode);
}

ModifyTime FfiOHOSRelationalStoreGetModifyTime(
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

FFI_EXPORT int32_t FfiOHOSRelationalStoreRdbPredicatesNotContains(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotContains(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreRdbPredicatesNotLike(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotLike(field, value);
    return 0;
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
}
} // namespace Relational
} // namespace OHOS
