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

#ifndef RELATIONAL_STORE_FFI_H
#define RELATIONAL_STORE_FFI_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "ffi_remote_data.h"
#include "js_ability.h"
#include "logger.h"
#include "napi_base_context.h"
#include "native_log.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"
#include "relational_store_impl_rdbpredicatesproxy.h"
#include "relational_store_impl_rdbstore.h"
#include "relational_store_impl_resultsetproxy.h"
#include "relational_store_utils.h"
#include "unistd.h"

namespace OHOS {
namespace Relational {
extern "C" {
FFI_EXPORT int64_t FfiOHOSRelationalStoreGetRdbStore(
    OHOS::AbilityRuntime::Context *context, StoreConfig config, int32_t *errCode);

FFI_EXPORT void FfiOHOSRelationalStoreDeleteRdbStore(
    OHOS::AbilityRuntime::Context *context, const char *name, int32_t *errCode);

FFI_EXPORT void FfiOHOSRelationalStoreDeleteRdbStoreConfig(
    OHOS::AbilityRuntime::Context *context, StoreConfig config, int32_t *errCode);

FFI_EXPORT int64_t FfiOHOSRelationalStoreRdbPredicatesConstructor(const char *tableName);

FFI_EXPORT int32_t FfiOHOSRelationalStoreInDevices(int64_t id, const char **devicesArray, int64_t devicesSize);

FFI_EXPORT CArrStr FfiOHOSRelationalStoreGetAllColumnNames(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetColumnCount(int64_t id, int32_t *errCode);

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetRowCount(int64_t id, int32_t *errCode);

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetRowIndex(int64_t id, int32_t *errCode);

FFI_EXPORT bool FfiOHOSRelationalStoreIsAtFirstRow(int64_t id, int32_t *errCode);

FFI_EXPORT bool FfiOHOSRelationalStoreIsAtLastRow(int64_t id, int32_t *errCode);

FFI_EXPORT bool FfiOHOSRelationalStoreIsEnded(int64_t id, int32_t *errCode);

FFI_EXPORT bool FfiOHOSRelationalStoreIsStarted(int64_t id, int32_t *errCode);

FFI_EXPORT bool FfiOHOSRelationalStoreIsClosed(int64_t id, int32_t *errCode);

FFI_EXPORT int32_t FfiOHOSRelationalStoreInAllDevices(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreBeginWrap(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreEndWrap(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOr(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreAnd(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreContains(int64_t id, const char *field, const char *value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreBeginsWith(int64_t id, const char *field, const char *value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreEndsWith(int64_t id, const char *field, const char *value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreIsNull(int64_t id, const char *field);

FFI_EXPORT int32_t FfiOHOSRelationalStoreIsNotNull(int64_t id, const char *field);

FFI_EXPORT int32_t FfiOHOSRelationalStoreLike(int64_t id, const char *field, const char *value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreGlob(int64_t id, const char *field, const char *value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOrderByAsc(int64_t id, const char *field);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOrderByDesc(int64_t id, const char *field);

FFI_EXPORT int32_t FfiOHOSRelationalStoreDistinct(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreLimitAs(int64_t id, int32_t value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffsetAs(int64_t id, int32_t rowOffset);

FFI_EXPORT int32_t FfiOHOSRelationalStoreGroupBy(int64_t id, const char **fieldsArray, int64_t fieldsSize);

FFI_EXPORT int32_t FfiOHOSRelationalStoreIndexedBy(int64_t id, const char *field);

FFI_EXPORT int32_t FfiOHOSRelationalStoreLessThanOrEqualTo(int64_t id, const char *field, ValueType value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreEqualTo(int64_t id, const char *field, ValueType value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreGreaterThanOrEqualTo(int64_t id, const char *field, ValueType value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreGreaterThan(int64_t id, const char *field, ValueType value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotBetween(
    int64_t id, const char *field, ValueType lowValue, ValueType highValue);

FFI_EXPORT int32_t FfiOHOSRelationalStoreLessThan(int64_t id, const char *field, ValueType value);

FFI_EXPORT int32_t FfiOHOSRelationalStoreBetween(
    int64_t id, const char *field, ValueType lowValue, ValueType highValue);

FFI_EXPORT int32_t FfiOHOSRelationalStoreIn(int64_t id, const char *field, ValueType *values, int64_t valuesSize);

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotIn(int64_t id, const char *field, ValueType *values, int64_t valuesSize);

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotEqualTo(int64_t id, const char *field, ValueType value);

FFI_EXPORT int64_t FfiOHOSRelationalStoreQuery(
    int64_t id, int64_t predicatesId, char **columns, int64_t columnsSize, int32_t *errCode);

FFI_EXPORT int64_t FfiOHOSRelationalStoreRemoteQuery(
    int64_t id, char *device, int64_t predicatesId, char **columns, int64_t columnsSize);

FFI_EXPORT int64_t FfiOHOSRelationalStoreUpdate(int64_t id, ValuesBucket valuesBucket, int64_t predicatesId,
    NativeRdb::ConflictResolution conflictResolution, int32_t *errCode);

FFI_EXPORT int64_t FfiOHOSRelationalStoreDelete(int64_t id, int64_t predicatesId, int32_t *errCode);

FFI_EXPORT int32_t FfiOHOSRelationalStoreSetDistributedTables(int64_t id, char **tables, int64_t tablesSize);

FFI_EXPORT int32_t FfiOHOSRelationalStoreSetDistributedTablesType(
    int64_t id, char **tables, int64_t tablesSize, int32_t type);

FFI_EXPORT int32_t FfiOHOSRelationalStoreSetDistributedTablesConfig(
    int64_t id, char **tables, int64_t tablesSize, int32_t type, RetDistributedConfig distributedConfig);

FFI_EXPORT char *FfiOHOSRelationalStoreObtainDistributedTableName(int64_t id, const char *device, char *table);

FFI_EXPORT int32_t FfiOHOSRelationalStoreRollBack(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreCommit(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreBeginTransaction(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreBackUp(int64_t id, const char *destName);

FFI_EXPORT int32_t FfiOHOSRelationalStoreReStore(int64_t id, const char *srcName);

FFI_EXPORT int64_t FfiOHOSRelationalStoreInsert(
    int64_t id, const char *table, ValuesBucket valuesBucket, int32_t conflict, int32_t *errCode);

FFI_EXPORT void FfiOHOSRelationalStoreExecuteSql(int64_t id, const char *sql, int32_t *errCode);

FFI_EXPORT CArrSyncResult FfiOHOSRelationalStoreSync(int64_t id, int32_t mode, int64_t predicatesId, int32_t *errCode);

FFI_EXPORT double FfiOHOSRelationalStoreGetDouble(int64_t id, int32_t columnIndex, int32_t *rtnCode);

FFI_EXPORT bool FfiOHOSRelationalStoreGoToRow(int64_t id, int32_t position, int32_t *rtnCode);

FFI_EXPORT bool FfiOHOSRelationalStoreGoToPreviousRow(int64_t id, int32_t *rtnCode);

FFI_EXPORT bool FfiOHOSRelationalStoreGoToLastRow(int64_t id, int32_t *rtnCode);

FFI_EXPORT char *FfiOHOSRelationalStoreGetColumnName(int64_t id, int32_t columnIndex, int32_t *rtnCode);

FFI_EXPORT bool FfiOHOSRelationalStoreIsColumnNull(int64_t id, int32_t columnIndex, int32_t *rtnCode);

FFI_EXPORT Asset FfiOHOSRelationalStoreGetAsset(int64_t id, int32_t columnIndex, int32_t *rtnCode);

FFI_EXPORT int32_t FfiOHOSRelationalStoreClose(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetColumnIndex(int64_t id, char *columnName, int32_t *rtnCode);

FFI_EXPORT char *FfiOHOSRelationalStoreGetString(int64_t id, int32_t columnIndex, int32_t *rtnCode);

FFI_EXPORT bool FfiOHOSRelationalStoreGoToFirstRow(int64_t id, int32_t *rtnCode);

FFI_EXPORT int64_t FfiOHOSRelationalStoreGetLong(int64_t id, int32_t columnIndex, int32_t *rtnCode);

FFI_EXPORT bool FfiOHOSRelationalStoreGoToNextRow(int64_t id, int32_t *rtnCode);

FFI_EXPORT CArrUI8 FfiOHOSRelationalStoreGetBlob(int64_t id, int32_t columnIndex, int32_t *rtnCode);

FFI_EXPORT bool FfiOHOSRelationalStoreGoTo(int64_t id, int32_t offset, int32_t *rtnCode);

FFI_EXPORT Assets FfiOHOSRelationalStoreGetAssets(int64_t id, int32_t columnIndex, int32_t *rtnCode);

FFI_EXPORT int32_t FfiOHOSRelationalStoreCleanDirtyData(int64_t id, const char *tableName, uint64_t cursor);

FFI_EXPORT int32_t FfiOHOSRelationalStoreBatchInsert(
    int64_t id, const char *tableName, ValuesBucket *values, int64_t valuesSize, int64_t *insertNum);

FFI_EXPORT int64_t FfiOHOSRelationalStoreQuerySql(
    int64_t id, const char *sql, ValueType *bindArgs, int64_t size, int32_t *errCode);

FFI_EXPORT void FfiOHOSRelationalStoreExecuteSqlBindArgs(
    int64_t id, char *sql, ValueType *bindArgs, int64_t bindArgsSize, int32_t *errCode);

FFI_EXPORT ValuesBucket FfiOHOSRelationalStoreGetRow(int64_t id, int32_t *errCode);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOn(
    int64_t id, const char *event, bool interProcess, int64_t callback, void (*callbackRef)());

FFI_EXPORT int32_t FfiOHOSRelationalStoreOnArrStr(int64_t id, int32_t subscribeType, int64_t callbackId);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOnChangeInfo(int64_t id, int32_t subscribeType, int64_t callbackId);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOnProgressDetails(int64_t id, int64_t callbackId);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOff(int64_t id, const char *event, bool interProcess, int64_t callback);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffAll(int64_t id, const char *event, bool interProcess);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffArrStrChangeInfo(int64_t id, int32_t subscribeType, int64_t callbackId);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffArrStrChangeInfoAll(int64_t id, int32_t subscribeType);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffProgressDetails(int64_t id, int64_t callbackId);

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffProgressDetailsAll(int64_t id);

FFI_EXPORT int32_t FfiOHOSRelationalStoreEmit(int64_t id, const char *event);

FFI_EXPORT int32_t FfiOHOSRelationalStoreCloudSync(int64_t id, int32_t mode, CArrStr tables, int64_t callbackId);

FFI_EXPORT int32_t FfiOHOSRelationalStoreGetVersion(int64_t id, int32_t *errCode);

FFI_EXPORT void FfiOHOSRelationalStoreSetVersion(int64_t id, int32_t value, int32_t *errCode);

FFI_EXPORT ModifyTime FfiOHOSRelationalStoreGetModifyTime(
    int64_t id, char *cTable, char *cColumnName, CArrPRIKeyType cPrimaryKeys, int32_t *errCode);
}
} // namespace Relational
} // namespace OHOS

#endif