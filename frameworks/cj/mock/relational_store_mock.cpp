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

#include "cj_common_ffi.h"

extern "C" {
FFI_EXPORT int FfiOHOSRelationalStoreGetRdbStore = 0;
FFI_EXPORT int FfiOHOSRelationalStoreDeleteRdbStore = 0;
FFI_EXPORT int FfiOHOSRelationalStoreDeleteRdbStoreConfig = 0;
FFI_EXPORT int FfiOHOSRelationalStoreRdbPredicatesConstructor = 0;
FFI_EXPORT int FfiOHOSRelationalStoreInDevices = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetAllColumnNames = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetColumnCount = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetRowCount = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetRowIndex = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIsAtFirstRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIsAtLastRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIsEnded = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIsStarted = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIsClosed = 0;
FFI_EXPORT int FfiOHOSRelationalStoreInAllDevices = 0;
FFI_EXPORT int FfiOHOSRelationalStoreBeginWrap = 0;
FFI_EXPORT int FfiOHOSRelationalStoreEndWrap = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOr = 0;
FFI_EXPORT int FfiOHOSRelationalStoreAnd = 0;
FFI_EXPORT int FfiOHOSRelationalStoreContains = 0;
FFI_EXPORT int FfiOHOSRelationalStoreBeginsWith = 0;
FFI_EXPORT int FfiOHOSRelationalStoreEndsWith = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIsNull = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIsNotNull = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLike = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGlob = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOrderByAsc = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOrderByDesc = 0;
FFI_EXPORT int FfiOHOSRelationalStoreDistinct = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLimitAs = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOffsetAs = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGroupBy = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIndexedBy = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLessThanOrEqualTo = 0;
FFI_EXPORT int FfiOHOSRelationalStoreEqualTo = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGreaterThanOrEqualTo = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGreaterThan = 0;
FFI_EXPORT int FfiOHOSRelationalStoreNotBetween = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLessThan = 0;
FFI_EXPORT int FfiOHOSRelationalStoreBetween = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIn = 0;
FFI_EXPORT int FfiOHOSRelationalStoreNotIn = 0;
FFI_EXPORT int FfiOHOSRelationalStoreNotEqualTo = 0;
FFI_EXPORT int FfiOHOSRelationalStoreQuery = 0;
FFI_EXPORT int FfiOHOSRelationalStoreRemoteQuery = 0;
FFI_EXPORT int FfiOHOSRelationalStoreUpdate = 0;
FFI_EXPORT int FfiOHOSRelationalStoreDelete = 0;
FFI_EXPORT int FfiOHOSRelationalStoreSetDistributedTables = 0;
FFI_EXPORT int FfiOHOSRelationalStoreSetDistributedTablesType = 0;
FFI_EXPORT int FfiOHOSRelationalStoreSetDistributedTablesConfig = 0;
FFI_EXPORT int FfiOHOSRelationalStoreObtainDistributedTableName = 0;
FFI_EXPORT int FfiOHOSRelationalStoreRollBack = 0;
FFI_EXPORT int FfiOHOSRelationalStoreCommit = 0;
FFI_EXPORT int FfiOHOSRelationalStoreBeginTransaction = 0;
FFI_EXPORT int FfiOHOSRelationalStoreBackUp = 0;
FFI_EXPORT int FfiOHOSRelationalStoreReStore = 0;
FFI_EXPORT int FfiOHOSRelationalStoreInsert = 0;
FFI_EXPORT int FfiOHOSRelationalStoreExecuteSql = 0;
FFI_EXPORT int FfiOHOSRelationalStoreSync = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetDouble = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGoToRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGoToPreviousRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGoToLastRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetColumnName = 0;
FFI_EXPORT int FfiOHOSRelationalStoreIsColumnNull = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetAsset = 0;
FFI_EXPORT int FfiOHOSRelationalStoreClose = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetColumnIndex = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetString = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGoToFirstRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetLong = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGoToNextRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetBlob = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGoTo = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetAssets = 0;
FFI_EXPORT int FfiOHOSRelationalStoreCleanDirtyData = 0;
FFI_EXPORT int FfiOHOSRelationalStoreBatchInsert = 0;
FFI_EXPORT int FfiOHOSRelationalStoreQuerySql = 0;
FFI_EXPORT int FfiOHOSRelationalStoreExecuteSqlBindArgs = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOn = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOff = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOffAll = 0;
FFI_EXPORT int FfiOHOSRelationalStoreEmit = 0;

FFI_EXPORT int FfiOHOSRelationalStoreGetRdbStoreEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreDeleteRdbStoreConfigEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreBatchInsertEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreInsertEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreUpdateEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreQuerySqlEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreExecuteSqlBindArgsEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetRowEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreEqualToEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreNotEqualToEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLessThanEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLessThanOrEqualToEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGreaterThanEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGreaterThanOrEqualToEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreBetweenEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreNotBetweenEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreInEx = 0;
FFI_EXPORT int FfiOHOSRelationalStoreNotInEx = 0;

FFI_EXPORT int FfiOHOSRelationalStoreBatchInsertWithConflictResolution = 0;
FFI_EXPORT int FfiOHOSRelationalStoreExecute = 0;
FFI_EXPORT int FfiOHOSRelationalStoreExecuteWithTxId = 0;
FFI_EXPORT int FfiOHOSRelationalStoreBeginTrans = 0;
FFI_EXPORT int FfiOHOSRelationalStoreRdbStoreClose = 0;
FFI_EXPORT int FfiOHOSRelationalStoreCommitWithTxId = 0;
FFI_EXPORT int FfiOHOSRelationalStoreSetDistributedTablesConfigExt = 0;
FFI_EXPORT int FfiOHOSRelationalStoreAttach = 0;
FFI_EXPORT int FfiOHOSRelationalStoreAttachConfig = 0;
FFI_EXPORT int FfiOHOSRelationalStoreDetach = 0;
FFI_EXPORT int FfiOHOSRelationalStoreRdbStoreGetRebuilt = 0;

FFI_EXPORT int FfiOHOSRelationalStoreOnArrStr = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOnChangeInfo = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOnProgressDetails = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOffArrStrChangeInfo = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOffArrStrChangeInfoAll = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOffProgressDetails = 0;
FFI_EXPORT int FfiOHOSRelationalStoreOffProgressDetailsAll = 0;
FFI_EXPORT int FfiOHOSRelationalStoreCloudSync = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetVersion = 0;
FFI_EXPORT int FfiOHOSRelationalStoreSetVersion = 0;
FFI_EXPORT int FfiOHOSRelationalStoreGetModifyTime = 0;

FFI_EXPORT int FfiOHOSRelationalStoreRdbPredicatesNotContains = 0;
FFI_EXPORT int FfiOHOSRelationalStoreRdbPredicatesNotLike = 0;

FFI_EXPORT int FfiOHOSRelationalStoreResultSetGetColumnNames = 0;
FFI_EXPORT int FfiOHOSRelationalStoreResultSetGetColumnTypeByName = 0;
FFI_EXPORT int FfiOHOSRelationalStoreResultSetGetColumnTypeById = 0;
FFI_EXPORT int FfiOHOSRelationalStoreResultSetGetColumnType = 0;
FFI_EXPORT int FfiOHOSRelationalStoreResultSetGetCurrentRowData = 0;
FFI_EXPORT int FfiOHOSRelationalStoreResultSetGetRowsData = 0;

FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetColumnIndex = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetColumnName = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetColumnTypeByName = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetColumnTypeById = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGoToNextRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetBlob = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetLong = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetAsset = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetAssets = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetValue = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetRow = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetIsColumnNull = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetRows = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetCurrentRowData = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetGetRowsData = 0;
FFI_EXPORT int FfiOHOSRelationalStoreLiteResultSetClose = 0;

FFI_EXPORT int FfiOHOSRelationalStoreBatchInsertWithReturning = 0;
FFI_EXPORT int FfiOHOSRelationalStoreUpdateWithReturning = 0;
FFI_EXPORT int FfiOHOSRelationalStoreDeleteWithReturning = 0;

FFI_EXPORT int FfiOHOSRelationalStoreCreateTransaction = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionCommit = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionRollBack = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionInsert = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionBatchInsert = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionBatchInsertWithReturning = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionUpdate = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionUpdateWithReturning = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionDelete = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionDeleteWithReturning = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionQuery = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionQuerySql = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionQueryWithoutRowCount = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionQuerySqlWithoutRowCount = 0;
FFI_EXPORT int FfiOHOSRelationalStoreTransactionExecute = 0;

FFI_EXPORT int FfiOHOSRelationalStoreQueryWithoutRowCount = 0;
FFI_EXPORT int FfiOHOSRelationalStoreQuerySqlWithoutRowCount = 0;
}