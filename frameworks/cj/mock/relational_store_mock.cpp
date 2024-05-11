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
}