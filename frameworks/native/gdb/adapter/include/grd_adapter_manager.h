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

#ifndef OHOS_DISTRIBUTED_DATA_OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRD_ADAPTER_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRD_ADAPTER_MANAGER_H

#include "grd_type_export.h"

namespace OHOS::DistributedDataAip {

typedef int32_t (*Open)(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db);
typedef int32_t (*Close)(GRD_DB *db, uint32_t flags);
typedef int32_t (*Repair)(const char *dbPath, const char *configStr);

typedef int32_t (*Prepare)(GRD_DB *db, const char *str, uint32_t strLen, GRD_StmtT **stmt, const char **unusedStr);
typedef int32_t (*Reset)(GRD_StmtT *stmt);
typedef int32_t (*Finalize)(GRD_StmtT *stmt);

typedef int32_t (*Step)(GRD_StmtT *stmt);
typedef uint32_t (*ColumnCount)(GRD_StmtT *stmt);
typedef GRD_DbDataTypeE (*GetColumnType)(GRD_StmtT *stmt, uint32_t idx);
typedef uint32_t (*ColumnBytes)(GRD_StmtT *stmt, uint32_t idx);
typedef char *(*ColumnName)(GRD_StmtT *stmt, uint32_t idx);
typedef GRD_DbValueT (*ColumnValue)(GRD_StmtT *stmt, uint32_t idx);
typedef int64_t (*ColumnInt64)(GRD_StmtT *stmt, uint32_t idx);
typedef int32_t (*ColumnInt)(GRD_StmtT *stmt, uint32_t idx);
typedef double (*ColumnDouble)(GRD_StmtT *stmt, uint32_t idx);
typedef const char *(*ColumnText)(GRD_StmtT *stmt, uint32_t idx);

typedef int32_t (*Backup)(GRD_DB *db, const char *backupDbFile, GRD_CipherInfoT *cipherInfo);
typedef int32_t (*Restore)(const char *dbFile, const char *backupDbFile, GRD_CipherInfoT *cipherInfo);
typedef int32_t (*Rekey)(const char *dbFile, const char *configStr, GRD_CipherInfoT *cipherInfo);

struct GrdAdapterHolder {
    Open Open = nullptr;
    Close Close = nullptr;
    Repair Repair = nullptr;

    Prepare Prepare = nullptr;
    Reset Reset = nullptr;
    Finalize Finalize = nullptr;
    Step Step = nullptr;
    ColumnCount ColumnCount = nullptr;
    GetColumnType GetColumnType = nullptr;
    ColumnBytes ColumnBytes = nullptr;
    ColumnName ColumnName = nullptr;
    ColumnValue ColumnValue = nullptr;
    ColumnInt64 ColumnInt64 = nullptr;
    ColumnInt ColumnInt = nullptr;
    ColumnDouble ColumnDouble = nullptr;
    ColumnText ColumnText = nullptr;

    Backup Backup = nullptr;
    Restore Restore = nullptr;
    Rekey Rekey = nullptr;
};

bool IsSupportArkDataDb();
GrdAdapterHolder GetAdapterHolder();

static void *g_library = nullptr;

} // namespace OHOS::DistributedDataAip

#endif // OHOS_DISTRIBUTED_DATA_OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRD_ADAPTER_MANAGER_H
