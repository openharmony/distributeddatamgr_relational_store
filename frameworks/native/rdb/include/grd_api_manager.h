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

#ifndef RDB_GRD_API_MANAGER_H
#define RDB_GRD_API_MANAGER_H

#include "grd_type_export.h"
#include "rdb_visibility.h"

namespace OHOS {
namespace NativeRdb {

typedef int32_t (*DBOpen)(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db);
typedef int32_t (*DBClose)(GRD_DB *db, uint32_t flags);
typedef int32_t (*DBRepair)(const char *dbPath, const char *configStr);

typedef int32_t (*DBSqlPrepare)(
    GRD_DB *db, const char *str, uint32_t strLen, GRD_SqlStmt **stmt, const char **unusedStr);
typedef int32_t (*DBSqlReset)(GRD_SqlStmt *stmt);
typedef int32_t (*DBSqlFinalize)(GRD_SqlStmt *stmt);
typedef int32_t (*DBSqlBindBlob)(
    GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *));
typedef int32_t (*DBSqlBindText)(
    GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *));
typedef int32_t (*DBSqlBindInt)(GRD_SqlStmt *stmt, uint32_t idx, int32_t val);
typedef int32_t (*DBSqlBindInt64)(GRD_SqlStmt *stmt, uint32_t idx, int64_t val);
typedef int32_t (*DBSqlBindDouble)(GRD_SqlStmt *stmt, uint32_t idx, double val);
typedef int32_t (*DBSqlBindNull)(GRD_SqlStmt *stmt, uint32_t idx);
typedef int32_t (*DBSqlBindFloatVector)(
    GRD_SqlStmt *stmt, uint32_t idx, const float *val, uint32_t dim, void (*freeFunc)(void *));

typedef int32_t (*DBSqlStep)(GRD_SqlStmt *stmt);
typedef uint32_t (*DBSqlColCnt)(GRD_SqlStmt *stmt);
typedef GRD_DbDataTypeE (*DBSqlColType)(GRD_SqlStmt *stmt, uint32_t idx);
typedef uint32_t (*DBSqlColBytes)(GRD_SqlStmt *stmt, uint32_t idx);
typedef char *(*DBSqlColName)(GRD_SqlStmt *stmt, uint32_t idx);
typedef GRD_DbValueT (*DBSqlColValue)(GRD_SqlStmt *stmt, uint32_t idx);
typedef const void *(*DBSqlColBlob)(GRD_SqlStmt *stmt, uint32_t idx);
typedef const char *(*DBSqlColText)(GRD_SqlStmt *stmt, uint32_t idx);
typedef int32_t (*DBSqlColInt)(GRD_SqlStmt *stmt, uint32_t idx);
typedef int64_t (*DBSqlColInt64)(GRD_SqlStmt *stmt, uint32_t idx);
typedef double (*DBSqlColDouble)(GRD_SqlStmt *stmt, uint32_t idx);
typedef const float *(*DBSqlColumnFloatVector)(GRD_SqlStmt *stmt, uint32_t idx, uint32_t *dim);
typedef int32_t (*DBBackup)(GRD_DB *db, const char *backupDbFile, GRD_CipherInfoT *cipherInfo);
typedef int32_t (*DBRestore)(const char *dbFile, const char *backupDbFile, GRD_CipherInfoT *cipherInfo);
typedef int32_t (*DBReKey)(const char *dbFile, const char *configStr, GRD_CipherInfoT *cipherInfo);
typedef GRD_DbValueT (*DBGetConfig)(GRD_DB *db, GRD_ConfigTypeE type);
typedef int32_t (*DBSetConfig)(GRD_DB *db, GRD_ConfigTypeE type, GRD_DbValueT value);

struct GRD_APIInfo {
    DBOpen DBOpenApi = nullptr;
    DBClose DBCloseApi = nullptr;
    DBRepair DBRepairApi = nullptr;
    DBSqlPrepare DBSqlPrepare = nullptr;
    DBSqlReset DBSqlReset = nullptr;
    DBSqlFinalize DBSqlFinalize = nullptr;
    DBSqlBindBlob DBSqlBindBlob = nullptr;
    DBSqlBindText DBSqlBindText = nullptr;
    DBSqlBindInt DBSqlBindInt = nullptr;
    DBSqlBindInt64 DBSqlBindInt64 = nullptr;
    DBSqlBindDouble DBSqlBindDouble = nullptr;
    DBSqlBindNull DBSqlBindNull = nullptr;
    DBSqlBindFloatVector DBSqlBindFloatVector = nullptr;
    DBSqlStep DBSqlStep = nullptr;
    DBSqlColCnt DBSqlColCnt = nullptr;
    DBSqlColType DBSqlColType = nullptr;
    DBSqlColBytes DBSqlColBytes = nullptr;
    DBSqlColName DBSqlColName = nullptr;
    DBSqlColValue DBSqlColValue = nullptr;
    DBSqlColBlob DBSqlColBlob = nullptr;
    DBSqlColText DBSqlColText = nullptr;
    DBSqlColInt DBSqlColInt = nullptr;
    DBSqlColInt64 DBSqlColInt64 = nullptr;
    DBSqlColDouble DBSqlColDouble = nullptr;
    DBSqlColumnFloatVector DBSqlColumnFloatVector = nullptr;
    DBBackup DBBackupApi = nullptr;
    DBRestore DBRestoreApi = nullptr;
    DBReKey DBReKeyApi = nullptr;
    DBGetConfig DBGetConfigApi = nullptr;
    DBSetConfig DBSetConfigApi = nullptr;
};

API_EXPORT bool IsUsingArkData();

GRD_APIInfo GetApiInfoInstance();

} // namespace NativeRdb
} // namespace OHOS

#endif // RDB_GRD_API_MANAGER_H
