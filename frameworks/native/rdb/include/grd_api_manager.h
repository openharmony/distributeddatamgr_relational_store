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

namespace OHOS {
namespace NativeRdb {

typedef int32_t (*DBOpen)(const char *dbPath, const char *configStr, uint32_t flags, GRD_DB **db);
typedef int32_t (*DBClose)(GRD_DB *db, uint32_t flags);

typedef int (*DBSqlPrepare)(GRD_DB *db, const char *str, uint32_t strLen, GRD_SqlStmt **stmt, const char **unusedStr);
typedef int (*DBSqlReset)(GRD_SqlStmt *stmt);
typedef int (*DBSqlFinalize)(GRD_SqlStmt *stmt);
typedef int (*DBSqlBindBlob)(GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *));
typedef int (*DBSqlBindText)(GRD_SqlStmt *stmt, uint32_t idx, const void *val, int32_t len, void (*freeFunc)(void *));
typedef int (*DBSqlBindInt)(GRD_SqlStmt *stmt, uint32_t idx, int32_t val);
typedef int (*DBSqlBindInt64)(GRD_SqlStmt *stmt, uint32_t idx, int64_t val);
typedef int (*DBSqlBindDouble)(GRD_SqlStmt *stmt, uint32_t idx, double val);
typedef int (*DBSqlBindNull)(GRD_SqlStmt *stmt, uint32_t idx);
typedef int (*DBSqlBindFloatVector)(
    GRD_SqlStmt *stmt, uint32_t idx, float *val, uint32_t dim, void (*freeFunc)(void *));

typedef int (*DBSqlStep)(GRD_SqlStmt *stmt);
typedef uint32_t (*DBSqlColCnt)(GRD_SqlStmt *stmt);
typedef GRD_DbDataTypeE (*DBSqlColType)(GRD_SqlStmt *stmt, uint32_t idx);
typedef int (*DBSqlColBytes)(GRD_SqlStmt *stmt, uint32_t idx);
typedef char *(*DBSqlColName)(GRD_SqlStmt *stmt, uint32_t idx);
typedef GRD_DbValueT (*DBSqlColValue)(GRD_SqlStmt *stmt, uint32_t idx);
typedef uint8_t *(*DBSqlColBlob)(GRD_SqlStmt *stmt, uint32_t idx);
typedef char *(*DBSqlColText)(GRD_SqlStmt *stmt, uint32_t idx);
typedef int (*DBSqlColInt)(GRD_SqlStmt *stmt, uint32_t idx);
typedef uint64_t (*DBSqlColInt64)(GRD_SqlStmt *stmt, uint32_t idx);
typedef double (*DBSqlColDouble)(GRD_SqlStmt *stmt, uint32_t idx);
typedef const float *(*DBSqlColumnFloatVector)(GRD_SqlStmt *stmt, uint32_t idx, uint32_t *dim);

struct GRD_APIInfo {
    DBOpen DBOpenApi = nullptr;
    DBClose DBCloseApi = nullptr;
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
};

GRD_APIInfo GetApiInfoInstance();

} // namespace NativeRdb
} // namespace OHOS

#endif // RDB_GRD_API_MANAGER_H
