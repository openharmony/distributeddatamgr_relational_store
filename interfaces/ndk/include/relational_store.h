/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RELATIONAL_STORE_H
#define RELATIONAL_STORE_H

#include "relational_cursor.h"
#include "relational_predicates.h"
#include "relational_values_bucket.h"

#ifdef __cplusplus
extern "C" {
#endif

enum OH_Rdb_SecurityLevel {
    S1 = 1,
    S2,
    S3,
    S4
};

typedef struct {
    const char *path;
    BOOL isEncrypt;
    enum OH_Rdb_SecurityLevel securityLevel;
} OH_Rdb_Config;

typedef struct {
    int64_t id;
} OH_Rdb_Store;

OH_Rdb_Store *OH_Rdb_GetOrOpen(const OH_Rdb_Config *config, int *errCode);
int OH_Rdb_CloseStore(OH_Rdb_Store *store);
int OH_Rdb_DeleteStore(const char *path);

int OH_Rdb_Insert(OH_Rdb_Store *store, const char *table, OH_Rdb_VBucket *valuesBucket);
int OH_Rdb_Update(OH_Rdb_Store *store, OH_Rdb_VBucket *valuesBucket, OH_Predicates *predicates);
int OH_Rdb_Delete(OH_Rdb_Store *store, OH_Predicates *predicates);
OH_Cursor *OH_Rdb_Query(OH_Rdb_Store *store, OH_Predicates *predicates, const char *const *columnNames, int length);
int OH_Rdb_Execute(OH_Rdb_Store *store, const char *sql);
OH_Cursor *OH_Rdb_ExecuteQuery(OH_Rdb_Store *store, const char *sql);
int OH_Rdb_BeginTransaction(OH_Rdb_Store *store);
int OH_Rdb_RollBack(OH_Rdb_Store *store);
int OH_Rdb_Commit(OH_Rdb_Store *store);
int OH_Rdb_Backup(OH_Rdb_Store *store, const char *databasePath);
int OH_Rdb_Restore(OH_Rdb_Store *store, const char *databasePath);
int OH_Rdb_GetVersion(OH_Rdb_Store *store, int *version);
int OH_Rdb_SetVersion(OH_Rdb_Store *store, int version);

#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_STORE_H
