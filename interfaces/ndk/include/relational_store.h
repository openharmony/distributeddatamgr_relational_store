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
    RDB_S1 = 1,
    RDB_S2,
    RDB_S3,
    RDB_S4,
    RDB_LAST
};

enum OH_Rdb_Bool {
    RDB_FALSE,
    RDB_TRUE
};

typedef struct {
    const char *path;
    enum OH_Rdb_Bool isEncrypt;
    enum OH_Rdb_SecurityLevel securityLevel;
} OH_Rdb_Config;

typedef struct {
    int id;
} OH_Rdb_Store;

typedef struct {
    int (*OH_Callback_OnCreate)(OH_Rdb_Store *);
    int (*OH_Callback_OnUpgrade)(OH_Rdb_Store *, int, int);
    int (*OH_Callback_OnDowngrade)(OH_Rdb_Store *, int, int);
    int (*OH_Callback_OnOpen)(OH_Rdb_Store *);
    int (*OH_Callback_OnCorruption)(const char *);
} OH_Rdb_OpenCallback;

OH_Rdb_Store *OH_Rdb_GetOrOpen(OH_Rdb_Config const *config, int version, OH_Rdb_OpenCallback *openCallback, int *errCode);
int OH_Rdb_CloseStore(OH_Rdb_Store *store);
int OH_Rdb_ClearCache();
int OH_Rdb_DeleteStore(const char *path);

int OH_Rdb_Insert(OH_Rdb_Store *store, const char *table, OH_Rdb_ValuesBucket *valuesBucket);
int OH_Rdb_Update(OH_Rdb_Store *store, OH_Rdb_ValuesBucket *valuesBucket, OH_Predicates *predicates);
int OH_Rdb_Delete(OH_Rdb_Store *store, OH_Predicates *predicates);
OH_Cursor *OH_Rdb_Query(OH_Rdb_Store *store, OH_Predicates *predicates, const char *const *columnNames, int length);
int OH_Rdb_Execute(OH_Rdb_Store *store, const char *sql);
OH_Cursor *OH_Rdb_ExecuteQuery(OH_Rdb_Store *store, const char *sql);
int OH_Rdb_Transaction(OH_Rdb_Store *store);
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
