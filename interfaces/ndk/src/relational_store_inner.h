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
#ifndef RELATIONAL_STORE_INNER_H
#define RELATIONAL_STORE_INNER_H

#include "relational_store.h"

#ifndef API_EXPORT
#define API_EXPORT __attribute__((visibility("default")))
#endif // API_EXPORT

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OH_Rdb_ConfigV2 OH_Rdb_ConfigV2;
API_EXPORT OH_Rdb_ConfigV2 *OH_Rdb_CreateConfig();
API_EXPORT int OH_Rdb_DestroyConfig(OH_Rdb_ConfigV2 *config);

API_EXPORT int OH_Rdb_SetDataBaseDir(OH_Rdb_ConfigV2 *config, const char *dataBaseDir);
API_EXPORT int OH_Rdb_SetStoreName(OH_Rdb_ConfigV2 *config, const char *storeName);
API_EXPORT int OH_Rdb_SetBundleName(OH_Rdb_ConfigV2 *config, const char *bundleName);
API_EXPORT int OH_Rdb_SetModuleName(OH_Rdb_ConfigV2 *config, const char *moduleName);
API_EXPORT int OH_Rdb_SetEncrypt(OH_Rdb_ConfigV2 *config, bool isEncrypt);
API_EXPORT int OH_Rdb_SetSecurityLevel(OH_Rdb_ConfigV2 *config, int securityLevel);
API_EXPORT int OH_Rdb_SetArea(OH_Rdb_ConfigV2 *config, int area);
API_EXPORT int OH_Rdb_SetDbType(OH_Rdb_ConfigV2 *config, int dbType);
API_EXPORT const int *OH_Rdb_GetSupportDBType(int *numType);

API_EXPORT OH_Rdb_Store *OH_Rdb_CreateOrOpen(const OH_Rdb_ConfigV2 *config, int *errCode);
API_EXPORT int OH_Rdb_DeleteStoreV2(const OH_Rdb_ConfigV2 *config);

API_EXPORT int OH_Rdb_ExecuteByTrxId(OH_Rdb_Store *store, int64_t trxId, const char *sql);
API_EXPORT int OH_Rdb_BeginTransWithTrxId(OH_Rdb_Store *store, int64_t *trxId);
API_EXPORT int OH_Rdb_RollBackByTrxId(OH_Rdb_Store *store, int64_t trxId);
API_EXPORT int OH_Rdb_CommitByTrxId(OH_Rdb_Store *store, int64_t trxId);

#ifdef __cplusplus
}
#endif

#endif // RELATIONAL_STORE_INNER_H
