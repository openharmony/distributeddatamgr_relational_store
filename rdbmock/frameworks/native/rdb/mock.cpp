/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "mock.h"

#include <cstring>

#include "hisysevent_c.h"
#include "rdb_file_system.h"
#include "rdb_visibility.h"
#include "relational_store_client.h"
#include "relational_store_manager.h"
#include "share_block.h"
#include "sqlite_errno.h"

int OH_HiSysEvent_Write(
    const char *domain, const char *name, HiSysEventEventType type, HiSysEventParam params[], size_t size)
{
    return 0;
}

namespace OHOS {
namespace NativeRdb {
API_EXPORT int gettid()
{
    return 0;
}
#ifdef __cplusplus
extern "C" {
#endif
API_EXPORT int FillSharedBlockOpt(SharedBlockInfo *info, sqlite3_stmt *stmt, int retryTime)
{
    return FillSharedBlock(info, stmt, retryTime);
}

static constexpr int RETRY_TIME = 50;
API_EXPORT int FillSharedBlock(SharedBlockInfo *info, sqlite3_stmt *stmt, int retryTime)
{
    (void) retryTime;
    int retryCount = 0;
    info->totalRows = info->addedRows = 0;
    bool isFull = false;
    bool hasException = false;
    while (!hasException && (!isFull || info->isCountAllRows)) {
        int err = sqlite3_step(stmt);
        if (err == SQLITE_ROW) {
            retryCount = 0;
            info->totalRows += 1;
            if (info->startPos >= info->totalRows || isFull) {
                continue;
            }
            info->isFull = true;
            isFull = info->isFull;
            hasException = info->hasException;
        } else if (err == SQLITE_DONE) {
            break;
        } else if (err == SQLITE_LOCKED || err == SQLITE_BUSY) {
            if (retryCount > RETRY_TIME) {
                hasException = true;
                return E_DATABASE_BUSY;
            } else {
                retryCount++;
            }
        } else {
            hasException = true;
            return SQLiteError::ErrNo(err);
        }
    }
    return E_OK;
}

API_EXPORT bool ResetStatement(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
    return true;
}
std::vector<std::string> RdbFileSystem::GetEntries(const std::string &path)
{
    return {};
}
std::pair<size_t, int32_t> RdbFileSystem::RemoveAll(const std::string &path, bool removeSelf)
{
    return std::make_pair(0, 0);
}

std::string RdbFileSystem::RealPath(const std::string &path)
{
    return "";
}

#ifdef __cplusplus
}
#endif
} // namespace NativeRdb
} // namespace OHOS

using namespace DistributedDB;
API_EXPORT DBStatus UnRegisterClientObserver(sqlite3 *db)
{
    (void)db;
    return DBStatus::OK;
}

API_EXPORT DBStatus RegisterStoreObserver(sqlite3 *db, const std::shared_ptr<StoreObserver> &storeObserver)
{
    (void)db;
    (void)storeObserver;
    return DBStatus::OK;
}

API_EXPORT DBStatus UnregisterStoreObserver(sqlite3 *db, const std::shared_ptr<StoreObserver> &storeObserver)
{
    (void)db;
    (void)storeObserver;
    return DBStatus::OK;
}

API_EXPORT DBStatus UnregisterStoreObserver(sqlite3 *db)
{
    (void)db;
    return DBStatus::OK;
}

API_EXPORT DBStatus Lock(const std::string &tableName, const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db)
{
    (void)tableName;
    (void)hashKey;
    (void)db;
    return DBStatus::OK;
}

API_EXPORT DBStatus UnLock(const std::string &tableName, const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db)
{
    (void)tableName;
    (void)hashKey;
    (void)db;
    return DBStatus::OK;
}

API_EXPORT DBStatus DropLogicDeletedData(sqlite3 *db, const std::string &tableName, uint64_t cursor)
{
    (void)db;
    (void)tableName;
    (void)cursor;
    return DBStatus::OK;
}

API_EXPORT void RegisterDbHook(sqlite3 *db)
{
    (void)db;
}

API_EXPORT void UnregisterDbHook(sqlite3 *db)
{
    (void)db;
}

API_EXPORT DBStatus CreateDataChangeTempTrigger(sqlite3 *db)
{
    (void)db;
    return DBStatus::OK;
}

API_EXPORT std::string DistributedDB::RelationalStoreManager::GetDistributedLogTableName(const std::string &tableName)
{
    (void)tableName;
    return "";
}

API_EXPORT std::vector<uint8_t> DistributedDB::RelationalStoreManager::CalcPrimaryKeyHash(
    const std::map<std::string, Type> &primaryKey, const std::map<std::string, CollateType> &collateTypeMap)
{
    (void)primaryKey;
    (void)collateTypeMap;
    return {};
}

API_EXPORT DistributedDB::DBStatus SetKnowledgeSourceSchema(
    sqlite3 *db, const DistributedDB::KnowledgeSourceSchema &schema)
{
    (void)db;
    (void)schema;
    return DBStatus::OK;
}

API_EXPORT DistributedDB::DBStatus CleanDeletedData(sqlite3 *db, const std::string &tableName, uint64_t cursor)
{
    (void)db;
    (void)tableName;
    (void)cursor;
    return DBStatus::OK;
}

API_EXPORT void Clean(bool isOpenSslClean)
{
    (void)isOpenSslClean;
    return;
}