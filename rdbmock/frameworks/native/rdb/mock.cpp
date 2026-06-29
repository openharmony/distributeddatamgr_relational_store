/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "rdb_visibility.h"
#include "relational_store_client.h"
#include "relational_store_manager.h"

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

API_EXPORT DistributedDB::DBStatus ArchiveSyncedData(sqlite3 *db, const std::string &tableName, uint64_t cursor)
{
    (void)db;
    (void)tableName;
    (void)cursor;
    return DBStatus::OK;
}

API_EXPORT DistributedDB::DBStatus DeleteSyncedData(sqlite3 *db, const std::string &tableName,
    const std::vector<std::vector<DistributedDB::Type>> &keys)
{
    (void)db;
    (void)tableName;
    (void)keys;
    return DBStatus::OK;
}

API_EXPORT void Clean(bool isOpenSslClean)
{
    (void)isOpenSslClean;
    return;
}