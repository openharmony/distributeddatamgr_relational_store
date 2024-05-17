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

#include "mock.h"
#include "relational_store_client.h"

namespace OHOS {
__attribute__((visibility("default"))) bool PathToRealPath(const std::string &path, std::string &realPath)
{
    realPath = path;
    return true;
}

__attribute__((visibility("default"))) std::string ExtractFilePath(const std::string &fileFullName)
{
    return std::string(fileFullName).substr(0, fileFullName.rfind("/") + 1);
}

namespace NativeRdb {
struct SharedBlockInfo;
struct sqlite3_stmt;
__attribute__((visibility("default"))) int gettid()
{
    return 0;
}
#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("default"))) int FillSharedBlockOpt(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
    return 0;
}

__attribute__((visibility("default"))) int FillSharedBlock(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
    return 0;
}

__attribute__((visibility("default"))) bool ResetStatement(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
    return true;
}

#ifdef __cplusplus
}
#endif
}
}

using namespace DistributedDB;
__attribute__((visibility("default"))) DBStatus UnRegisterClientObserver(sqlite3 *db)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus RegisterStoreObserver(sqlite3 *db,
    const std::shared_ptr<StoreObserver> &storeObserver)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus UnregisterStoreObserver(sqlite3 *db,
    const std::shared_ptr<StoreObserver> &storeObserver)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus UnregisterStoreObserver(sqlite3 *db)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus Lock(const std::string &tableName,
    const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus UnLock(
    const std::string &tableName, const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus DropLogicDeletedData(sqlite3 *db, const std::string &tableName,
    uint64_t cursor)
{
    (void)db;
    (void)tableName;
    (void)cursor;
    return DBStatus::OK;
}

__attribute__((visibility("default"))) std::string DistributedDB::RelationalStoreManager::GetDistributedLogTableName(
    const std::string &tableName)
{
    return "";
}