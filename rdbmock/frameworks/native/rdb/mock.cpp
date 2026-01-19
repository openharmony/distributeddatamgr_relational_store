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

#include "relational_store_client.h"
#include "share_block.h"
#include "sqlite_errno.h"

constexpr int RETRY_TIME = 50;

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
__attribute__((visibility("default"))) int gettid()
{
    return 0;
}
#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("default"))) int FillSharedBlockOpt(SharedBlockInfo *info, sqlite3_stmt *stmt, int retryTime)
{
    return FillSharedBlock(info, stmt, retryTime);
}

__attribute__((visibility("default"))) int FillSharedBlock(SharedBlockInfo *info, sqlite3_stmt *stmt, int retryTime)
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

__attribute__((visibility("default"))) bool ResetStatement(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
    return true;
}

#ifdef __cplusplus
}
#endif
} // namespace NativeRdb
} // namespace OHOS

using namespace DistributedDB;
__attribute__((visibility("default"))) DBStatus UnRegisterClientObserver(sqlite3 *db)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus RegisterStoreObserver(
    sqlite3 *db, const std::shared_ptr<StoreObserver> &storeObserver)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus UnregisterStoreObserver(
    sqlite3 *db, const std::shared_ptr<StoreObserver> &storeObserver)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus UnregisterStoreObserver(sqlite3 *db)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus Lock(
    const std::string &tableName, const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus UnLock(
    const std::string &tableName, const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DBStatus DropLogicDeletedData(
    sqlite3 *db, const std::string &tableName, uint64_t cursor)
{
    (void)db;
    (void)tableName;
    (void)cursor;
    return DBStatus::OK;
}

__attribute__((visibility("default"))) void RegisterDbHook(sqlite3 *db)
{
    (void)db;
}

__attribute__((visibility("default"))) void UnregisterDbHook(sqlite3 *db)
{
    (void)db;
}

__attribute__((visibility("default"))) DBStatus CreateDataChangeTempTrigger(sqlite3 *db)
{
    (void)db;
    return DBStatus::OK;
}

__attribute__((visibility("default"))) std::string DistributedDB::RelationalStoreManager::GetDistributedLogTableName(
    const std::string &tableName)
{
    return "";
}

__attribute__((visibility("default"))) DistributedDB::DBStatus SetKnowledgeSourceSchema([[gnu::unused]] sqlite3 *db,
    [[gnu::unused]] const DistributedDB::KnowledgeSourceSchema &schema)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) DistributedDB::DBStatus CleanDeletedData([[gnu::unused]] sqlite3 *db,
    [[gnu::unused]] const std::string &tableName, [[gnu::unused]] uint64_t cursor)
{
    return DBStatus::OK;
}

__attribute__((visibility("default"))) void Clean([[gnu::unused]] bool isOpenSslClean)
{
    return;
}