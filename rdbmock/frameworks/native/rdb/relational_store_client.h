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

#ifndef RELATIONAL_STORE_RELATIONAL_STORE_CLIENT_H
#define RELATIONAL_STORE_RELATIONAL_STORE_CLIENT_H

#include <map>
#include <memory>
#include <set>

#include "sqlite3sym.h"
#include "store_observer.h"

namespace DistributedDB {
enum DBStatus {
    DB_ERROR = -1,
    OK = 0,
    NOT_FOUND = 2,
    WAIT_COMPENSATED_SYNC = 57,
};
class RelationalStoreManager {
public:
    static std::string GetDistributedLogTableName(const std::string &tableName);
};
} // namespace DistributedDB

DistributedDB::DBStatus UnRegisterClientObserver(sqlite3 *db);

DistributedDB::DBStatus RegisterStoreObserver(
    sqlite3 *db, const std::shared_ptr<DistributedDB::StoreObserver> &storeObserver);

DistributedDB::DBStatus UnregisterStoreObserver(
    sqlite3 *db, const std::shared_ptr<DistributedDB::StoreObserver> &storeObserver);

DistributedDB::DBStatus UnregisterStoreObserver(sqlite3 *db);

DistributedDB::DBStatus Lock(
    const std::string &tableName, const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db);

DistributedDB::DBStatus UnLock(
    const std::string &tableName, const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db);
DistributedDB::DBStatus DropLogicDeletedData(sqlite3 *db, const std::string &tableName, uint64_t cursor);

void RegisterDbHook(sqlite3 *db);

void UnregisterDbHook(sqlite3 *db);

DistributedDB::DBStatus CreateDataChangeTempTrigger(sqlite3 *db);

namespace DistributedDB {
struct KnowledgeSourceSchema {
    std::string tableName;
    std::set<std::string> extendColNames;
    std::set<std::string> knowledgeColNames;
    std::map<std::string, std::set<std::string>> columnsToVerify;
};
}

DistributedDB::DBStatus SetKnowledgeSourceSchema(sqlite3 *db, const DistributedDB::KnowledgeSourceSchema &schema);

DistributedDB::DBStatus CleanDeletedData(sqlite3 *db, const std::string &tableName, uint64_t cursor);

void Clean(bool isOpenSslClean);

#endif //RELATIONAL_STORE_RELATIONAL_STORE_CLIENT_H
