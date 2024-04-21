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
namespace NativeRdb {
__attribute__((visibility("default"))) int gettid()
{
    return 0;
}

DistributedDB::DBStatus UnRegisterClientObserver(sqlite3 *db)
{
    return DistributedDB::DBStatus::OK;
}

DistributedDB::DBStatus RegisterStoreObserver(sqlite3 *db,
    const std::shared_ptr<DistributedDB::StoreObserver> &storeObserver)
{
    return DistributedDB::DBStatus::OK;
}

DistributedDB::DBStatus UnregisterStoreObserver(sqlite3 *db,
    const std::shared_ptr<DistributedDB::StoreObserver> &storeObserver)
{
    return DistributedDB::DBStatus::OK;
}

DistributedDB::DBStatus UnregisterStoreObserver(sqlite3 *db)
{
    return DistributedDB::DBStatus::OK;
}

DistributedDB::DBStatus Lock(
    const std::string &tableName, const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db)
{
    return DistributedDB::DBStatus::OK;
}

DistributedDB::DBStatus UnLock(
    const std::string &tableName, const std::vector<std::vector<uint8_t>> &hashKey, sqlite3 *db)
{
    return DistributedDB::DBStatus::OK;
}
}
}