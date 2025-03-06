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

#ifndef OHOS_DISTRIBUTED_DATA_NATIVE_GDB_DB_STORE_IMPL_H
#define OHOS_DISTRIBUTED_DATA_NATIVE_GDB_DB_STORE_IMPL_H

#include <mutex>
#include <variant>

#include "connection.h"
#include "connection_pool.h"
#include "gdb_store.h"
#include "gdb_store_config.h"
#include "gdb_transaction.h"

namespace OHOS::DistributedDataAip {
class DBStoreImpl final : public DBStore {
public:
    explicit DBStoreImpl(StoreConfig config);
    ~DBStoreImpl();
    std::pair<int32_t, std::shared_ptr<Result>> QueryGql(const std::string &gql) override;
    std::pair<int32_t, std::shared_ptr<Result>> ExecuteGql(const std::string &gql) override;
    std::pair<int32_t, std::shared_ptr<Transaction>> CreateTransaction() override;
    int32_t Close() override;
    int32_t InitConn();

private:
    std::shared_ptr<ConnectionPool> GetConnectionPool();
    void SetConnectionPool(std::shared_ptr<ConnectionPool> connectionPool);

    std::mutex mutex_;
    std::mutex transMutex_;
    StoreConfig config_;
    std::shared_ptr<ConnectionPool> connectionPool_ = nullptr;
    std::list<std::weak_ptr<Transaction>> transactions_;
};
} // namespace OHOS::DistributedDataAip
#endif
