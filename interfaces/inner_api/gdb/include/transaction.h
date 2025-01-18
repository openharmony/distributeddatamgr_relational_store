/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#ifndef ARKDATA_INTELLIGENCE_PLATFORM_TRANSACTION_H
#define ARKDATA_INTELLIGENCE_PLATFORM_TRANSACTION_H
 
#include <functional>
#include <tuple>
#include <utility>
#include <vector>
 
#include "gdb_store_config.h"
#include "result.h"
 
namespace OHOS::DistributedDataAip {
class Connection;
class Transaction {
public:
    using Creator = std::function<std::pair<int32_t, std::shared_ptr<Transaction>>(std::shared_ptr<Connection> conn)>;
 
    static std::pair<int32_t, std::shared_ptr<Transaction>> Create(std::shared_ptr<Connection> conn);
    static int32_t RegisterCreator(Creator creator);
 
    virtual ~Transaction() = default;
 
    virtual int32_t Commit() = 0;
    virtual int32_t Rollback() = 0;
    virtual int32_t Close() = 0;
 
    /**
     * @brief Queries data in the database based on GQL statement.
     *
     * @param gql Indicates the GQL statement to execute.
     */
    virtual std::pair<int32_t, std::shared_ptr<Result>> Query(const std::string &gql) = 0;
 
    /**
     * @brief Executes an GQL statement.
     *
     * @param gql Indicates the GQL statement to execute.
     */
    virtual std::pair<int32_t, std::shared_ptr<Result>> Execute(const std::string &gql) = 0;
 
private:
    static inline Creator creator_;
};
} // namespace OHOS::DistributedDataAip
#endif
