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

#ifndef ARKDATA_INTELLIGENCE_PLATFORM_TRANS_DB_H
#define ARKDATA_INTELLIGENCE_PLATFORM_TRANS_DB_H
#include <memory>

#include "connection.h"
#include "gdb_store.h"
#include "graph_statement.h"
namespace OHOS::DistributedDataAip {
class TransDB : public DBStore {
public:
    TransDB(std::shared_ptr<Connection> connection);
    std::pair<int32_t, std::shared_ptr<Result>> QueryGql(const std::string &gql) override;
    std::pair<int32_t, std::shared_ptr<Result>> ExecuteGql(const std::string &gql) override;

    std::pair<int32_t, std::shared_ptr<Transaction>> CreateTransaction() override;
    int32_t Close() override;

private:
    std::pair<int32_t, std::shared_ptr<Statement>> GetStatement(const std::string &gql) const;

    std::weak_ptr<Connection> conn_;
};
} // namespace OHOS::DistributedDataAip
#endif // ARKDATA_INTELLIGENCE_PLATFORM_TRANS_DB_H