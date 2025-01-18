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
#ifndef ARKDATA_INTELLIGENCE_PLATFORM_TRANSACTION_IMPL_H
#define ARKDATA_INTELLIGENCE_PLATFORM_TRANSACTION_IMPL_H
 
#include <memory>
#include <mutex>
#include <vector>
 
#include "connection.h"
#include "gdb_store_config.h"
#include "result.h"
#include "transaction.h"
 
namespace OHOS::DistributedDataAip {
class DBStore;
class TransactionImpl : public Transaction {
public:
    TransactionImpl(std::shared_ptr<Connection> connection);
    ~TransactionImpl() override;
 
    int32_t Commit() override;
    int32_t Rollback() override;
    int32_t Close() override;
 
    std::pair<int32_t, std::shared_ptr<Result>> Query(const std::string &gql) override;
    std::pair<int32_t, std::shared_ptr<Result>> Execute(const std::string &gql) override;
 
    static std::pair<int32_t, std::shared_ptr<Transaction>> Create(std::shared_ptr<Connection> conn);
 
private:
    int32_t Start();
    int32_t CloseInner();
    std::shared_ptr<DBStore> GetStore();

    std::recursive_mutex mutex_;
    std::shared_ptr<DBStore> store_;
    std::shared_ptr<Connection> connection_;

    static const int32_t regCreator_;
};
} // namespace OHOS::DistributedDataAip
#endif
