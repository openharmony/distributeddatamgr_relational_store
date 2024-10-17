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
#ifndef NATIVE_RDB_TRANSACTIONIMPL_H
#define NATIVE_RDB_TRANSACTIONIMPL_H
#include <memory>
#include "transaction.h"

namespace OHOS {
namespace NativeRdb {
class TransactionImpl : public Transaction {
public:
    TransactionImpl() = default;
    ~TransactionImpl() = default;
    int32_t Begin() override;
    int32_t Commit() override;
    int32_t Rollback() override;
    int32_t Close() override;

    std::pair<int32_t, int64_t> Insert(const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) override;
    std::pair<int32_t, int64_t> BatchInsert(const std::string &table,
        const std::vector<ValuesBucket> &values) override;
    std::pair<int32_t, int64_t> Delete(const AbsRdbPredicates &values) override;
    std::pair<int32_t, int64_t> Update(const ValuesBucket &values, const AbsRdbPredicates &predicates,
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) override;
    std::shared_ptr<ResultSet> QuerySql(const std::string &sql, const std::vector<ValueObject> &args) override;
    std::pair<int32_t, ValueObject> Execute(const std::string &sql, const std::vector<ValueObject> &args) override;
};

} // namespace NativeRdb
} // namespace OHOS
#endif //NATIVE_RDB_TRANSACTIONIMPL_H
