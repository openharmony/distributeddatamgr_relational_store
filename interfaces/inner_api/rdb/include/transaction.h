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
#ifndef NATIVE_RDB_TRANSACTION_H
#define NATIVE_RDB_TRANSACTION_H
#include "rdb_common.h"
#include "rdb_predicates.h"
#include "rdb_visibility.h"
#include "result_set.h"
#include "values_bucket.h"
namespace OHOS {
namespace NativeRdb {
enum TransactionType { DEFERRED, IMMEDIATE, EXCLUSIVE };
class API_EXPORT Transaction {
public:
    virtual ~Transaction() = default;
    virtual int32_t Begin() = 0;
    virtual int32_t Commit() = 0;
    virtual int32_t Rollback() = 0;
    virtual int32_t Close() = 0;
    virtual std::pair<int32_t, int64_t> Insert(const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) = 0;
    virtual std::pair<int32_t, int64_t> BatchInsert(
        const std::string &table, const std::vector<ValuesBucket> &values) = 0;
    virtual std::pair<int32_t, int64_t> Delete(const AbsRdbPredicates &values) = 0;
    virtual std::pair<int32_t, int64_t> Update(const ValuesBucket &values, const AbsRdbPredicates &predicates,
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) = 0;

    virtual std::shared_ptr<ResultSet> QuerySql(const std::string &sql, const std::vector<ValueObject> &args = {}) = 0;
    virtual std::pair<int32_t, ValueObject> Execute(
        const std::string &sql, const std::vector<ValueObject> &args = {}) = 0;

    //    virtual std::pair<int32_t, int64_t> Insert(const std::string &table, const ValuesBucket &values) = 0;
};

} // namespace NativeRdb
} // namespace OHOS
#endif //LDBPROJ_TRANSACTION_H
