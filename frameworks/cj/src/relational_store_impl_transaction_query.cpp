/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "relational_store_impl_transaction.h"

#include "relational_store_impl_literesultset.h"
#include "relational_store_impl_resultsetproxy.h"
#include "relational_store_utils.h"
#include "values_bucket.h"
#include "values_buckets.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {

int64_t TransactionImpl::Update(ValuesBucketEx values, RdbPredicatesImpl &predicates,
    int32_t conflict, int32_t *errCode)
{
    if (transaction_ == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }

    NativeRdb::ValuesBucket bucket;
    for (int64_t i = 0; i < values.size; ++i) {
        NativeRdb::ValueObject valueObj = ValueTypeExToValueObject(values.value[i]);
        bucket.Put(values.key[i], std::move(valueObj));
    }

    auto conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflict);
    auto [code, updateRows] = transaction_->Update(bucket, *predicates.GetPredicates(), conflictResolution);
    *errCode = code;
    return updateRows;
}

ReturningResult TransactionImpl::UpdateWithReturning(ValuesBucketEx values, RdbPredicatesImpl &predicates,
    int32_t conflict, ReturningConfig config, int32_t *errCode)
{
    ReturningResult result = { 0, 0, NativeRdb::E_ERROR };
    if (transaction_ == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return result;
    }

    NativeRdb::ValuesBucket bucket;
    for (int64_t i = 0; i < values.size; ++i) {
        NativeRdb::ValueObject valueObj = ValueTypeExToValueObject(values.value[i]);
        bucket.Put(values.key[i], std::move(valueObj));
    }

    auto nativeConfig = CReturningConfigToNative(config);
    auto conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflict);
    auto [code, results] = transaction_->Update(bucket, *predicates.GetPredicates(), nativeConfig, conflictResolution);
    *errCode = code;

    if (code != NativeRdb::E_OK) {
        return result;
    }

    result.changed = results.changed;
    if (results.results != nullptr) {
        auto liteResultSet = FFIData::Create<LiteResultSetImpl>(results.results);
        if (liteResultSet != nullptr) {
            result.resultSetId = liteResultSet->GetID();
        }
    }
    result.errCode = NativeRdb::E_OK;
    return result;
}

int64_t TransactionImpl::Delete(RdbPredicatesImpl &predicates, int32_t *errCode)
{
    if (transaction_ == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }

    auto [code, deleteRows] = transaction_->Delete(*predicates.GetPredicates());
    *errCode = code;
    return deleteRows;
}

ReturningResult TransactionImpl::DeleteWithReturning(RdbPredicatesImpl &predicates, ReturningConfig config,
    int32_t *errCode)
{
    ReturningResult result = { 0, 0, NativeRdb::E_ERROR };
    if (transaction_ == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return result;
    }

    auto nativeConfig = CReturningConfigToNative(config);
    auto [code, results] = transaction_->Delete(*predicates.GetPredicates(), nativeConfig);
    *errCode = code;

    if (code != NativeRdb::E_OK) {
        return result;
    }

    result.changed = results.changed;
    if (results.results != nullptr) {
        auto liteResultSet = FFIData::Create<LiteResultSetImpl>(results.results);
        if (liteResultSet != nullptr) {
            result.resultSetId = liteResultSet->GetID();
        }
    }
    result.errCode = NativeRdb::E_OK;
    return result;
}

int64_t TransactionImpl::Query(RdbPredicatesImpl &predicates, char **columns, int64_t columnsSize, int32_t *errCode)
{
    if (transaction_ == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }

    std::vector<std::string> cols;
    if (columns != nullptr && columnsSize > 0) {
        cols.reserve(columnsSize);
        for (int64_t i = 0; i < columnsSize; ++i) {
            cols.push_back(columns[i]);
        }
    }

    auto resultSet = transaction_->QueryByStep(*predicates.GetPredicates(), cols);
    if (resultSet == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }

    auto resultSetProxy = FFIData::Create<ResultSetImpl>(resultSet);
    if (resultSetProxy == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    *errCode = NativeRdb::E_OK;
    return resultSetProxy->GetID();
}

int64_t TransactionImpl::QuerySql(const char *sql, ValueTypeEx *bindArgs, int64_t size, int32_t *errCode)
{
    if (transaction_ == nullptr || sql == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }

    std::vector<NativeRdb::ValueObject> args;
    if (bindArgs != nullptr && size > 0) {
        args.reserve(size);
        for (int64_t i = 0; i < size; ++i) {
            args.push_back(ValueTypeExToValueObject(bindArgs[i]));
        }
    }

    auto resultSet = transaction_->QueryByStep(sql, args);
    if (resultSet == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }

    auto resultSetProxy = FFIData::Create<ResultSetImpl>(resultSet);
    if (resultSetProxy == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    *errCode = NativeRdb::E_OK;
    return resultSetProxy->GetID();
}

int64_t TransactionImpl::QueryWithoutRowCount(RdbPredicatesImpl &predicates, char **columns,
    int64_t columnsSize, int32_t *errCode)
{
    if (transaction_ == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }

    std::vector<std::string> cols;
    if (columns != nullptr && columnsSize > 0) {
        cols.reserve(columnsSize);
        for (int64_t i = 0; i < columnsSize; ++i) {
            cols.push_back(columns[i]);
        }
    }

    DistributedRdb::QueryOptions options{.preCount = false, .isGotoNextRowReturnLastError = true};
    auto resultSet = transaction_->QueryByStep(*predicates.GetPredicates(), cols, options);
    if (resultSet == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }

    auto liteResultSet = FFIData::Create<LiteResultSetImpl>(resultSet);
    if (liteResultSet == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    *errCode = NativeRdb::E_OK;
    return liteResultSet->GetID();
}

int64_t TransactionImpl::QuerySqlWithoutRowCount(const char *sql, ValueTypeEx *bindArgs, int64_t size, int32_t *errCode)
{
    if (transaction_ == nullptr || sql == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }

    std::vector<NativeRdb::ValueObject> args;
    if (bindArgs != nullptr && size > 0) {
        args.reserve(size);
        for (int64_t i = 0; i < size; ++i) {
            args.push_back(ValueTypeExToValueObject(bindArgs[i]));
        }
    }

    DistributedRdb::QueryOptions options{.preCount = false, .isGotoNextRowReturnLastError = true};
    auto resultSet = transaction_->QueryByStep(sql, args, options);
    if (resultSet == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }

    auto liteResultSet = FFIData::Create<LiteResultSetImpl>(resultSet);
    if (liteResultSet == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    *errCode = NativeRdb::E_OK;
    return liteResultSet->GetID();
}

ValueTypeEx TransactionImpl::Execute(const char *sql, ValueTypeEx *args, int64_t size, int32_t *errCode)
{
    if (transaction_ == nullptr || sql == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return ValueTypeEx{};
    }

    std::vector<NativeRdb::ValueObject> bindArgs;
    if (args != nullptr && size > 0) {
        bindArgs.reserve(size);
        for (int64_t i = 0; i < size; ++i) {
            bindArgs.push_back(ValueTypeExToValueObject(args[i]));
        }
    }

    int32_t status = NativeRdb::E_ERROR;
    NativeRdb::ValueObject output;
    std::tie(status, output) = transaction_->Execute(sql, bindArgs);
    *errCode = status;

    if (status != NativeRdb::E_OK) {
        return ValueTypeEx{};
    }

    return ValueObjectToValueTypeEx(output);
}

} // namespace Relational
} // namespace OHOS