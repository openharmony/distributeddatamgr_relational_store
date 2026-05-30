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

OHOS::FFI::RuntimeType *TransactionImpl::GetClassType()
{
    static OHOS::FFI::RuntimeType runtimeType = OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("TransactionImpl");
    return &runtimeType;
}

TransactionImpl::TransactionImpl(std::shared_ptr<NativeRdb::Transaction> tx)
    : transaction_(tx)
{
}

int32_t TransactionImpl::Commit()
{
    if (transaction_ == nullptr) {
        return NativeRdb::E_ALREADY_CLOSED;
    }
    return transaction_->Commit();
}

int32_t TransactionImpl::RollBack()
{
    if (transaction_ == nullptr) {
        return NativeRdb::E_ALREADY_CLOSED;
    }
    return transaction_->Rollback();
}

int64_t TransactionImpl::Insert(const char *table, ValuesBucketEx values, int32_t conflict, int32_t *errCode)
{
    if (transaction_ == nullptr || table == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    if (!IsValidTableName(table)) {
        *errCode = NativeRdb::E_INVALID_ARGS_NEW;
        return -1;
    }

    NativeRdb::ValuesBucket bucket;
    for (int64_t i = 0; i < values.size; ++i) {
        NativeRdb::ValueObject valueObj = ValueTypeExToValueObject(values.value[i]);
        bucket.Put(values.key[i], std::move(valueObj));
    }

    auto conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflict);
    auto [code, insertRows] = transaction_->Insert(table, bucket, conflictResolution);
    *errCode = code;
    return insertRows;
}

int32_t TransactionImpl::BatchInsert(const char *table, ValuesBucketEx *values, int64_t size, int64_t *insertNum)
{
    if (transaction_ == nullptr || table == nullptr || values == nullptr) {
        *insertNum = -1;
        return NativeRdb::E_ERROR;
    }
    if (!IsValidTableName(table)) {
        *insertNum = -1;
        return NativeRdb::E_INVALID_ARGS_NEW;
    }

    NativeRdb::ValuesBuckets buckets;
    buckets.Reserve(size);
    for (int64_t i = 0; i < size; ++i) {
        NativeRdb::ValuesBucket bucket;
        for (int64_t j = 0; j < values[i].size; ++j) {
            NativeRdb::ValueObject valueObj = ValueTypeExToValueObject(values[i].value[j]);
            bucket.Put(values[i].key[j], std::move(valueObj));
        }
        buckets.Put(std::move(bucket));
    }

    auto [code, rows] = transaction_->BatchInsert(table, buckets);
    *insertNum = rows;
    return code;
}

ReturningResult TransactionImpl::BatchInsertWithReturning(const char *table, ValuesBucketEx *values,
    int64_t size, ReturningConfig config, int32_t conflict)
{
    ReturningResult result = { 0, 0, NativeRdb::E_ERROR };
    if (transaction_ == nullptr || table == nullptr || values == nullptr) {
        result.errCode = NativeRdb::E_ERROR;
        return result;
    }
    if (!IsValidTableName(table)) {
        result.errCode = NativeRdb::E_INVALID_ARGS_NEW;
        return result;
    }

    NativeRdb::ValuesBuckets buckets;
    buckets.Reserve(size);
    for (int64_t i = 0; i < size; ++i) {
        NativeRdb::ValuesBucket bucket;
        for (int64_t j = 0; j < values[i].size; ++j) {
            NativeRdb::ValueObject valueObj = ValueTypeExToValueObject(values[i].value[j]);
            bucket.Put(values[i].key[j], std::move(valueObj));
        }
        buckets.Put(std::move(bucket));
    }

    auto nativeConfig = CReturningConfigToNative(config);
    auto conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflict);
    auto [code, results] = transaction_->BatchInsert(table, buckets, nativeConfig, conflictResolution);
    result.errCode = code;

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

} // namespace Relational
} // namespace OHOS