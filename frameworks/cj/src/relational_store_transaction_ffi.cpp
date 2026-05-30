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

#include <cstdint>
#include <cstdlib>

#include "cj_lambda.h"
#include "napi_rdb_js_utils.h"
#include "rdb_errno.h"
#include "relational_store_impl_rdbpredicatesproxy.h"
#include "relational_store_impl_transaction.h"
#include "relational_store_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
extern "C" {
FFI_EXPORT int32_t FfiOHOSRelationalStoreTransactionCommit(int64_t id)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        return -1;
    }
    return nativeTransaction->Commit();
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreTransactionRollBack(int64_t id)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        return -1;
    }
    return nativeTransaction->RollBack();
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreTransactionInsert(int64_t id, const char *table,
    ValuesBucketEx values, int32_t conflict, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeTransaction->Insert(table, values, conflict, errCode);
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreTransactionBatchInsert(int64_t id, const char *table,
    ValuesBucketEx *values, int64_t size, int64_t *insertNum)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *insertNum = -1;
        return -1;
    }
    return nativeTransaction->BatchInsert(table, values, size, insertNum);
}

FFI_EXPORT ReturningResult FfiOHOSRelationalStoreTransactionBatchInsertWithReturning(int64_t id,
    const char *table, ValuesBucketEx *values, int64_t size, ReturningConfig config,
    int32_t conflict)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    return nativeTransaction->BatchInsertWithReturning(table, values, size, config, conflict);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreTransactionUpdate(int64_t id, ValuesBucketEx values,
    int64_t predicatesId, int32_t conflict, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        return -1;
    }
    auto nativePredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativePredicates == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeTransaction->Update(values, *nativePredicates, conflict, errCode);
}

FFI_EXPORT ReturningResult FfiOHOSRelationalStoreTransactionUpdateWithReturning(int64_t id,
    ValuesBucketEx values, int64_t predicatesId, int32_t conflict, ReturningConfig config, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    auto nativePredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativePredicates == nullptr) {
        *errCode = -1;
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    return nativeTransaction->UpdateWithReturning(values, *nativePredicates, conflict, config, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreTransactionDelete(int64_t id, int64_t predicatesId, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        return -1;
    }
    auto nativePredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativePredicates == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeTransaction->Delete(*nativePredicates, errCode);
}

FFI_EXPORT ReturningResult FfiOHOSRelationalStoreTransactionDeleteWithReturning(int64_t id,
    int64_t predicatesId, ReturningConfig config, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    auto nativePredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativePredicates == nullptr) {
        *errCode = -1;
        ReturningResult result = { 0, 0, -1 };
        return result;
    }
    return nativeTransaction->DeleteWithReturning(*nativePredicates, config, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreTransactionQuery(int64_t id, int64_t predicatesId,
    char **columns, int64_t columnsSize, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        return -1;
    }
    auto nativePredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativePredicates == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeTransaction->Query(*nativePredicates, columns, columnsSize, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreTransactionQuerySql(int64_t id, const char *sql,
    ValueTypeEx *bindArgs, int64_t size, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeTransaction->QuerySql(sql, bindArgs, size, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreTransactionQueryWithoutRowCount(int64_t id, int64_t predicatesId,
    char **columns, int64_t columnsSize, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        return -1;
    }
    auto nativePredicates = FFIData::GetData<RdbPredicatesImpl>(predicatesId);
    if (nativePredicates == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeTransaction->QueryWithoutRowCount(*nativePredicates, columns, columnsSize, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreTransactionQuerySqlWithoutRowCount(int64_t id, const char *sql,
    ValueTypeEx *bindArgs, int64_t size, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeTransaction->QuerySqlWithoutRowCount(sql, bindArgs, size, errCode);
}

FFI_EXPORT ValueTypeEx FfiOHOSRelationalStoreTransactionExecute(int64_t id, const char *sql,
    ValueTypeEx *args, int64_t size, int32_t *errCode)
{
    auto nativeTransaction = FFIData::GetData<TransactionImpl>(id);
    if (nativeTransaction == nullptr) {
        *errCode = -1;
        return ValueTypeEx{};
    }
    return nativeTransaction->Execute(sql, args, size, errCode);
}
}
} // namespace Relational
} // namespace OHOS