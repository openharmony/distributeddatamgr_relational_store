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

#ifndef RELATIONAL_STORE_IMPL_TRANSACTION_FFI_H
#define RELATIONAL_STORE_IMPL_TRANSACTION_FFI_H

#include <memory>

#include "ffi_remote_data.h"
#include "relational_store_impl_rdbpredicatesproxy.h"
#include "relational_store_utils.h"
#include "transaction_impl.h"

namespace OHOS {
namespace Relational {

class TransactionImpl : public OHOS::FFI::FFIData {
public:
    OHOS::FFI::RuntimeType *GetRuntimeType() override
    {
        return GetClassType();
    }

    explicit TransactionImpl(std::shared_ptr<NativeRdb::Transaction> tx);

    int32_t Commit();
    int32_t RollBack();
    int64_t Insert(const char *table, ValuesBucketEx values, int32_t conflict, int32_t *errCode);
    int32_t BatchInsert(const char *table, ValuesBucketEx *values, int64_t size, int64_t *insertNum);
    ReturningResult BatchInsertWithReturning(const char *table, ValuesBucketEx *values,
        int64_t size, ReturningConfig config, int32_t conflict);
    int64_t Update(ValuesBucketEx values, RdbPredicatesImpl &predicates,
        int32_t conflict, int32_t *errCode);
    ReturningResult UpdateWithReturning(ValuesBucketEx values, RdbPredicatesImpl &predicates,
        int32_t conflict, ReturningConfig config, int32_t *errCode);
    int64_t Delete(RdbPredicatesImpl &predicates, int32_t *errCode);
    ReturningResult DeleteWithReturning(RdbPredicatesImpl &predicates, ReturningConfig config, int32_t *errCode);
    int64_t Query(RdbPredicatesImpl &predicates, char **columns, int64_t columnsSize, int32_t *errCode);
    int64_t QuerySql(const char *sql, ValueTypeEx *bindArgs, int64_t size, int32_t *errCode);
    int64_t QueryWithoutRowCount(RdbPredicatesImpl &predicates, char **columns, int64_t columnsSize, int32_t *errCode);
    int64_t QuerySqlWithoutRowCount(const char *sql, ValueTypeEx *bindArgs, int64_t size, int32_t *errCode);
    ValueTypeEx Execute(const char *sql, ValueTypeEx *args, int64_t size, int32_t *errCode);

private:
    friend class OHOS::FFI::RuntimeType;
    friend class OHOS::FFI::TypeBase;
    static OHOS::FFI::RuntimeType *GetClassType();

    std::shared_ptr<NativeRdb::Transaction> transaction_;
};
} // namespace Relational
} // namespace OHOS

#endif