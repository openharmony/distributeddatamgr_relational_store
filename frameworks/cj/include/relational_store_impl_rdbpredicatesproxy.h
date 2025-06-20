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

#ifndef RELATIONAL_STORE_IMPL_RDBPREDICATES_FFI_H
#define RELATIONAL_STORE_IMPL_RDBPREDICATES_FFI_H

#include <memory>
#include <string>

#include "ffi_remote_data.h"
#include "rdb_predicates.h"
#include "relational_store_utils.h"
#include "value_object.h"

namespace OHOS {
namespace Relational {
class RdbPredicatesImpl : public OHOS::FFI::FFIData {
public:
    OHOS::FFI::RuntimeType *GetRuntimeType() override
    {
        return GetClassType();
    }

    explicit RdbPredicatesImpl(const char *tableName);

    explicit RdbPredicatesImpl(std::shared_ptr<NativeRdb::RdbPredicates> predicates);

    void InDevices(const char **devicesArray, int64_t devicesSize);

    void InAllDevices();

    void BeginWrap();

    void EndWrap();

    void Or();

    void And();

    void Contains(const char *field, const char *value);

    void BeginsWith(const char *field, const char *value);

    void EndsWith(const char *field, const char *value);

    void IsNull(const char *field);

    void IsNotNull(const char *field);

    void Like(const char *field, const char *value);

    void Glob(const char *field, const char *value);

    void OrderByAsc(const char *field);

    void OrderByDesc(const char *field);

    void Distinct();

    void LimitAs(int32_t value);

    void OffsetAs(int32_t rowOffset);

    void GroupBy(const char **fieldsArray, int64_t fieldsSize);

    void IndexedBy(const char *field);

    void LessThanOrEqualTo(const char *field, ValueType value);

    void EqualTo(const char *field, ValueType value);

    void GreaterThanOrEqualTo(const char *field, ValueType value);

    void GreaterThan(const char *field, ValueType value);

    void NotBetween(const char *field, ValueType lowValue, ValueType highValue);

    void LessThan(const char *field, ValueType value);

    void Between(const char *field, ValueType lowValue, ValueType highValue);

    void In(const char *field, ValueType *values, int64_t valuesSize);

    void NotIn(const char *field, ValueType *values, int64_t valuesSize);

    void NotEqualTo(const char *field, ValueType value);

    void NotContains(const char* field, const char* value);

    void NotLike(const char* field, const char* value);

    std::shared_ptr<NativeRdb::RdbPredicates> GetPredicates();

    void LessThanOrEqualToEx(const char *field, const ValueTypeEx *value);

    void EqualToEx(const char *field, const ValueTypeEx *value);

    void GreaterThanOrEqualToEx(const char *field, const ValueTypeEx *value);

    void GreaterThanEx(const char *field, const ValueTypeEx *value);

    void NotBetweenEx(const char *field, const ValueTypeEx *lowValue, const ValueTypeEx *highValue);

    void LessThanEx(const char *field, const ValueTypeEx *value);

    void BetweenEx(const char *field, const ValueTypeEx *lowValue, const ValueTypeEx *highValue);

    void InEx(const char *field, ValueTypeEx *values, int64_t valuesSize);

    void NotInEx(const char *field, ValueTypeEx *values, int64_t valuesSize);

    void NotEqualToEx(const char *field, const ValueTypeEx *value);

private:
    std::shared_ptr<NativeRdb::RdbPredicates> predicates_;

    friend class OHOS::FFI::RuntimeType;

    friend class OHOS::FFI::TypeBase;

    static OHOS::FFI::RuntimeType *GetClassType();
};
} // namespace Relational
} // namespace OHOS

#endif