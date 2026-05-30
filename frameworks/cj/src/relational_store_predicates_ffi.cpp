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
#include "relational_store_utils.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
extern "C" {
FFI_EXPORT int64_t FfiOHOSRelationalStoreRdbPredicatesConstructor(const char *tableName)
{
    if (tableName == nullptr) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::Create<RdbPredicatesImpl>(tableName);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    return nativeRdbPredicates->GetID();
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreInDevices(int64_t id, const char **devicesArray, int64_t devicesSize)
{
    if (devicesArray == nullptr && devicesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->InDevices(devicesArray, devicesSize);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreInAllDevices(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->InAllDevices();
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreBeginWrap(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->BeginWrap();
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreEndWrap(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->EndWrap();
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOr(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Or();
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreAnd(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->And();
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreContains(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Contains(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreBeginsWith(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->BeginsWith(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreEndsWith(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->EndsWith(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreIsNull(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->IsNull(field);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreIsNotNull(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->IsNotNull(field);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLike(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Like(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGlob(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Glob(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOrderByAsc(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->OrderByAsc(field);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOrderByDesc(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->OrderByDesc(field);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreDistinct(int64_t id)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Distinct();
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLimitAs(int64_t id, int32_t value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LimitAs(value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreOffsetAs(int64_t id, int32_t rowOffset)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->OffsetAs(rowOffset);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGroupBy(int64_t id, const char **fieldsArray, int64_t fieldsSize)
{
    if (fieldsArray == nullptr && fieldsSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GroupBy(fieldsArray, fieldsSize);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreIndexedBy(int64_t id, const char *field)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->IndexedBy(field);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLessThanOrEqualTo(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LessThanOrEqualTo(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLessThanOrEqualToEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LessThanOrEqualToEx(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreEqualTo(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->EqualTo(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreEqualToEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->EqualToEx(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGreaterThanOrEqualTo(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GreaterThanOrEqualTo(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGreaterThanOrEqualToEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GreaterThanOrEqualToEx(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGreaterThan(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GreaterThan(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreGreaterThanEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->GreaterThanEx(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotBetween(
    int64_t id, const char *field, ValueType lowValue, ValueType highValue)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotBetween(field, lowValue, highValue);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotBetweenEx(int64_t id, const char *field, const ValueTypeEx *lowValue,
    const ValueTypeEx *highValue)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || lowValue == nullptr || highValue == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotBetweenEx(field, lowValue, highValue);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLessThan(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LessThan(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreLessThanEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->LessThanEx(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreBetween(int64_t id, const char *field, ValueType lowValue, ValueType highValue)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->Between(field, lowValue, highValue);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreBetweenEx(int64_t id, const char *field, const ValueTypeEx *lowValue,
    const ValueTypeEx *highValue)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || lowValue == nullptr || highValue == nullptr) {
        return -1;
    }
    nativeRdbPredicates->BetweenEx(field, lowValue, highValue);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreIn(int64_t id, const char *field, ValueType *values, int64_t valuesSize)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->In(field, values, valuesSize);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreInEx(int64_t id, const char *field, ValueTypeEx *values, int64_t valuesSize)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->InEx(field, values, valuesSize);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotIn(int64_t id, const char *field, ValueType *values, int64_t valuesSize)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotIn(field, values, valuesSize);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotInEx(int64_t id, const char *field, ValueTypeEx *values, int64_t valuesSize)
{
    if (values == nullptr && valuesSize != 0) {
        return -1;
    }
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotInEx(field, values, valuesSize);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotEqualTo(int64_t id, const char *field, ValueType value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotEqualTo(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreNotEqualToEx(int64_t id, const char *field, const ValueTypeEx *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotEqualToEx(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreRdbPredicatesNotContains(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotContains(field, value);
    return 0;
}

FFI_EXPORT int32_t FfiOHOSRelationalStoreRdbPredicatesNotLike(int64_t id, const char *field, const char *value)
{
    auto nativeRdbPredicates = FFIData::GetData<RdbPredicatesImpl>(id);
    if (nativeRdbPredicates == nullptr || field == nullptr || value == nullptr) {
        return -1;
    }
    nativeRdbPredicates->NotLike(field, value);
    return 0;
}
}
} // namespace Relational
} // namespace OHOS