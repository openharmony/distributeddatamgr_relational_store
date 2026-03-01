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

#define LOG_TAG "RdbPredicatesImpl"
#include "ohos.data.relationalStore.impl.h"
#include "ohos.data.relationalStore.proj.hpp"
#include "rdb_predicates_impl.h"
#include "error_throw_utils.h"

namespace OHOS {
namespace RdbTaihe {

RdbPredicatesImpl::RdbPredicatesImpl()
{
}

RdbPredicatesImpl::RdbPredicatesImpl(const std::string &name)
{
    nativeRdbPredicates_ = std::make_shared<OHOS::NativeRdb::RdbPredicates>(name);
}

uintptr_t RdbPredicatesImpl::GetSpecificImplPtr()
{
    return reinterpret_cast<uintptr_t>(this);
}

void RdbPredicatesImpl::InnerInDevices(array_view<string> devices)
{
    std::vector<std::string> fields(devices.begin(), devices.end());
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->InDevices(fields);
    }
}

void RdbPredicatesImpl::InnerInAllDevices()
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->InAllDevices();
    }
}

void RdbPredicatesImpl::InnerEqualTo(string_view field, ValueType const &value)
{
    OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->EqualTo(std::string(field), valueObj);
    }
}

void RdbPredicatesImpl::InnerNotEqualTo(string_view field, ValueType const &value)
{
    OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->NotEqualTo(std::string(field), valueObj);
    }
}

void RdbPredicatesImpl::InnerBeginWrap()
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->BeginWrap();
    }
}

void RdbPredicatesImpl::InnerEndWrap()
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->EndWrap();
    }
}

void RdbPredicatesImpl::InnerOr()
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->Or();
    }
}

void RdbPredicatesImpl::InnerAnd()
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->And();
    }
}

void RdbPredicatesImpl::InnerContains(string_view field, string_view value)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->Contains(std::string(field), std::string(value));
    }
}

void RdbPredicatesImpl::InnerBeginsWith(string_view field, string_view value)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->BeginsWith(std::string(field), std::string(value));
    }
}

void RdbPredicatesImpl::InnerEndsWith(string_view field, string_view value)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->EndsWith(std::string(field), std::string(value));
    }
}

void RdbPredicatesImpl::InnerIsNull(string_view field)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->IsNull(std::string(field));
    }
}

void RdbPredicatesImpl::InnerIsNotNull(string_view field)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->IsNotNull(std::string(field));
    }
}

void RdbPredicatesImpl::InnerLike(string_view field, string_view value)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->Like(std::string(field), std::string(value));
    }
}

void RdbPredicatesImpl::InnerGlob(string_view field, string_view value)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->Glob(std::string(field), std::string(value));
    }
}

void RdbPredicatesImpl::InnerBetween(string_view field, ValueType const &low, ValueType const &high)
{
    OHOS::NativeRdb::ValueObject lowValueObj = ani_rdbutils::ValueTypeToNative(low);
    OHOS::NativeRdb::ValueObject highValueObj = ani_rdbutils::ValueTypeToNative(high);
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->Between(std::string(field), lowValueObj, highValueObj);
    }
}

void RdbPredicatesImpl::InnerNotBetween(string_view field, ValueType const &low, ValueType const &high)
{
    OHOS::NativeRdb::ValueObject lowValueObj = ani_rdbutils::ValueTypeToNative(low);
    OHOS::NativeRdb::ValueObject highValueObj = ani_rdbutils::ValueTypeToNative(high);
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->NotBetween(std::string(field), lowValueObj, highValueObj);
    }
}

void RdbPredicatesImpl::InnerGreaterThan(string_view field, ValueType const &value)
{
    OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->GreaterThan(std::string(field), valueObj);
    }
}

void RdbPredicatesImpl::InnerLessThan(string_view field, ValueType const &value)
{
    OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->LessThan(std::string(field), valueObj);
    }
}

void RdbPredicatesImpl::InnerGreaterThanOrEqualTo(string_view field, ValueType const &value)
{
    OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->GreaterThanOrEqualTo(std::string(field), valueObj);
    }
}

void RdbPredicatesImpl::InnerLessThanOrEqualTo(string_view field, ValueType const &value)
{
    OHOS::NativeRdb::ValueObject valueObj = ani_rdbutils::ValueTypeToNative(value);
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->LessThanOrEqualTo(std::string(field), valueObj);
    }
}

void RdbPredicatesImpl::InnerOrderByAsc(string_view field)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->OrderByAsc(std::string(field));
    }
}

void RdbPredicatesImpl::InnerOrderByDesc(string_view field)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->OrderByDesc(std::string(field));
    }
}

void RdbPredicatesImpl::InnerDistinct()
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->Distinct();
    }
}

void RdbPredicatesImpl::InnerLimitAs(int32_t value)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->Limit(value);
    }
}

void RdbPredicatesImpl::InnerOffsetAs(int32_t rowOffset)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->Offset(rowOffset);
    }
}

void RdbPredicatesImpl::InnerGroupBy(array_view<string> fields)
{
    std::vector<std::string> para(fields.begin(), fields.end());
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->GroupBy(para);
    }
}

void RdbPredicatesImpl::InnerIndexedBy(string_view field)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->IndexedBy(std::string(field));
    }
}

void RdbPredicatesImpl::InnerInValues(string_view field, array_view<ValueType> value)
{
    std::vector<OHOS::NativeRdb::ValueObject> para;
    std::transform(value.begin(), value.end(), std::back_inserter(para),
        [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->In(std::string(field), para);
    }
}

void RdbPredicatesImpl::InnerNotInValues(string_view field, array_view<ValueType> value)
{
    std::vector<OHOS::NativeRdb::ValueObject> para;
    std::transform(value.begin(), value.end(), std::back_inserter(para),
        [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->NotIn(std::string(field), para);
    }
}

void RdbPredicatesImpl::InnerNotContains(string_view field, string_view value)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->NotContains(std::string(field), std::string(value));
    }
}

void RdbPredicatesImpl::InnerNotLike(string_view field, string_view value)
{
    if (nativeRdbPredicates_ != nullptr) {
        nativeRdbPredicates_->NotLike(std::string(field), std::string(value));
    }
}

void RdbPredicatesImpl::InnerHaving(string_view conditions, optional_view<array<ValueType>> args)
{
    if (nativeRdbPredicates_ == nullptr) {
        ThrowError(std::make_shared<ParamError>("predicates", "null"));
        return;
    }
    if (conditions.empty()) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "conditions cannot be empty"));
        return;
    }
    std::vector<OHOS::NativeRdb::ValueObject> para;
    if (args.has_value()) {
        std::transform(args.value().begin(), args.value().end(), std::back_inserter(para),
            [](const ValueType &valueType) { return ani_rdbutils::ValueTypeToNative(valueType); });
    }
    if (nativeRdbPredicates_->GetGroup().empty()) {
        ThrowError(std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Missing GROUP BY clause."));
        return;
    }
    nativeRdbPredicates_->Having(std::string(conditions), para);
}

std::shared_ptr<OHOS::NativeRdb::RdbPredicates> RdbPredicatesImpl::GetNativePtr()
{
    return nativeRdbPredicates_;
}
}
}