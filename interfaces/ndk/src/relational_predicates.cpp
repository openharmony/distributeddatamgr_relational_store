/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "RelationalPredicate"
#include "relational_predicates.h"

#include <variant>

#include "logger.h"
#include "oh_predicates.h"
#include "relational_predicates_objects.h"
#include "relational_store_error_code.h"
#include "sqlite_global_config.h"

using namespace OHOS::NativeRdb;
namespace OHOS {
namespace RdbNdk {
OH_Predicates *RelationalPredicate::EqualTo(OH_Predicates *predicates, const char *field, OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    if (!values.empty()) {
        self->predicates_.EqualTo(field, values[0]);
    }
    return self;
}

OH_Predicates *RelationalPredicate::NotEqualTo(OH_Predicates *predicates, const char *field,
    OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    if (!values.empty()) {
        self->predicates_.NotEqualTo(field, values[0]);
    }
    return self;
}

OH_Predicates *RelationalPredicate::BeginWrap(OH_Predicates *predicates)
{
    auto self = GetSelf(predicates);
    if (self == nullptr) {
        return self;
    }
    self->predicates_.BeginWrap();
    return self;
}

OH_Predicates *RelationalPredicate::EndWrap(OH_Predicates *predicates)
{
    auto self = GetSelf(predicates);
    if (self == nullptr) {
        return self;
    }
    self->predicates_.EndWrap();
    return self;
}

OH_Predicates *RelationalPredicate::Or(OH_Predicates *predicates)
{
    auto self = GetSelf(predicates);
    if (self == nullptr) {
        return self;
    }
    self->predicates_.Or();
    return self;
}

OH_Predicates *RelationalPredicate::And(OH_Predicates *predicates)
{
    auto self = GetSelf(predicates);
    if (self == nullptr) {
        return self;
    }
    self->predicates_.And();
    return self;
}

OH_Predicates *RelationalPredicate::IsNull(OH_Predicates *predicates, const char *field)
{
    auto self = GetSelf(predicates);
    if (self == nullptr || field == nullptr) {
        return self;
    }
    self->predicates_.IsNull(field);
    return self;
}

OH_Predicates *RelationalPredicate::IsNotNull(OH_Predicates *predicates, const char *field)
{
    auto self = GetSelf(predicates);
    if (self == nullptr || field == nullptr) {
        return self;
    }
    self->predicates_.IsNotNull(field);
    return self;
}

OH_Predicates *RelationalPredicate::Like(OH_Predicates *predicates, const char *field, OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    if (!values.empty()) {
        if (auto pval = std::get_if<std::string>(&values[0].value)) {
            self->predicates_.Like(field, std::move(*pval));
        }
    }
    return self;
}

OH_Predicates *RelationalPredicate::Between(OH_Predicates *predicates, const char *field, OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    // The number of arguments required for the between method is 2
    if (values.size() != 2) {
        LOG_ERROR("size is %{public}zu", values.size());
        return self;
    }

    self->predicates_.Between(field, values[0], values[1]);
    return self;
}

OH_Predicates *RelationalPredicate::NotBetween(OH_Predicates *predicates, const char *field,
    OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    // The number of arguments required for the between method is 2
    if (values.size() != 2) {
        LOG_ERROR("size is %{public}zu", values.size());
        return self;
    }
    self->predicates_.NotBetween(field, values[0], values[1]);
    return self;
}

OH_Predicates *RelationalPredicate::GreaterThan(OH_Predicates *predicates, const char *field,
    OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    if (!values.empty()) {
        self->predicates_.GreaterThan(field, values[0]);
    }
    return self;
}

OH_Predicates *RelationalPredicate::LessThan(OH_Predicates *predicates, const char *field,
    OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    if (!values.empty()) {
        self->predicates_.LessThan(field, values[0]);
    }
    return self;
}

OH_Predicates *RelationalPredicate::GreaterThanOrEqualTo(OH_Predicates *predicates, const char *field,
    OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    if (!values.empty()) {
        self->predicates_.GreaterThanOrEqualTo(field, values[0]);
    }
    return self;
}
OH_Predicates *RelationalPredicate::LessThanOrEqualTo(OH_Predicates *predicates, const char *field,
    OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    if (!values.empty()) {
        self->predicates_.LessThanOrEqualTo(field, values[0]);
    }
    return self;
}

OH_Predicates *RelationalPredicate::OrderBy(OH_Predicates *predicates, const char *field, OH_OrderType type)
{
    auto self = GetSelf(predicates);
    if (self == nullptr || field == nullptr) {
        return self;
    }
    if (type == OH_OrderType::DESC) {
        self->predicates_.OrderByDesc(field);
        return self;
    }
    self->predicates_.OrderByAsc(field);
    return self;
}

OH_Predicates *RelationalPredicate::Distinct(OH_Predicates *predicates)
{
    auto self = GetSelf(predicates);
    if (self == nullptr) {
        return self;
    }
    self->predicates_.Distinct();
    return self;
}

OH_Predicates *RelationalPredicate::Limit(OH_Predicates *predicates, unsigned int value)
{
    auto self = GetSelf(predicates);
    if (self == nullptr) {
        return self;
    }
    self->predicates_.Limit(value);
    return self;
}

OH_Predicates *RelationalPredicate::Offset(OH_Predicates *predicates, unsigned int rowOffset)
{
    auto self = GetSelf(predicates);
    if (self == nullptr) {
        return self;
    }
    self->predicates_.Offset(rowOffset);
    return self;
}

OH_Predicates *RelationalPredicate::GroupBy(OH_Predicates *predicates, char const *const *fields, int length)
{
    auto self = GetSelf(predicates);
    if (self == nullptr || fields == nullptr || length <= 0) {
        return self;
    }
    std::vector<std::string> vec;
    vec.reserve(length);
    for (int i = 0; i < length; i++) {
        vec.push_back(std::string(fields[i]));
    }
    self->predicates_.GroupBy(vec);
    return self;
}

OH_Predicates *RelationalPredicate::In(OH_Predicates *predicates, const char *field, OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    if (values.size() > OHOS::NativeRdb::GlobalExpr::SQLITE_MAX_COLUMN) {
        return self;
    }

    self->predicates_.In(field, values);
    return self;
}

OH_Predicates *RelationalPredicate::NotIn(OH_Predicates *predicates, const char *field, OH_VObject *valueObject)
{
    auto self = GetSelf(predicates);
    auto selfObjects = RelationalPredicatesObjects::GetSelf(valueObject);
    if (self == nullptr || selfObjects == nullptr || field == nullptr) {
        return self;
    }
    std::vector<ValueObject> values = selfObjects->Get();
    if (values.size() > OHOS::NativeRdb::GlobalExpr::SQLITE_MAX_COLUMN) {
        return self;
    }

    self->predicates_.NotIn(field, values);
    return self;
}

OH_Predicates *RelationalPredicate::Clear(OH_Predicates *predicates)
{
    auto self = GetSelf(predicates);
    if (self == nullptr) {
        return self;
    }
    self->predicates_.Clear();
    return self;
}

int RelationalPredicate::Destroy(OH_Predicates *predicates)
{
    auto self = GetSelf(predicates);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    delete self;
    return OH_Rdb_ErrCode::RDB_OK;
}

RelationalPredicate::RelationalPredicate(const char *table) : predicates_(table)
{
    id = RDB_PREDICATES_CID;
    equalTo = EqualTo;
    notEqualTo = NotEqualTo;
    beginWrap = BeginWrap;
    endWrap = EndWrap;
    orOperate = Or;
    andOperate = And;
    isNull = IsNull;
    isNotNull = IsNotNull;
    like = Like;
    between = Between;
    notBetween = NotBetween;
    greaterThan = GreaterThan;
    lessThan = LessThan;
    greaterThanOrEqualTo = GreaterThanOrEqualTo;
    lessThanOrEqualTo = LessThanOrEqualTo;
    orderBy = OrderBy;
    distinct = Distinct;
    limit = Limit;
    offset = Offset;
    groupBy = GroupBy;
    in = In;
    notIn = NotIn;
    clear = Clear;
    destroy = Destroy;
}

OHOS::NativeRdb::RdbPredicates &RelationalPredicate::Get()
{
    return predicates_;
}

RelationalPredicate* RelationalPredicate::GetSelf(OH_Predicates *predicates)
{
    if (predicates == nullptr || predicates->id != OHOS::RdbNdk::RDB_PREDICATES_CID) {
        LOG_ERROR("cursor invalid. is null %{public}d", (predicates == nullptr));
        return nullptr;
    }
    return static_cast<OHOS::RdbNdk::RelationalPredicate *>(predicates);
}
} // namespace RdbNdk
} // namespace OHOS