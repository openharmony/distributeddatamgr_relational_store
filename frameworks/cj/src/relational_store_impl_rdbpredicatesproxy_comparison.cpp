/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "relational_store_impl_rdbpredicatesproxy.h"
#include "relational_store_utils.h"

namespace OHOS {
namespace Relational {
void RdbPredicatesImpl::LessThanOrEqualTo(const char* field, ValueType value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeToValueObject(value);
    predicates_->LessThanOrEqualTo(cfield, valueObject);
}

void RdbPredicatesImpl::LessThanOrEqualToEx(const char* field, const ValueTypeEx *value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeExToValueObject(*value);
    predicates_->LessThanOrEqualTo(cfield, valueObject);
}

void RdbPredicatesImpl::EqualTo(const char* field, ValueType value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeToValueObject(value);
    predicates_->EqualTo(cfield, valueObject);
}

void RdbPredicatesImpl::EqualToEx(const char* field, const ValueTypeEx *value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeExToValueObject(*value);
    predicates_->EqualTo(cfield, valueObject);
}

void RdbPredicatesImpl::GreaterThanOrEqualTo(const char* field, ValueType value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeToValueObject(value);
    predicates_->GreaterThanOrEqualTo(cfield, valueObject);
}

void RdbPredicatesImpl::GreaterThanOrEqualToEx(const char* field, const ValueTypeEx *value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeExToValueObject(*value);
    predicates_->GreaterThanOrEqualTo(cfield, valueObject);
}

void RdbPredicatesImpl::GreaterThan(const char* field, ValueType value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeToValueObject(value);
    predicates_->GreaterThan(cfield, valueObject);
}

void RdbPredicatesImpl::GreaterThanEx(const char* field, const ValueTypeEx *value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeExToValueObject(*value);
    predicates_->GreaterThan(cfield, valueObject);
}

void RdbPredicatesImpl::NotBetween(const char* field, ValueType lowValue, ValueType highValue)
{
    std::string cfield = field;
    NativeRdb::ValueObject lowValueObject = ValueTypeToValueObject(lowValue);
    NativeRdb::ValueObject highValueObject = ValueTypeToValueObject(highValue);
    predicates_->NotBetween(cfield, lowValueObject, highValueObject);
}

void RdbPredicatesImpl::NotBetweenEx(const char* field, const ValueTypeEx *lowValue, const ValueTypeEx *highValue)
{
    std::string cfield = field;
    NativeRdb::ValueObject lowValueObject = ValueTypeExToValueObject(*lowValue);
    NativeRdb::ValueObject highValueObject = ValueTypeExToValueObject(*highValue);
    predicates_->NotBetween(cfield, lowValueObject, highValueObject);
}

void RdbPredicatesImpl::Between(const char* field, ValueType lowValue, ValueType highValue)
{
    std::string cfield = field;
    NativeRdb::ValueObject lowValueObject = ValueTypeToValueObject(lowValue);
    NativeRdb::ValueObject highValueObject = ValueTypeToValueObject(highValue);
    predicates_->Between(cfield, lowValueObject, highValueObject);
}

void RdbPredicatesImpl::BetweenEx(const char* field, const ValueTypeEx *lowValue, const ValueTypeEx *highValue)
{
    std::string cfield = field;
    NativeRdb::ValueObject lowValueObject = ValueTypeExToValueObject(*lowValue);
    NativeRdb::ValueObject highValueObject = ValueTypeExToValueObject(*highValue);
    predicates_->Between(cfield, lowValueObject, highValueObject);
}

void RdbPredicatesImpl::LessThan(const char* field, ValueType value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeToValueObject(value);
    predicates_->LessThan(cfield, valueObject);
}

void RdbPredicatesImpl::LessThanEx(const char *field, const ValueTypeEx *value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeExToValueObject(*value);
    predicates_->LessThan(cfield, valueObject);
}

void RdbPredicatesImpl::In(const char* field, ValueType* values, int64_t valuesSize)
{
    std::string cfield = field;
    std::vector<NativeRdb::ValueObject> valueObjects = std::vector<NativeRdb::ValueObject>();
    for (int64_t i = 0; i < valuesSize; i++) {
        valueObjects.push_back(ValueTypeToValueObject(values[i]));
    }
    predicates_->In(cfield, valueObjects);
}

void RdbPredicatesImpl::InEx(const char* field, ValueTypeEx* values, int64_t valuesSize)
{
    std::string cfield = field;
    std::vector<NativeRdb::ValueObject> valueObjects = std::vector<NativeRdb::ValueObject>();
    for (int64_t i = 0; i < valuesSize; i++) {
        valueObjects.push_back(ValueTypeExToValueObject(values[i]));
    }
    predicates_->In(cfield, valueObjects);
}

void RdbPredicatesImpl::NotIn(const char* field, ValueType* values, int64_t valuesSize)
{
    std::string cfield = field;
    std::vector<NativeRdb::ValueObject> valueObjects = std::vector<NativeRdb::ValueObject>();
    for (int64_t i = 0; i < valuesSize; i++) {
        valueObjects.push_back(ValueTypeToValueObject(values[i]));
    }
    predicates_->NotIn(cfield, valueObjects);
}

void RdbPredicatesImpl::NotInEx(const char* field, ValueTypeEx* values, int64_t valuesSize)
{
    std::string cfield = field;
    std::vector<NativeRdb::ValueObject> valueObjects = std::vector<NativeRdb::ValueObject>();
    for (int64_t i = 0; i < valuesSize; i++) {
        valueObjects.push_back(ValueTypeExToValueObject(values[i]));
    }
    predicates_->NotIn(cfield, valueObjects);
}

void RdbPredicatesImpl::NotEqualTo(const char* field, ValueType value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeToValueObject(value);
    predicates_->NotEqualTo(cfield, valueObject);
}

void RdbPredicatesImpl::NotEqualToEx(const char* field, const ValueTypeEx *value)
{
    std::string cfield = field;
    NativeRdb::ValueObject valueObject = ValueTypeExToValueObject(*value);
    predicates_->NotEqualTo(cfield, valueObject);
}
}
}