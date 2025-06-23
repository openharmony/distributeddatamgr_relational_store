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

#include "relational_store_impl_rdbpredicatesproxy.h"
#include "relational_store_utils.h"

namespace OHOS {
namespace Relational {
    RdbPredicatesImpl::RdbPredicatesImpl(const char* tableName)
    {
        std::string str = tableName;
        predicates_ = std::make_shared<NativeRdb::RdbPredicates>(str);
    }

    RdbPredicatesImpl::RdbPredicatesImpl(std::shared_ptr<NativeRdb::RdbPredicates> predicates)
    {
        predicates_ = predicates;
    }

    OHOS::FFI::RuntimeType* RdbPredicatesImpl::GetClassType()
    {
        static OHOS::FFI::RuntimeType runtimeType =
            OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("RdbPredicatesImpl");
        return &runtimeType;
    }

    std::shared_ptr<NativeRdb::RdbPredicates> RdbPredicatesImpl::GetPredicates()
    {
        return predicates_;
    }

    void RdbPredicatesImpl::InDevices(const char** devicesArray, int64_t devicesSize)
    {
        std::vector<std::string> devices;
        for (int64_t i = 0; i < devicesSize; i++) {
            devices.push_back(devicesArray[i]);
        }
        predicates_->InDevices(devices);
    }

    void RdbPredicatesImpl::InAllDevices()
    {
        predicates_->InAllDevices();
    }

    void RdbPredicatesImpl::BeginWrap()
    {
        predicates_->BeginWrap();
    }

    void RdbPredicatesImpl::EndWrap()
    {
        predicates_->EndWrap();
    }

    void RdbPredicatesImpl::Or()
    {
        predicates_->Or();
    }

    void RdbPredicatesImpl::And()
    {
        predicates_->And();
    }

    void RdbPredicatesImpl::Contains(const char* field, const char* value)
    {
        std::string cfield = field;
        std::string cvalue = value;
        predicates_->Contains(cfield, cvalue);
    }

    void RdbPredicatesImpl::BeginsWith(const char* field, const char* value)
    {
        std::string cfield = field;
        std::string cvalue = value;
        predicates_->BeginsWith(cfield, cvalue);
    }

    void RdbPredicatesImpl::EndsWith(const char* field, const char* value)
    {
        std::string cfield = field;
        std::string cvalue = value;
        predicates_->EndsWith(cfield, cvalue);
    }

    void RdbPredicatesImpl::IsNull(const char* field)
    {
        std::string cfield = field;
        predicates_->IsNull(cfield);
    }

    void RdbPredicatesImpl::IsNotNull(const char* field)
    {
        std::string cfield = field;
        predicates_->IsNotNull(cfield);
    }

    void RdbPredicatesImpl::Like(const char* field, const char* value)
    {
        std::string cfield = field;
        std::string cvalue = value;
        predicates_->Like(cfield, cvalue);
    }

    void RdbPredicatesImpl::Glob(const char* field, const char* value)
    {
        std::string cfield = field;
        std::string cvalue = value;
        predicates_->Glob(cfield, cvalue);
    }

    void RdbPredicatesImpl::OrderByAsc(const char* field)
    {
        std::string cfield = field;
        predicates_->OrderByAsc(cfield);
    }

    void RdbPredicatesImpl::OrderByDesc(const char* field)
    {
        std::string cfield = field;
        predicates_->OrderByDesc(cfield);
    }

    void RdbPredicatesImpl::Distinct()
    {
        predicates_->Distinct();
    }

    void RdbPredicatesImpl::LimitAs(int32_t value)
    {
        predicates_->Limit(value);
    }

    void RdbPredicatesImpl::OffsetAs(int32_t rowOffset)
    {
        predicates_->Offset(rowOffset);
    }

    void RdbPredicatesImpl::GroupBy(const char** fieldsArray, int64_t fieldsSize)
    {
        std::vector<std::string> fields;
        for (int64_t i = 0; i < fieldsSize; i++) {
            fields.push_back(fieldsArray[i]);
        }
        predicates_->GroupBy(fields);
    }

    void RdbPredicatesImpl::IndexedBy(const char* field)
    {
        std::string cfield = field;
        predicates_->IndexedBy(cfield);
    }

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

    void RdbPredicatesImpl::NotContains(const char* field, const char* value)
    {
        std::string cfield = field;
        std::string cvalue = value;
        predicates_->NotContains(cfield, cvalue);
    }

    void RdbPredicatesImpl::NotLike(const char* field, const char* value)
    {
        std::string cfield = field;
        std::string cvalue = value;
        predicates_->NotLike(field, value);
    }
}
}