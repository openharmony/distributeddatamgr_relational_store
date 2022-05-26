/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "datashare_predicates_object.h"
#include "datashare_log.h"
#include "datashare_errno.h"

namespace OHOS {
namespace DataShare {
DataSharePredicatesObject::DataSharePredicatesObject() : type(DataSharePredicatesObjectType::TYPE_NULL)
{
}

DataSharePredicatesObject::DataSharePredicatesObject(DataSharePredicatesObject &&DataSharePredicatesObject) noexcept
{
    if (this == &DataSharePredicatesObject) {
        return;
    }
    type = DataSharePredicatesObject.type;
    value = std::move(DataSharePredicatesObject.value);
    DataSharePredicatesObject.type = DataSharePredicatesObjectType::TYPE_NULL;
}

DataSharePredicatesObject::DataSharePredicatesObject(const DataSharePredicatesObject &DataSharePredicatesObject)
{
    if (this == &DataSharePredicatesObject) {
        return;
    }
    type = DataSharePredicatesObject.type;
    value = DataSharePredicatesObject.value;
}

DataSharePredicatesObject::~DataSharePredicatesObject()
{
}

DataSharePredicatesObject::DataSharePredicatesObject(int val) : type(DataSharePredicatesObjectType::TYPE_INT)
{
    value = static_cast<int64_t>(val);
}

DataSharePredicatesObject::DataSharePredicatesObject(int64_t val) : type(DataSharePredicatesObjectType::TYPE_LONG)
{
    value = val;
}

DataSharePredicatesObject::DataSharePredicatesObject(double val) : type(DataSharePredicatesObjectType::TYPE_DOUBLE)
{
    value = val;
}

DataSharePredicatesObject::DataSharePredicatesObject(bool val) : type(DataSharePredicatesObjectType::TYPE_BOOL)
{
    value = val;
}

DataSharePredicatesObject::DataSharePredicatesObject(const std::string &val)
    : type(DataSharePredicatesObjectType::TYPE_STRING)
{
    value = val;
}

DataSharePredicatesObject::DataSharePredicatesObject(const std::vector<int> &val)
    : type(DataSharePredicatesObjectType::TYPE_INT_VECTOR)
{
    std::vector<int64_t> int64val {};
    if (!val.empty()) {
        for (const auto &it : val) {
            int64val.push_back(static_cast<int64_t>(it));
        }
        value = int64val;
    }
}

DataSharePredicatesObject::DataSharePredicatesObject(const std::vector<int64_t> &val)
    : type(DataSharePredicatesObjectType::TYPE_LONG_VECTOR)
{
    std::vector<int64_t> parameter = val;
    value = parameter;
}

DataSharePredicatesObject::DataSharePredicatesObject(const std::vector<std::string> &val)
    : type(DataSharePredicatesObjectType::TYPE_STRING_VECTOR)
{
    std::vector<std::string> parameter = val;
    value = parameter;
}

DataSharePredicatesObject::DataSharePredicatesObject(const std::vector<double> &val)
    : type(DataSharePredicatesObjectType::TYPE_DOUBLE_VECTOR)
{
    std::vector<double> parameter = val;
    value = parameter;
}

DataSharePredicatesObject &DataSharePredicatesObject::operator=(
    DataSharePredicatesObject &&DataSharePredicatesObject) noexcept
{
    if (this == &DataSharePredicatesObject) {
        return *this;
    }
    type = DataSharePredicatesObject.type;
    value = std::move(DataSharePredicatesObject.value);
    DataSharePredicatesObject.type = DataSharePredicatesObjectType::TYPE_NULL;
    return *this;
}

DataSharePredicatesObject &DataSharePredicatesObject::operator=(
    const DataSharePredicatesObject &DataSharePredicatesObject)
{
    if (this == &DataSharePredicatesObject) {
        return *this;
    }
    type = DataSharePredicatesObject.type;
    value = DataSharePredicatesObject.value;
    return *this;
}

DataSharePredicatesObjectType DataSharePredicatesObject::GetType() const
{
    return type;
}

int DataSharePredicatesObject::GetInt(int &val) const
{
    if (type != DataSharePredicatesObjectType::TYPE_INT) {
        return E_INVALID_OBJECT_TYPE;
    }

    int64_t v = std::get<int64_t>(value);
    val = static_cast<int>(v);
    return E_OK;
}

int DataSharePredicatesObject::GetLong(int64_t &val) const
{
    if (type != DataSharePredicatesObjectType::TYPE_INT) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<int64_t>(value);
    return E_OK;
}

int DataSharePredicatesObject::GetDouble(double &val) const
{
    if (type != DataSharePredicatesObjectType::TYPE_DOUBLE) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<double>(value);
    return E_OK;
}

int DataSharePredicatesObject::GetBool(bool &val) const
{
    if (type != DataSharePredicatesObjectType::TYPE_BOOL) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<bool>(value);
    return E_OK;
}

int DataSharePredicatesObject::GetString(std::string &val) const
{
    if (type != DataSharePredicatesObjectType::TYPE_STRING) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<std::string>(value);
    return E_OK;
}

int DataSharePredicatesObject::GetIntVector(std::vector<int> &val) const
{
    if (type != DataSharePredicatesObjectType::TYPE_INT_VECTOR) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<std::vector<int>>(value);
    return E_OK;
}

int DataSharePredicatesObject::GetLongVector(std::vector<int64_t> &val) const
{
    if (type != DataSharePredicatesObjectType::TYPE_LONG_VECTOR) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<std::vector<int64_t>>(value);
    return E_OK;
}

int DataSharePredicatesObject::GetDoubleVector(std::vector<double> &val) const
{
    if (type != DataSharePredicatesObjectType::TYPE_DOUBLE_VECTOR) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<std::vector<double>>(value);
    return E_OK;
}

int DataSharePredicatesObject::GetStringVector(std::vector<std::string> &val) const
{
    if (type != DataSharePredicatesObjectType::TYPE_STRING_VECTOR) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<std::vector<std::string>>(value);
    return E_OK;
}

bool DataSharePredicatesObject::Marshalling(Parcel &parcel) const
{
    LOG_DEBUG("DataSharePredicatesObject::Marshalling Start");
    parcel.WriteInt16((int16_t)this->type);
    switch (this->type) {
        case DataSharePredicatesObjectType::TYPE_NULL: {
            break;
        }
        case DataSharePredicatesObjectType::TYPE_INT: {
            parcel.WriteInt64(std::get<int64_t>(value));
            break;
        }
        case DataSharePredicatesObjectType::TYPE_LONG: {
            parcel.WriteInt64(std::get<int64_t>(value));
            break;
        }
        case DataSharePredicatesObjectType::TYPE_DOUBLE: {
            parcel.WriteDouble(std::get<double>(value));
            break;
        }
        case DataSharePredicatesObjectType::TYPE_STRING: {
            parcel.WriteString(std::get<std::string>(value));
            break;
        }
        case DataSharePredicatesObjectType::TYPE_BOOL: {
            parcel.WriteBool(std::get<bool>(value));
            break;
        }
        default:
            break;
    }
    MarshallingVector(parcel);
    LOG_DEBUG("DataSharePredicatesObject::Marshalling End");
    return true;
}

DataSharePredicatesObject *DataSharePredicatesObject::Unmarshalling(Parcel &parcel)
{
    LOG_DEBUG("DataSharePredicatesObject::Unmarshalling Start");
    auto *pValueObject = new DataSharePredicatesObject();
    if (pValueObject != nullptr) {
        pValueObject->type = (DataSharePredicatesObjectType)parcel.ReadInt16();
        switch (pValueObject->type) {
            case DataSharePredicatesObjectType::TYPE_NULL: {
                break;
            }
            case DataSharePredicatesObjectType::TYPE_INT: {
                pValueObject->value = static_cast<int>(parcel.ReadInt64());
                break;
            }
            case DataSharePredicatesObjectType::TYPE_LONG: {
                pValueObject->value = parcel.ReadInt64();
                break;
            }
            case DataSharePredicatesObjectType::TYPE_DOUBLE: {
                pValueObject->value = parcel.ReadDouble();
                break;
            }
            case DataSharePredicatesObjectType::TYPE_STRING: {
                pValueObject->value = parcel.ReadString();
                break;
            }
            case DataSharePredicatesObjectType::TYPE_BOOL: {
                pValueObject->value = parcel.ReadBool();
                break;
            }
            default:
                break;
        }
        UnmarshallingVector(pValueObject->type, pValueObject, parcel);
    }
    LOG_DEBUG("DataSharePredicatesObject::Unmarshalling End");
    return pValueObject;
}

void DataSharePredicatesObject::UnmarshallingVector(DataSharePredicatesObjectType type,
    DataSharePredicatesObject *pValueObject, Parcel &parcel)
{
    switch (type) {
        case DataSharePredicatesObjectType::TYPE_INT_VECTOR: {
            std::vector<int64_t> int64val {};
            std::vector<int> intval {};
            parcel.ReadInt64Vector(&int64val);
            if (!int64val.empty()) {
                for (const auto &it : int64val) {
                    intval.push_back(static_cast<int>(it));
                }
            }
            pValueObject->value = intval;
            break;
        }
        case DataSharePredicatesObjectType::TYPE_LONG_VECTOR: {
            std::vector<int64_t> int64val {};
            parcel.ReadInt64Vector(&int64val);
            pValueObject->value = int64val;
            break;
        }
        case DataSharePredicatesObjectType::TYPE_DOUBLE_VECTOR: {
            std::vector<double> doubleval {};
            parcel.ReadDoubleVector(&doubleval);
            pValueObject->value = doubleval;
            break;
        }
        case DataSharePredicatesObjectType::TYPE_STRING_VECTOR: {
            std::vector<std::string> stringval {};
            parcel.ReadStringVector(&stringval);
            pValueObject->value = stringval;
            break;
        }
        default:
            break;
    }
}

void DataSharePredicatesObject::MarshallingVector(Parcel &parcel) const
{
    switch (this->type) {
        case DataSharePredicatesObjectType::TYPE_INT_VECTOR: {
            parcel.WriteInt64Vector(std::get<std::vector<int64_t>>(value));
            break;
        }
        case DataSharePredicatesObjectType::TYPE_LONG_VECTOR: {
            parcel.WriteInt64Vector(std::get<std::vector<int64_t>>(value));
            break;
        }
        case DataSharePredicatesObjectType::TYPE_DOUBLE_VECTOR: {
            parcel.WriteDoubleVector(std::get<std::vector<double>>(value));
            break;
        }
        case DataSharePredicatesObjectType::TYPE_STRING_VECTOR: {
            parcel.WriteStringVector(std::get<std::vector<std::string>>(value));
            break;
        }
        default:
            break;
    }
}
} // namespace DataShare
} // namespace OHOS
