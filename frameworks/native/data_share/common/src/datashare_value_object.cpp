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

#include "datashare_value_object.h"

#include "datashare_errno.h"

namespace OHOS {
namespace DataShare {
DataShareValueObjectType DataShareValueObject::GetType() const
{
    return type;
}

int DataShareValueObject::GetInt(int &val) const
{
    if (type != DataShareValueObjectType::TYPE_INT) {
        return E_INVALID_OBJECT_TYPE;
    }

    int64_t v = std::get<int64_t>(value);
    val = static_cast<int>(v);
    return E_OK;
}

int DataShareValueObject::GetLong(int64_t &val) const
{
    if (type != DataShareValueObjectType::TYPE_INT) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<int64_t>(value);
    return E_OK;
}

int DataShareValueObject::GetDouble(double &val) const
{
    if (type != DataShareValueObjectType::TYPE_DOUBLE) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<double>(value);
    return E_OK;
}

int DataShareValueObject::GetBool(bool &val) const
{
    if (type != DataShareValueObjectType::TYPE_BOOL) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<bool>(value);
    return E_OK;
}

int DataShareValueObject::GetString(std::string &val) const
{
    if (type != DataShareValueObjectType::TYPE_STRING) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<std::string>(value);
    return E_OK;
}

int DataShareValueObject::GetBlob(std::vector<uint8_t> &val) const
{
    if (type != DataShareValueObjectType::TYPE_BLOB) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<std::vector<uint8_t>>(value);
    return E_OK;
}

bool DataShareValueObject::Marshalling(Parcel &parcel) const
{
    switch (this->type) {
        case DataShareValueObjectType::TYPE_NULL: {
            parcel.WriteInt16((int16_t) DataShareValueObjectType::TYPE_NULL);
            break;
        }
        case DataShareValueObjectType::TYPE_INT: {
            parcel.WriteInt16((int16_t) DataShareValueObjectType::TYPE_INT);
            parcel.WriteInt64(std::get<int64_t>(value));
            break;
        }
        case DataShareValueObjectType::TYPE_DOUBLE: {
            parcel.WriteInt16((int16_t) DataShareValueObjectType::TYPE_DOUBLE);
            parcel.WriteDouble(std::get<double>(value));
            break;
        }
        case DataShareValueObjectType::TYPE_STRING: {
            parcel.WriteInt16((int16_t) DataShareValueObjectType::TYPE_STRING);
            parcel.WriteString(std::get<std::string>(value));
            break;
        }
        case DataShareValueObjectType::TYPE_BLOB: {
            parcel.WriteInt16((int16_t) DataShareValueObjectType::TYPE_BLOB);
            parcel.WriteUInt8Vector(std::get<std::vector<uint8_t>>(value));
            break;
        }
        case DataShareValueObjectType::TYPE_BOOL: {
            parcel.WriteInt16((int16_t) DataShareValueObjectType::TYPE_BOOL);
            parcel.WriteBool(std::get<bool>(value));
            break;
        }
        default:
            break;
    }
    return true;
}

DataShareValueObject *DataShareValueObject::Unmarshalling(Parcel &parcel)
{
    auto *pValueObject = new DataShareValueObject();
    switch (parcel.ReadInt16()) {
        case (int16_t)DataShareValueObjectType::TYPE_NULL: {
            pValueObject->type = DataShareValueObjectType::TYPE_NULL;
            break;
        }
        case (int16_t)DataShareValueObjectType::TYPE_INT: {
            pValueObject->type = DataShareValueObjectType::TYPE_INT;
            pValueObject->value = parcel.ReadInt64();
            break;
        }
        case (int16_t)DataShareValueObjectType::TYPE_DOUBLE: {
            pValueObject->type = DataShareValueObjectType::TYPE_DOUBLE;
            pValueObject->value = parcel.ReadDouble();
            break;
        }
        case (int16_t)DataShareValueObjectType::TYPE_STRING: {
            pValueObject->type = DataShareValueObjectType::TYPE_STRING;
            pValueObject->value = parcel.ReadString();
            break;
        }
        case (int16_t)DataShareValueObjectType::TYPE_BLOB: {
            pValueObject->type = DataShareValueObjectType::TYPE_BLOB;
            std::vector<uint8_t> val;
            parcel.ReadUInt8Vector(&val);
            pValueObject->value = val;
            break;
        }
        case (int16_t)DataShareValueObjectType::TYPE_BOOL: {
            pValueObject->type = DataShareValueObjectType::TYPE_BOOL;
            pValueObject->value = parcel.ReadBool();
            break;
        }
        default:
            break;
    }
    return pValueObject;
}
} // namespace DataShare
} // namespace OHOS
