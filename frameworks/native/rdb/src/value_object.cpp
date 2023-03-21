/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "value_object.h"

#include "rdb_errno.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
ValueObject::ValueObject() : type(ValueObjectType::TYPE_NULL)
{
}

ValueObject::ValueObject(ValueObject::Type valueObject) noexcept : value(std::move(valueObject))
{
    type = ValueObjectType(value.index());
}

ValueObject::ValueObject(ValueObject &&valueObject) noexcept
{
    if (this == &valueObject) {
        return;
    }
    type = valueObject.type;
    value = std::move(valueObject.value);
    valueObject.type = ValueObjectType::TYPE_NULL;
}

ValueObject::ValueObject(const ValueObject &valueObject)
{
    if (this == &valueObject) {
        return;
    }
    type = valueObject.type;
    value = valueObject.value;
}

ValueObject::~ValueObject()
{
}

ValueObject::ValueObject(int val) : type(ValueObjectType::TYPE_INT)
{
    value = static_cast<int64_t>(val);
}

ValueObject::ValueObject(int64_t val) : type(ValueObjectType::TYPE_INT)
{
    value = val;
}
ValueObject::ValueObject(double val) : type(ValueObjectType::TYPE_DOUBLE)
{
    value = val;
}
ValueObject::ValueObject(bool val) : type(ValueObjectType::TYPE_BOOL)
{
    value = val;
}
ValueObject::ValueObject(const std::string &val) : type(ValueObjectType::TYPE_STRING)
{
    value = val;
}
ValueObject::ValueObject(const std::vector<uint8_t> &val) : type(ValueObjectType::TYPE_BLOB)
{
    std::vector<uint8_t> blob = val;
    value = blob;
}

ValueObject &ValueObject::operator=(ValueObject &&valueObject) noexcept
{
    if (this == &valueObject) {
        return *this;
    }
    type = valueObject.type;
    value = std::move(valueObject.value);
    valueObject.type = ValueObjectType::TYPE_NULL;
    return *this;
}

ValueObject &ValueObject::operator=(const ValueObject &valueObject)
{
    if (this == &valueObject) {
        return *this;
    }
    type = valueObject.type;
    value = valueObject.value;
    return *this;
}

ValueObjectType ValueObject::GetType() const
{
    return type;
}

int ValueObject::GetInt(int &val) const
{
    if (type != ValueObjectType::TYPE_INT) {
        return E_INVALID_OBJECT_TYPE;
    }

    int64_t v = std::get<int64_t>(value);
    val = static_cast<int>(v);
    return E_OK;
}

int ValueObject::GetLong(int64_t &val) const
{
    if (type != ValueObjectType::TYPE_INT) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<int64_t>(value);
    return E_OK;
}

int ValueObject::GetDouble(double &val) const
{
    if (type != ValueObjectType::TYPE_DOUBLE) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<double>(value);
    return E_OK;
}

int ValueObject::GetBool(bool &val) const
{
    if (type != ValueObjectType::TYPE_BOOL) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<bool>(value);
    return E_OK;
}

int ValueObject::GetString(std::string &val) const
{
    if (type != ValueObjectType::TYPE_STRING) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<std::string>(value);
    return E_OK;
}

int ValueObject::GetBlob(std::vector<uint8_t> &val) const
{
    if (type != ValueObjectType::TYPE_BLOB) {
        return E_INVALID_OBJECT_TYPE;
    }

    val = std::get<std::vector<uint8_t>>(value);
    return E_OK;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
bool ValueObject::Marshalling(Parcel &parcel) const
{
    switch (this->type) {
        case ValueObjectType::TYPE_NULL: {
            parcel.WriteInt16((int16_t) ValueObjectType::TYPE_NULL);
            break;
        }
        case ValueObjectType::TYPE_INT: {
            parcel.WriteInt16((int16_t) ValueObjectType::TYPE_INT);
            parcel.WriteInt64(std::get<int64_t>(value));
            break;
        }
        case ValueObjectType::TYPE_DOUBLE: {
            parcel.WriteInt16((int16_t) ValueObjectType::TYPE_DOUBLE);
            parcel.WriteDouble(std::get<double>(value));
            break;
        }
        case ValueObjectType::TYPE_STRING: {
            parcel.WriteInt16((int16_t) ValueObjectType::TYPE_STRING);
            parcel.WriteString(std::get<std::string>(value));
            break;
        }
        case ValueObjectType::TYPE_BLOB: {
            parcel.WriteInt16((int16_t) ValueObjectType::TYPE_BLOB);
            parcel.WriteUInt8Vector(std::get<std::vector<uint8_t>>(value));
            break;
        }
        case ValueObjectType::TYPE_BOOL: {
            parcel.WriteInt16((int16_t) ValueObjectType::TYPE_BOOL);
            parcel.WriteBool(std::get<bool>(value));
            break;
        }
        default:
            break;
    }
    return true;
}

ValueObject *ValueObject::Unmarshalling(Parcel &parcel)
{
    switch (parcel.ReadInt16()) {
        case (int16_t)ValueObjectType::TYPE_NULL: {
            return new ValueObject();
        }
        case (int16_t)ValueObjectType::TYPE_INT: {
            return new ValueObject(parcel.ReadInt64());
        }
        case (int16_t)ValueObjectType::TYPE_DOUBLE: {
            return new ValueObject(parcel.ReadDouble());
        }
        case (int16_t)ValueObjectType::TYPE_STRING: {
            return new ValueObject(parcel.ReadString());
        }
        case (int16_t)ValueObjectType::TYPE_BLOB: {
            std::vector<uint8_t> val;
            return new ValueObject(parcel.ReadUInt8Vector(&val));
        }
        case (int16_t)ValueObjectType::TYPE_BOOL: {
            return new ValueObject(parcel.ReadBool());
        }
        default:
            return new ValueObject();
    }
}
#endif
} // namespace NativeRdb
} // namespace OHOS
