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
ValueObject::ValueObject()
{
}

ValueObject::ValueObject(Type val) noexcept : value(std::move(val))
{
}

ValueObject::ValueObject(ValueObject &&val) noexcept
{
    if (this == &val) {
        return;
    }
    value = std::move(val.value);
}

ValueObject::ValueObject(const ValueObject &val)
{
    if (this == &val) {
        return;
    }
    value = val.value;
}

ValueObject::~ValueObject()
{
}

ValueObject::ValueObject(int val) : value(static_cast<int64_t>(val))
{
}

ValueObject::ValueObject(int64_t val) : value(val)
{
}

ValueObject::ValueObject(double val) : value(val)
{
}

ValueObject::ValueObject(bool val) : value(val)
{
}

ValueObject::ValueObject(std::string val) : value(std::move(val))
{
}

ValueObject::ValueObject(const char *val) : ValueObject(std::string(val))
{
}

ValueObject::ValueObject(const std::vector<uint8_t> &val) : value(val)
{
}

ValueObject::ValueObject(ValueObject::Asset val) : value(std::move(val))
{
}

ValueObject::ValueObject(ValueObject::Assets val) : value(std::move(val))
{
}

ValueObject &ValueObject::operator=(ValueObject &&val) noexcept
{
    if (this == &val) {
        return *this;
    }
    value = std::move(val.value);
    return *this;
}

ValueObject &ValueObject::operator=(const ValueObject &val)
{
    if (this == &val) {
        return *this;
    }
    value = val.value;
    return *this;
}

ValueObjectType ValueObject::GetType() const
{
    return ValueObjectType(value.index());
}

int ValueObject::GetInt(int &val) const
{
    int64_t value = 0;
    auto ret = Get(value);
    val = value;
    return ret;
}

int ValueObject::GetLong(int64_t &val) const
{
    return Get(val);
}

int ValueObject::GetDouble(double &val) const
{
    return Get(val);
}

int ValueObject::GetBool(bool &val) const
{
    return Get(val);
}

int ValueObject::GetString(std::string &val) const
{
    return Get(val);
}

int ValueObject::GetBlob(std::vector<uint8_t> &val) const
{
    return Get(val);
}

int ValueObject::GetAsset(Asset &val) const
{
    return Get(val);
}

int ValueObject::GetAssets(Assets &val) const
{
    return Get(val);
}

template<class T>
int ValueObject::Get(T &output) const
{
    const T *v = std::get_if<T>(&value);
    if (v == nullptr) {
        return E_INVALID_OBJECT_TYPE;
    }
    output = static_cast<T>(*v);
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
