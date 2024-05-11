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

#include <iostream>
#include <limits>
#include <sstream>

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

ValueObject::ValueObject(ValueObject::BigInt val) : value(std::move(val))
{
}

ValueObject::ValueObject(ValueObject::FloatVector val) : value(std::move(val))
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
    if (Get(val) == E_OK) {
        return E_OK;
    }

    double ftmp;
    if (Get(ftmp) == E_OK) {
        val = std::to_string(ftmp);
        return E_OK;
    }

    int64_t itmp;
    if (Get(itmp) == E_OK) {
        val = std::to_string(itmp);
        return E_OK;
    }

    bool btmp;
    if (Get(btmp) == 0) {
        val = std::to_string(btmp);
        return E_OK;
    }
    return E_INVALID_OBJECT_TYPE;
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

ValueObject::operator int() const
{
    return static_cast<int>(operator int64_t());
}

ValueObject::operator int64_t() const
{
    int64_t val = 0L;
    int type = static_cast<int>(value.index());
    if (type == ValueObject::TYPE_INT) {
        val = std::get<int64_t>(value);
    } else if (type == ValueObject::TYPE_DOUBLE) {
        val = int64_t(std::get<double>(value));
    } else if (type == ValueObject::TYPE_BOOL) {
        val = std::get<bool>(value);
    } else if (type == ValueObject::TYPE_STRING) {
        auto temp = std::get<std::string>(value);
        val = temp.empty() ? 0L : int64_t(strtoll(temp.c_str(), nullptr, 0));
    }
    return val;
}

ValueObject::operator double() const
{
    double val = 0.0L;
    size_t type = value.index();
    if (type == ValueObject::TYPE_INT) {
        val = double(std::get<int64_t>(value));
    } else if (type == ValueObject::TYPE_DOUBLE) {
        val = std::get<double>(value);
    } else if (type == ValueObject::TYPE_BOOL) {
        val = std::get<bool>(value);
    } else if (type == ValueObject::TYPE_STRING) {
        auto temp = std::get<std::string>(value);
        val = temp.empty() ? 0.0 : double(strtod(temp.c_str(), nullptr));
    }
    return val;
}

ValueObject::operator bool() const
{
    bool val = false;
    int type = value.index();
    if (type == ValueObject::TYPE_INT) {
        val = std::get<int64_t>(value) != 0;
    } else if (type == ValueObject::TYPE_DOUBLE) {
        val = static_cast<int64_t>(std::get<double>(value)) != 0;
    } else if (type == ValueObject::TYPE_BOOL) {
        val = std::get<bool>(value);
    } else if (type == ValueObject::TYPE_STRING) {
        auto temp = std::get<std::string>(value);
        val = (temp == "true" || temp != "0");
    }
    return val;
}

static int32_t GetPrecision(double val)
{
    int max = std::numeric_limits<double>::max_digits10;
    int precision = 0;
    val = val - int64_t(val);
    for (int i = 0; i < max; ++i) {
        // Loop to multiply the decimal part of val by 10 until it is no longer a decimal
        val *= 10;
        if (int64_t(val) > 0) {
            precision = i + 1;
        }
        val -= int64_t(val);
    }
    return precision;
}

ValueObject::operator std::string() const
{
    std::string val;
    int type = value.index();
    if (type == ValueObject::TYPE_INT) {
        auto temp = std::get<int64_t>(value);
        val = std::to_string(temp);
    } else if (type == ValueObject::TYPE_BOOL) {
        val = std::get<bool>(value) ? "1" : "0";
    } else if (type == ValueObject::TYPE_DOUBLE) {
        double temp = std::get<double>(value);
        std::ostringstream os;
        os.setf(std::ios::fixed);
        os.precision(GetPrecision(temp));
        if (os << temp) {
            val = os.str();
        }
    } else if (type == ValueObject::TYPE_STRING) {
        val = std::get<std::string>(value);
    }
    return val;
}

ValueObject::operator Blob() const
{
    Blob val;
    int type = static_cast<int>(value.index());
    if (type == ValueObject::TYPE_BLOB) {
        val = std::get<std::vector<uint8_t>>(value);
    } else if (type == ValueObject::TYPE_STRING) {
        auto temp = std::get<std::string>(value);
        val.assign(temp.begin(), temp.end());
    }
    return val;
}

ValueObject::operator Asset() const
{
    auto val = std::get_if<Asset>(&value);
    if (val == nullptr) {
        return {};
    }
    return *val;
}

ValueObject::operator Assets() const
{
    auto val = std::get_if<Assets>(&value);
    if (val == nullptr) {
        return {};
    }
    return *val;
}

ValueObject::operator FloatVector() const
{
    auto val = std::get_if<FloatVector>(&value);
    if (val == nullptr) {
        return {};
    }
    return *val;
}

ValueObject::operator BigInt() const
{
    auto val = std::get_if<BigInt>(&value);
    if (val == nullptr) {
        return {};
    }
    return *val;
}

int ValueObject::GetVecs(FloatVector &val) const
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
