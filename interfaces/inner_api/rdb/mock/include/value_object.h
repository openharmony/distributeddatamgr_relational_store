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

#ifndef NATIVE_RDB_VALUE_OBJECT_H
#define NATIVE_RDB_VALUE_OBJECT_H

#include <string>
#include <variant>
#include <vector>

namespace OHOS {
namespace NativeRdb {
enum class ValueObjectType {
    TYPE_NULL = 0,
    TYPE_INT,
    TYPE_DOUBLE,
    TYPE_STRING,
    TYPE_BOOL,
    TYPE_BLOB,
};
class ValueObject {
public:
    using Type = std::variant<std::monostate, int64_t, double, std::string, bool, std::vector<uint8_t>>;
    ValueObject();
    ~ValueObject();
    ValueObject(Type valueObject) noexcept;
    ValueObject(ValueObject &&valueObject) noexcept;
    ValueObject(const ValueObject &valueObject);
    explicit ValueObject(int val);
    explicit ValueObject(int64_t val);
    explicit ValueObject(double val);
    explicit ValueObject(bool val);
    explicit ValueObject(const std::string &val);
    explicit ValueObject(const char *val);
    explicit ValueObject(const std::vector<uint8_t> &blob);
    ValueObject &operator=(ValueObject &&valueObject) noexcept;
    ValueObject &operator=(const ValueObject &valueObject);

    ValueObjectType GetType() const;
    int GetInt(int &val) const;
    int GetLong(int64_t &val) const;
    int GetDouble(double &val) const;
    int GetBool(bool &val) const;
    int GetString(std::string &val) const;
    int GetBlob(std::vector<uint8_t> &val) const;

    operator int () const
    {
        return static_cast<int>(std::get<int64_t>(value));
    }
    operator int64_t () const
    {
        return std::get<int64_t>(value);
    }
    operator double () const
    {
        return std::get<double>(value);
    }
    operator bool () const
    {
        return std::get<bool>(value);
    }
    operator std::string () const
    {
        return std::get<std::string>(value);
    }
    operator std::vector<uint8_t> () const
    {
        return std::get<std::vector<uint8_t>>(value);
    }
    operator Type() const
    {
        return value;
    }

private:
    ValueObjectType type;
    Type value;
};
} // namespace NativeRdb
} // namespace OHOS
#endif
