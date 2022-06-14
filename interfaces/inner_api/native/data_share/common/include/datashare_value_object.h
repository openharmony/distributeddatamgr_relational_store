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

#ifndef DATASHARE_VALUE_OBJECT_H
#define DATASHARE_VALUE_OBJECT_H

#include <parcel.h>
#include <variant>
#include <string>
#include <vector>

namespace OHOS {
namespace DataShare {
enum DataShareValueObjectType : int32_t {
    TYPE_NULL = 0,
    TYPE_INT,
    TYPE_DOUBLE,
    TYPE_STRING,
    TYPE_BOOL,
    TYPE_BLOB,
};

class DataShareValueObject {
public:
    DataShareValueObject() : type(TYPE_NULL){};
    ~DataShareValueObject() = default;
    DataShareValueObject(DataShareValueObject &&object) noexcept : type(object.type), value(std::move(object.value)){};
    DataShareValueObject(const DataShareValueObject &object) : type(object.type), value(object.value){};
    DataShareValueObject(int val) : DataShareValueObject(static_cast<int64_t>(val)) {};
    DataShareValueObject(int64_t val) : type(TYPE_INT), value(val){};
    DataShareValueObject(double val) : type(TYPE_DOUBLE), value(val){};
    DataShareValueObject(bool val) : type(TYPE_BOOL), value(val){};
    DataShareValueObject(const std::string &val) : type(TYPE_STRING), value(val){};
    DataShareValueObject(const char *val) : DataShareValueObject(std::string(val)){};
    DataShareValueObject(std::vector<uint8_t> blob) : type(TYPE_BLOB), value(std::move(blob)){};
    DataShareValueObject &operator=(DataShareValueObject &&object) noexcept
    {
        if (this == &object) {
            return *this;
        }
        type = object.type;
        value = std::move(object.value);
        object.type = TYPE_NULL;
        return *this;
    };
    DataShareValueObject &operator=(const DataShareValueObject &object)
    {
        if (this == &object) {
            return *this;
        }
        type = object.type;
        value = object.value;
        return *this;
    }

    DataShareValueObjectType GetType() const;
    int GetInt(int &val) const;
    int GetLong(int64_t &val) const;
    int GetDouble(double &val) const;
    int GetBool(bool &val) const;
    int GetString(std::string &val) const;
    int GetBlob(std::vector<uint8_t> &val) const;
    static bool Marshalling(const DataShareValueObject &valueObject, Parcel &parcel);
    static DataShareValueObject *Unmarshalling(Parcel &parcel);

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
    DataShareValueObjectType type;
    std::variant<std::monostate, int, int64_t, double, std::string, bool, std::vector<uint8_t>> value;
};
} // namespace DataShare
} // namespace OHOS
#endif
