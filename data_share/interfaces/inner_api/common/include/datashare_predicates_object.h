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

#ifndef DATASHARE_PREDICATES_OBJECT_H
#define DATASHARE_PREDICATES_OBJECT_H

#include <parcel.h>
#include <variant>
#include <string>
#include <vector>

namespace OHOS {
namespace DataShare {
enum class DataSharePredicatesObjectType {
    TYPE_NULL = 0,
    TYPE_INT,
    TYPE_DOUBLE,
    TYPE_STRING,
    TYPE_BOOL,
    TYPE_LONG,
    TYPE_INT_VECTOR,
    TYPE_LONG_VECTOR,
    TYPE_DOUBLE_VECTOR,
    TYPE_STRING_VECTOR,
};

class DataSharePredicatesObject : public virtual OHOS::Parcelable {
public:
    DataSharePredicatesObject();
    ~DataSharePredicatesObject();
    DataSharePredicatesObject(DataSharePredicatesObject &&DataSharePredicatesObject) noexcept;
    DataSharePredicatesObject(const DataSharePredicatesObject &DataSharePredicatesObject);
    DataSharePredicatesObject &operator=(DataSharePredicatesObject &&DataSharePredicatesObject) noexcept;
    DataSharePredicatesObject &operator=(const DataSharePredicatesObject &DataSharePredicatesObject);
    DataSharePredicatesObject(int val);
    DataSharePredicatesObject(int64_t val);
    DataSharePredicatesObject(double val);
    DataSharePredicatesObject(bool val);
    DataSharePredicatesObject(const std::string &val);
    DataSharePredicatesObject(const std::vector<int> &val);
    DataSharePredicatesObject(const std::vector<int64_t> &val);
    DataSharePredicatesObject(const std::vector<double> &val);
    DataSharePredicatesObject(const std::vector<std::string> &val);

    DataSharePredicatesObjectType GetType() const;
    int GetInt(int &val) const;
    int GetLong(int64_t &val) const;
    int GetDouble(double &val) const;
    int GetBool(bool &val) const;
    int GetString(std::string &val) const;
    int GetIntVector(std::vector<int> &val) const;
    int GetLongVector(std::vector<int64_t> &val) const;
    int GetDoubleVector(std::vector<double> &val) const;
    int GetStringVector(std::vector<std::string> &val) const;
    bool Marshalling(Parcel &parcel) const override;
    static DataSharePredicatesObject *Unmarshalling(Parcel &parcel);
    DataSharePredicatesObjectType type;
    std::variant<std::monostate, int, int64_t, double, std::string, bool, std::vector<int>, std::vector<int64_t>,
        std::vector<std::string>, std::vector<double>> value;

    operator int () const
    {
        return std::get<int>(value);
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
    operator std::vector<int> () const
    {
        return std::get<std::vector<int>>(value);
    }
    operator std::vector<int64_t> () const
    {
        return std::get<std::vector<int64_t>>(value);
    }
    operator std::vector<std::string> () const
    {
        return std::get<std::vector<std::string>>(value);
    }
    operator std::vector<double> () const
    {
        return std::get<std::vector<double>>(value);
    }

private:
    void MarshallingVector(Parcel &parcel) const;
    static void UnmarshallingVector(DataSharePredicatesObjectType type, DataSharePredicatesObject *pValueObject,
        Parcel &parcel);
};
} // namespace DataShare
} // namespace OHOS
#endif
