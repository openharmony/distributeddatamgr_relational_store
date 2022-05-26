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
enum class DataShareValueObjectType {
    TYPE_NULL = 0,
    TYPE_INT,
    TYPE_DOUBLE,
    TYPE_STRING,
    TYPE_BLOB,
    TYPE_BOOL,
};

class DataShareValueObject : public virtual OHOS::Parcelable {
public:
    DataShareValueObject();
    ~DataShareValueObject();
    DataShareValueObject(DataShareValueObject &&DataShareValueObject) noexcept;
    DataShareValueObject(const DataShareValueObject &DataShareValueObject);
    explicit DataShareValueObject(int val);
    explicit DataShareValueObject(int64_t val);
    explicit DataShareValueObject(double val);
    explicit DataShareValueObject(bool val);
    explicit DataShareValueObject(const std::string &val);
    explicit DataShareValueObject(const std::vector<uint8_t> &blob);
    DataShareValueObject &operator=(DataShareValueObject &&DataShareValueObject) noexcept;
    DataShareValueObject &operator=(const DataShareValueObject &DataShareValueObject);

    DataShareValueObjectType GetType() const;
    int GetInt(int &val) const;
    int GetLong(int64_t &val) const;
    int GetDouble(double &val) const;
    int GetBool(bool &val) const;
    int GetString(std::string &val) const;
    int GetBlob(std::vector<uint8_t> &val) const;

    bool Marshalling(Parcel &parcel) const override;
    static DataShareValueObject *Unmarshalling(Parcel &parcel);
    std::variant<int64_t, double, std::string, bool, std::vector<uint8_t>> value;
    template<typename T>
    operator T () const
    {
        return std::get<T>(value);
    }

private:
    DataShareValueObjectType type;
   
};
} // namespace DataShare
} // namespace OHOS
#endif
