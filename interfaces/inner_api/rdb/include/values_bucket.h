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

#ifndef NATIVE_RDB_VALUES_BUCKET_H
#define NATIVE_RDB_VALUES_BUCKET_H

#include <map>
#include <set>
#include <parcel.h>

#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
/**
 * The ValuesBucket class of RDB.
 */
class RDB_API_EXPORT ValuesBucket : public virtual OHOS::Parcelable {
public:
    /**
     * @brief Constructor.
     */
    RDB_API_EXPORT ValuesBucket();

    /**
     * @brief Constructor.
     *
     * A parameterized constructor used to create a ValuesBucket instance.
     */
    RDB_API_EXPORT explicit ValuesBucket(std::map<std::string, ValueObject> &valuesMap);

    /**
     * @brief Destructor.
     */
    RDB_API_EXPORT  ~ValuesBucket();

    /**
     * @brief Put the string value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the string value.
     */
    RDB_API_EXPORT void PutString(const std::string &columnName, const std::string &value);

    /**
     * @brief Put the int value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the int value.
     */
    RDB_API_EXPORT void PutInt(const std::string &columnName, int value);

    /**
     * @brief Put the long value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the long value.
     */
    RDB_API_EXPORT void PutLong(const std::string &columnName, int64_t value);

    /**
     * @brief Put the double value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the double value.
     */
    RDB_API_EXPORT void PutDouble(const std::string &columnName, double value);

    /**
     * @brief Put the bool value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the bool value.
     */
    RDB_API_EXPORT void PutBool(const std::string &columnName, bool value);

    /**
     * @brief Put the vector<uint8_t> value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the vector<uint8_t> value.
     */
    RDB_API_EXPORT void PutBlob(const std::string &columnName, const std::vector<uint8_t> &value);

    /**
     * @brief Put NULL to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     */
    RDB_API_EXPORT void PutNull(const std::string &columnName);

    /**
     * @brief Put value object to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     */
    void Put(const std::string &columnName, const ValueObject &value);

    /**
     * @brief Delete the ValueObject object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     */
    RDB_API_EXPORT void Delete(const std::string &columnName);

    /**
     * @brief Clear the ValuesBucket object's valuesmap.
     */
    RDB_API_EXPORT void Clear();

    /**
     * @brief Obtains the ValuesBucket object's valuesmap size.
     */
    RDB_API_EXPORT int Size() const;

    /**
     * @brief Checks whether the ValuesBucket object's valuesmap is empty.
     */
    RDB_API_EXPORT bool IsEmpty() const;

    /**
     * @brief Checks whether the ValuesBucket object's valuesmap contain the specified columnName.
     *
     * @param columnName Indicates the name of the column.
     */
    RDB_API_EXPORT bool HasColumn(const std::string &columnName) const;

    /**
     * @brief Obtains the specified value for the given column name.
     *
     * @param columnName Indicates the name of the column.
     */
    RDB_API_EXPORT bool GetObject(const std::string &columnName, ValueObject &value) const;

    /**
     * @brief Obtains the ValuesBucket object's valuesmap.
     */
    RDB_API_EXPORT void GetAll(std::map<std::string, ValueObject> &valuesMap) const;

    /**
     * @brief Write to message parcel.
     */
    RDB_API_EXPORT bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Obtains a ValuesBucket object from parcel.
     */
    RDB_API_EXPORT static ValuesBucket *Unmarshalling(Parcel &parcel);
private:
    std::map<std::string, ValueObject> valuesMap;
};

} // namespace NativeRdb
} // namespace OHOS
#endif
