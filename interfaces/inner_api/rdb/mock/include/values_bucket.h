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

#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
class ValuesBucket {
public:
    /**
     * @brief Constructor.
     */
    ValuesBucket();

    /**
     * @brief Constructor.
     *
     * A parameterized constructor used to create a ValuesBucket instance.
     */
    ValuesBucket(std::map<std::string, ValueObject> values);
    ValuesBucket(const ValuesBucket &values);
    ValuesBucket &operator =(const ValuesBucket &values);
    ValuesBucket(ValuesBucket &&values) noexcept;
    ValuesBucket &operator =(ValuesBucket &&values) noexcept;

    /**
     * @brief Destructor.
     */
    ~ValuesBucket();

    /**
     * @brief Put the string value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the string value.
     */
    void PutString(const std::string &columnName, const std::string &value);

    /**
     * @brief Put the int value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the int value.
     */
    void PutInt(const std::string &columnName, int value);

    /**
     * @brief Put the long value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the long value.
     */
    void PutLong(const std::string &columnName, int64_t value);

    /**
     * @brief Put the double value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the double value.
     */
    void PutDouble(const std::string &columnName, double value);

    /**
     * @brief Put the bool value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the bool value.
     */
    void PutBool(const std::string &columnName, bool value);

    /**
     * @brief Put the vector<uint8_t> value to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     * @param value Indicates the vector<uint8_t> value.
     */
    void PutBlob(const std::string &columnName, const std::vector<uint8_t> &value);

    /**
     * @brief Put NULL to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     */
    void PutNull(const std::string &columnName);

    /**
     * @brief Put the integer double bool string bytes asset asset and so on
     * to this {@code ValuesBucket} object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     */
    void Put(const std::string &columnName, const ValueObject &value);

    /**
     * @brief Delete the ValueObject object for the given column name.
     *
     * @param columnName Indicates the name of the column.
     */
    void Delete(const std::string &columnName);

    /**
     * @brief Clear the ValuesBucket object's valuesmap.
     */
    void Clear();

    /**
     * @brief Obtains the ValuesBucket object's valuesmap size.
     */
    int Size() const;

    /**
     * @brief Checks whether the ValuesBucket object's valuesmap is empty.
     */
    bool IsEmpty() const;

    /**
     * @brief Checks whether the ValuesBucket object's valuesmap contain the specified columnName.
     *
     * @param columnName Indicates the name of the column.
     */
    bool HasColumn(const std::string &columnName) const;

    /**
     * @brief Obtains the specified value for the given column name.
     *
     * @param columnName Indicates the name of the column.
     */
    bool GetObject(const std::string &columnName, ValueObject &value) const;

    /**
     * @brief Obtains the ValuesBucket object's values.
     */
    std::map<std::string, ValueObject> GetAll() const;

    /**
     * @brief Obtains the ValuesBucket object's values.
     */
    void GetAll(std::map<std::string, ValueObject> &output) const;

    std::map<std::string, ValueObject> values_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif
