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
#include <parcel.h>

namespace OHOS {
namespace NativeRdb {
/**
 * @brief Indicates the ValueObject {@link ValueObject} type.
 */
enum class ValueObjectType {
    /** Indicates the ValueObject type is NULL.*/
    TYPE_NULL = 0,
    /** Indicates the ValueObject type is int.*/
    TYPE_INT,
    /** Indicates the ValueObject type is double.*/
    TYPE_DOUBLE,
    /** Indicates the ValueObject type is string.*/
    TYPE_STRING,
    /** Indicates the ValueObject type is bool.*/
    TYPE_BOOL,
    /** Indicates the ValueObject type is blob.*/
    TYPE_BLOB,
};
/**
 * The ValueObject class of RDB.
 */
class ValueObject : public virtual OHOS::Parcelable {
public:
    /**
     * @brief Use Type replace std::variant.
     */
    using Type = std::variant<std::monostate, int64_t, double, std::string, bool, std::vector<uint8_t>>;
    /**
     * @brief Constructor.
     */
    ValueObject();
    /**
     * @brief Destructor.
     */
    ~ValueObject();
    /**
     * @brief Constructor.
     *
     * A parameterized constructor used to create a ValueObject instance.
     */
    ValueObject(Type valueObject) noexcept;
    /**
     * @brief Move constructor.
     */
    ValueObject(ValueObject &&valueObject) noexcept;
    /**
     * @brief Copy constructor.
     */
    ValueObject(const ValueObject &valueObject);
    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int input parameter to a value of type ValueObject.
     *
     * @param val Indicates an int input parameter.
     */
    explicit ValueObject(int val);
    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int64_t input parameter to a value of type ValueObject.
     *
     * @param val Indicates an int64_t input parameter.
     */
    explicit ValueObject(int64_t val);
    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the double input parameter to a value of type ValueObject.
     *
     * @param val Indicates an double input parameter.
     */
    explicit ValueObject(double val);
    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the bool input parameter to a value of type ValueObject.
     *
     * @param val Indicates an bool input parameter.
     */
    explicit ValueObject(bool val);
    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the string input parameter to a value of type ValueObject.
     *
     * @param val Indicates an string input parameter.
     */
    explicit ValueObject(const std::string &val);
    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the vector<uint8_t> input parameter to a value of type ValueObject.
     *
     * @param val Indicates an vector<uint8_t> input parameter.
     */
    explicit ValueObject(const std::vector<uint8_t> &blob);
    /**
     * @brief Move assignment operator overloaded function.
     */
    ValueObject &operator=(ValueObject &&valueObject) noexcept;
    /**
     * @brief Copy assignment operator overloaded function.
     */
    ValueObject &operator=(const ValueObject &valueObject);

    /**
     * @brief Obtains the type in this {@code ValueObject} object.
     */
    ValueObjectType GetType() const;
    /**
     * @brief Obtains the int value in this {@code ValueObject} object.
     */
    int GetInt(int &val) const;
    /**
     * @brief Obtains the long value in this {@code ValueObject} object.
     */
    int GetLong(int64_t &val) const;
    /**
     * @brief Obtains the double value in this {@code ValueObject} object.
     */
    int GetDouble(double &val) const;
    /**
     * @brief Obtains the bool value in this {@code ValueObject} object.
     */
    int GetBool(bool &val) const;
    /**
     * @brief Obtains the string value in this {@code ValueObject} object.
     */
    int GetString(std::string &val) const;
    /**
     * @brief Obtains the vector<uint8_t> value in this {@code ValueObject} object.
     */
    int GetBlob(std::vector<uint8_t> &val) const;

    /**
     * @brief Write to message parcel.
     */
    bool Marshalling(Parcel &parcel) const override;
    /**
     * @brief Obtains a ValueObject object from parcel.
     */
    static ValueObject *Unmarshalling(Parcel &parcel);

    /**
     * @brief Type conversion function.
     *
     * @return Returns the int type ValueObject.
     */
    operator int () const
    {
        return static_cast<int>(std::get<int64_t>(value));
    }
    /**
     * @brief Type conversion function.
     *
     * @return Returns the int64_t type ValueObject.
     */
    operator int64_t () const
    {
        return std::get<int64_t>(value);
    }
    /**
     * @brief Type conversion function.
     *
     * @return Returns the double type ValueObject.
     */
    operator double () const
    {
        return std::get<double>(value);
    }
    /**
     * @brief Type conversion function.
     *
     * @return Returns the bool type ValueObject.
     */
    operator bool () const
    {
        return std::get<bool>(value);
    }
    /**
     * @brief Type conversion function.
     *
     * @return Returns the string type ValueObject.
     */
    operator std::string () const
    {
        return std::get<std::string>(value);
    }
    /**
     * @brief Type conversion function.
     *
     * @return Returns the vector<uint8_t> type ValueObject.
     */
    operator std::vector<uint8_t> () const
    {
        return std::get<std::vector<uint8_t>>(value);
    }
    /**
     * @brief Type conversion function.
     *
     * @return Returns the Type type ValueObject.
     */
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
