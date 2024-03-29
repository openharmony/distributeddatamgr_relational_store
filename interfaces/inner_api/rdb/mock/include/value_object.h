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
#include "big_integer.h"
#include "asset_value.h"
namespace OHOS {
namespace NativeRdb {
/**
 * The ValueObject class of RDB.
 */
class ValueObject {
public:
    /**
     * @brief Use Type replace std::variant.
     */
    using Nil = std::monostate;
    using Blob = std::vector<uint8_t>;
    using Asset = AssetValue;
    using Assets = std::vector<Asset>;
    using BigInt = BigInteger;
    using Type = std::variant<Nil, int64_t, double, std::string, bool, Blob, Asset, Assets, BigInt>;
    template<typename Tp, typename... Types>
    struct index_of : std::integral_constant<size_t, 0> {};

    template<typename Tp, typename... Types>
    inline static constexpr size_t index_of_v = index_of<Tp, Types...>::value;

    template<typename Tp, typename First, typename... Rest>
    struct index_of<Tp, First, Rest...>
        : std::integral_constant<size_t, std::is_same_v<Tp, First> ? 0 : index_of_v<Tp, Rest...> + 1> {};

    template<typename... Types>
    struct variant_size_of {
        static constexpr size_t value = sizeof...(Types);
    };

    template<typename T, typename... Types>
    struct variant_index_of {
        static constexpr size_t value = index_of_v<T, Types...>;
    };

    template<typename... Types>
    static variant_size_of<Types...> variant_size_test(const std::variant<Types...> &);

    template<typename T, typename... Types>
    static variant_index_of<T, Types...> variant_index_test(const T &, const std::variant<Types...> &);

    template<typename T>
    inline constexpr static int32_t TYPE_INDEX =
        decltype(variant_index_test(std::declval<T>(), std::declval<Type>()))::value;

    inline constexpr static int32_t TYPE_MAX = decltype(variant_size_test(std::declval<Type>()))::value;

    /**
     * @brief Indicates the ValueObject {@link ValueObject} type.
     * */
    enum TypeId : int32_t {
        /** Indicates the ValueObject type is NULL.*/
        TYPE_NULL = TYPE_INDEX<Nil>,
        /** Indicates the ValueObject type is int.*/
        TYPE_INT = TYPE_INDEX<int64_t>,
        /** Indicates the ValueObject type is double.*/
        TYPE_DOUBLE = TYPE_INDEX<double>,
        /** Indicates the ValueObject type is string.*/
        TYPE_STRING = TYPE_INDEX<std::string>,
        /** Indicates the ValueObject type is bool.*/
        TYPE_BOOL = TYPE_INDEX<bool>,
        /** Indicates the ValueObject type is blob.*/
        TYPE_BLOB = TYPE_INDEX<Blob>,
        /** Indicates the ValueObject type is asset.*/
        TYPE_ASSET = TYPE_INDEX<Asset>,
        /** Indicates the ValueObject type is assets.*/
        TYPE_ASSETS = TYPE_INDEX<Assets>,
        /** Indicates the ValueObject type is bigint.*/
        TYPE_BIGINT = TYPE_INDEX<BigInt>,
        /** the BUTT.*/
        TYPE_BUTT = TYPE_MAX
    };
    Type value;

    /**
     * @brief convert a std::variant input to another std::variant output with different (..._Types)
     */
    template<typename T>
    static inline std::enable_if_t<(TYPE_INDEX<T>) < TYPE_MAX, const char *> DeclType()
    {
        return DECLARE_TYPES[TYPE_INDEX<T>];
    }
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
    ValueObject(Type val) noexcept;

    /**
     * @brief Move constructor.
     */
    ValueObject(ValueObject &&val) noexcept;

    /**
     * @brief Copy constructor.
     */
    ValueObject(const ValueObject &val);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int input parameter to a value of type ValueObject.
     *
     * @param val Indicates an int input parameter.
     */
    ValueObject(int32_t val);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the int64_t input parameter to a value of type ValueObject.
     *
     * @param val Indicates an int64_t input parameter.
     */
    ValueObject(int64_t val);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the double input parameter to a value of type ValueObject.
     *
     * @param val Indicates an double input parameter.
     */
    ValueObject(double val);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the bool input parameter to a value of type ValueObject.
     *
     * @param val Indicates an bool input parameter.
     */
    ValueObject(bool val);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the string input parameter to a value of type ValueObject.
     *
     * @param val Indicates an string input parameter.
     */
    ValueObject(std::string val);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the const char * input parameter to a value of type ValueObject.
     *
     * @param val Indicates an const char * input parameter.
     */
    ValueObject(const char *val);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the vector<uint8_t> input parameter to a value of type ValueObject.
     *
     * @param val Indicates an vector<uint8_t> input parameter.
     */
    ValueObject(const std::vector<uint8_t> &blob);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the Asset input parameter to a value of type ValueObject.
     *
     * @param val Indicates an Asset input parameter.
     */
    ValueObject(Asset val);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the Assets input parameter to a value of type ValueObject.
     *
     * @param val Indicates an Assets input parameter.
     */
    ValueObject(Assets val);

    /**
     * @brief Constructor.
     *
     * This constructor is used to convert the Assets input parameter to a value of type ValueObject.
     *
     * @param val Indicates an Assets input parameter.
     */
    API_EXPORT ValueObject(BigInt val);

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
    TypeId GetType() const;

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
     * @brief Obtains the vector<uint8_t> value in this {@code ValueObject} object.
     */
    int GetAsset(Asset &val) const;

    /**
     * @brief Obtains the vector<uint8_t> value in this {@code ValueObject} object.
     */
    int GetAssets(Assets &val) const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns the int type ValueObject.
     */
    operator int() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns the int64_t type ValueObject.
     */
    operator int64_t() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns the double type ValueObject.
     */
    operator double() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns the bool type ValueObject.
     */
    operator bool() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns the string type ValueObject.
     */
    operator std::string() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns the vector<uint8_t> type ValueObject.
     */
    operator Blob() const;

    /**
     * @brief Type conversion function.
     *
     * @return Returns the vector<uint8_t> type ValueObject.
     */
    operator Asset() const;

    /**
    * @brief Type conversion function.
    *
    * @return Returns the vector<uint8_t> type ValueObject.
    */
    operator Assets() const;

    /**
    * @brief Type conversion function.
    *
    * @return Returns the BigInt type ValueObject.
    */
    operator BigInt() const;

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
    template<class T>
    int Get(T &output) const;
    static constexpr const char *DECLARE_TYPES[TypeId::TYPE_BUTT] = {
        /** Indicates the ValueObject type is NULL.*/
        "",
        /** Indicates the ValueObject type is int.*/
        "INT",
        /** Indicates the ValueObject type is double.*/
        "REAL",
        /** Indicates the ValueObject type is string.*/
        "TEXT",
        /** Indicates the ValueObject type is bool.*/
        "INT",
        /** Indicates the ValueObject type is blob.*/
        "BLOB",
        /** Indicates the ValueObject type is asset.*/
        "ASSET",
        /** Indicates the ValueObject type is assets.*/
        "ASSETS",
        /** Indicates the ValueObject type is bigint.*/
        "BIGINT"
    };
};
using ValueObjectType = ValueObject::TypeId;
} // namespace NativeRdb
} // namespace OHOS
#endif
