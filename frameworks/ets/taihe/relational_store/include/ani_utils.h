/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ANI_UTILS_H
#define ANI_UTILS_H

#include <ani.h>

#include <cstdarg>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace ani_utils {
enum class ErrorHandling {
    STRICT,  // Strict mode: All errors are returned.
    OPTIONAL // Optional mode: Only handle 'ANID_NOT_SFOUND' errors.
};

ani_status AniGetProperty(ani_env *env, ani_object ani_obj, const char *property, std::string &result,
    ErrorHandling handling = ErrorHandling::STRICT);

ani_status AniGetProperty(ani_env *env, ani_object ani_obj, const char *property, bool &result,
    ErrorHandling handling = ErrorHandling::STRICT);

ani_status AniGetProperty(ani_env *env, ani_object ani_obj, const char *property, int32_t &result,
    ErrorHandling handling = ErrorHandling::STRICT);

ani_status GetEnumValueInt(ani_env *env, ani_object ani_obj, const char *property, int32_t &result,
    ErrorHandling handling = ErrorHandling::STRICT);

ani_status AniGetProperty(ani_env *env, ani_object ani_obj, const char *property, uint32_t &result,
    ErrorHandling handling = ErrorHandling::STRICT);

ani_status AniGetProperty(ani_env *env, ani_object ani_obj, const char *property, ani_object &result,
    ErrorHandling handling = ErrorHandling::STRICT);

class AniObjectUtils {
public:
    template<typename T>
    static ani_status Wrap(ani_env *env, ani_object object, T *nativePtr, const char *propName = "nativePtr")
    {
        return env->Object_SetFieldByName_Long(object, propName, reinterpret_cast<ani_long>(nativePtr));
    }

    template<typename T>
    static T *Unwrap(ani_env *env, ani_object object, const char *propName = "nativePtr")
    {
        ani_long nativePtr = 0;
        if (ANI_OK != env->Object_GetFieldByName_Long(object, propName, &nativePtr)) {
            return nullptr;
        }
        return reinterpret_cast<T *>(nativePtr);
    }
};

class AniStringUtils {
public:
    static std::string ToStd(ani_env *env, ani_string ani_str);
    static ani_string ToAni(ani_env *env, const std::string &str);
};

class UnionAccessor {
public:
    UnionAccessor(ani_env *env, ani_object &obj) : env_(env), obj_(obj)
    {
    }

    bool IsInstanceOf(const std::string &cls_name)
    {
        ani_class cls;
        auto status = env_->FindClass(cls_name.c_str(), &cls);
        if (status != ANI_OK) {
            return false;
        }

        ani_boolean ret = false;
        status = env_->Object_InstanceOf(obj_, cls, &ret);
        if (status != ANI_OK) {
            return false;
        }
        return ret;
    }

    template<typename T>
    bool IsInstanceOfType();

    template<typename T>
    bool TryConvert(T &value);

    template<typename... Types>
    bool TryConvertVariant(std::variant<Types...> &value)
    {
        return GetNativeValue<decltype(value), Types...>(value);
    }

    template<typename T>
    bool GetNativeValue(T &value)
    {
        return false;
    }

    template<typename T, typename First, typename... Types>
    bool GetNativeValue(T &value)
    {
        First cValue;
        auto ret = TryConvert(cValue);
        if (ret == true) {
            value = cValue;
            return ret;
        }
        return GetNativeValue<T, Types...>(value);
    }

    template<typename T>
    bool TryConvertArray(std::vector<T> &value);

    bool GetObjectRefPropertyByName(const std::string &clsName, const char *name, ani_ref &val);
    bool GetObjectStringPropertyByName(const std::string &clsName, const char *name, std::string &val);
    bool GetObjectEnumValuePropertyByName(const std::string &clsName, const char *name, ani_int &val);
    ani_ref AniIteratorNext(ani_ref interator, bool &isSuccess);

private:
    ani_env *env_;
    ani_object obj_;
};

class OptionalAccessor {
public:
    OptionalAccessor(ani_env *env, ani_object &obj) : env_(env), obj_(obj)
    {
    }

    bool IsUndefined()
    {
        ani_boolean isUndefined = false;
        env_->Reference_IsUndefined(obj_, &isUndefined);
        return isUndefined;
    }

    template<typename T>
    std::optional<T> Convert();

private:
    ani_env *env_;
    ani_object obj_;
};

class PropertyErrorHandler {
public:
    static ani_status HandleError(
        ani_status status, const char *property, ErrorHandling handling, const char *type_name);

private:
    static ani_status HandleNotFound(const char *property, ErrorHandling handling, const char *type_name);
    static ani_status HandleSystemError(ani_status status, const char *property, const char *type_name);
};

template<typename T>
constexpr const char *GetTypeName()
{
    return "unknown";
}

template<>
constexpr const char *GetTypeName<bool>()
{
    return "bool";
}

template<>
constexpr const char *GetTypeName<int32_t>()
{
    return "int32";
}

template<>
constexpr const char *GetTypeName<uint32_t>()
{
    return "uint32";
}

template<>
constexpr const char *GetTypeName<ani_object>()
{
    return "object";
}

template<>
constexpr const char *GetTypeName<ani_enum_item>()
{
    return "ani_enum_item";
}

template<typename NativeType, typename AniType>
ani_status AniGetPropertyImpl(ani_env *env, ani_object ani_obj, const char *property, NativeType &result,
    ErrorHandling handling, ani_status (ani_env::*getter)(ani_object, const char *, AniType *))
{
    if (getter == nullptr) {
        return ANI_INVALID_ARGS;
    }

    if (env == nullptr) {
        return ANI_INVALID_ARGS;
    }
    AniType ani_value;
    ani_status status = (env->*getter)(ani_obj, property, &ani_value);

    if (status != ANI_OK) {
        return HandlePropertyError(status, property, handling, GetTypeName<NativeType>());
    }

    result = static_cast<NativeType>(ani_value);
    return ANI_OK;
}
} //namespace ani_utils
#endif
