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
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>
#include <iostream>

class AniObjectUtils {
public:
    static ani_object Create(ani_env *env, const char *nsName, const char *clsName, ...)
    {
        ani_object nullobj{};

        if (env == nullptr) {
            return nullobj;
        }

        ani_class cls;
        const std::string fullClsName = std::string(nsName) + "." + clsName;
        if (ANI_OK != env->FindClass(fullClsName.c_str(), &cls)) {
            std::cerr << "[ANI] Not found class " << fullClsName << std::endl;
            return nullobj;
        }

        ani_method ctor;
        if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
            return nullobj;
        }

        ani_object obj;
        va_list args;
        va_start(args, clsName);
        ani_status status = env->Object_New_V(cls, ctor, &obj, args);
        va_end(args);
        if (ANI_OK != status)  {
            return nullobj;
        }
        return obj;
    }

    static ani_object Create(ani_env *env, const char *clsName, ...)
    {
        ani_object nullobj{};

        if (env == nullptr) {
            return nullobj;
        }

        ani_class cls;
        if (ANI_OK != env->FindClass(clsName, &cls)) {
            return nullobj;
        }

        ani_method ctor;
        if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
            return nullobj;
        }

        ani_object obj;
        va_list args;
        va_start(args, clsName);
        ani_status status = env->Object_New_V(cls, ctor, &obj, args);
        va_end(args);
        if (ANI_OK != status) {
            return nullobj;
        }
        return obj;
    }

    static ani_object Create(ani_env *env, ani_class cls, ...)
    {
        ani_object nullobj{};

        if (env == nullptr) {
            return nullobj;
        }

        ani_method ctor;
        if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
            return nullobj;
        }

        ani_object obj;
        va_list args;
        va_start(args, cls);
        ani_status status = env->Object_New_V(cls, ctor, &obj, args);
        va_end(args);
        if (ANI_OK != status) {
            return nullobj;
        }
        return obj;
    }

    static ani_status CallObjMethod(ani_env *env, const char *ns, const char *cls, const char *method, ani_object obj)
    {
        if (env == nullptr) {
            return ANI_ERROR;
        }

        ani_class clazz;
        const std::string fullClsName = std::string(ns) + "." + cls;
        status = env->FindClass(fullClsName.c_str(), &clazz);
        if (status != ANI_OK) {
            std::cerr << "[ANI] Not found class " << fullClsName << std::endl;
            return status;
        }

        ani_method objMethod;
        status = env->Class_FindMethod(clazz, method, ":V", &objMethod);
        if (status != ANI_OK) {
            return status;
        }
        status = env->Object_CallMethod_Void(obj, objMethod);
        return status;
    }

    template<typename T>
    static ani_status Wrap(ani_env *env, ani_object object, T *nativePtr, const char *propName = "nativePtr")
    {
        return env->Object_SetFieldByName_Long(object, propName, reinterpret_cast<ani_long>(nativePtr));
    }

    template<typename T>
    static T* Unwrap(ani_env *env, ani_object object, const char *propName = "nativePtr")
    {
        ani_long nativePtr;
        if (ANI_OK != env->Object_GetFieldByName_Long(object, propName, &nativePtr)) {
            return nullptr;
        }
        return reinterpret_cast<T*>(nativePtr);
    }
};

class AniStringUtils {
public:
    static std::string ToStd(ani_env *env, ani_string ani_str)
    {
        if (env == nullptr) {
            return std::string();
        }

        ani_size strSize = 0;
        auto status = env->String_GetUTF8Size(ani_str, &strSize);
        if (ANI_OK != status) {
            return std::string();
        }

        std::vector<char> buffer(strSize + 1); // +1 for null terminator
        char *utf8Buffer = buffer.data();

        // String_GetUTF8 Supportted by https://gitee.com/openharmony/arkcompiler_runtime_core/pulls/3416
        ani_size bytesWritten = 0;
        status = env->String_GetUTF8(ani_str, utf8Buffer, strSize + 1, &bytesWritten);
        if (ANI_OK != status) {
            return std::string();
        }

        utf8Buffer[bytesWritten] = '\0';
        std::string content = std::string(utf8Buffer);
        return content;
    }

    static ani_string ToAni(ani_env *env, const std::string& str)
    {
        if (env == nullptr) {
            return nullptr;
        }
        ani_string aniStr = nullptr;
        if (ANI_OK != env->String_NewUTF8(str.data(), str.size(), &aniStr)) {
            return nullptr;
        }
        return aniStr;
    }
};

class UnionAccessor {
public:
    UnionAccessor(ani_env *env, ani_object &obj) : env_(env), obj_(obj)
    {
    }

    bool IsInstanceOf(const std::string& cls_name)
    {
        ani_class cls;
        env_->FindClass(cls_name.c_str(), &cls);

        ani_boolean ret;
        env_->Object_InstanceOf(obj_, cls, &ret);
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

    bool GetObjectRefPropertyByName(std::string clsName, const char *name, ani_ref &val);
    bool GetObjectStringPropertyByName(std::string clsName, const char *name, std::string &val);
    bool GetObjectEnumValuePropertyByName(std::string clsName, const char *name, ani_int &val, bool optional = false);
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
        ani_boolean isUndefined;
        env_->Reference_IsUndefined(obj_, &isUndefined);
        return isUndefined;
    }

    template<typename T>
    std::optional<T> Convert();

private:
    ani_env *env_;
    ani_object obj_;
};

class NativeObject {
public:
    virtual ~NativeObject() = default;
};

ani_status CleanerInit(ani_env *env);
#endif
