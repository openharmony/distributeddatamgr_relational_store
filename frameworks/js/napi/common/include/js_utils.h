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

#ifndef DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H
#define DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H

#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>
#include <optional>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppDataMgrJsKit {
namespace JSUtils {
constexpr int OK = 0;
constexpr int ERR = -1;
constexpr uint32_t ASYNC_RST_SIZE = 2;
constexpr uint32_t DEFAULT_VALUE_LENGTH = 1024;
constexpr uint32_t MAX_VALUE_LENGTH = 1024 * 1024 * 8; // the max length of all kand of out string value
constexpr uint32_t SYNC_RESULT_ELEMENT_NUM = 2;
struct JsFeatureSpace {
    const char* spaceName;
    const char* nameBase64;
    bool isComponent;
};

#ifndef ADD_JS_PROPERTY
#define ADD_JS_PROPERTY(env, object, value, member) \
    napi_set_named_property((env), (object), #member, Convert2JSValue((env), (value).member))
#endif

#ifndef GET_PROPERTY
#define GET_PROPERTY(env, object, value, member) \
    Convert2Value((env), GetNamedProperty((env), (object), #member), (value).member)
#endif

napi_value GetNamedProperty(napi_env env, napi_value object, const char *name);

int32_t Convert2ValueExt(napi_env env, napi_value jsValue, uint32_t &output);
int32_t Convert2ValueExt(napi_env env, napi_value jsValue, int32_t &output);
int32_t Convert2ValueExt(napi_env env, napi_value jsValue, int64_t &output);

int32_t Convert2Value(napi_env env, napi_value jsValue, bool &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, double &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, int64_t &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::string &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::vector<uint8_t> &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::monostate &value);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, int32_t> &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, bool> &output);

bool IsNull(napi_env env, napi_value value);

template<typename T>
int32_t Convert2Value(napi_env env, napi_value jsValue, T &output);

template<typename T>
int32_t Convert2Value(napi_env env, napi_value jsValue, std::vector<T> &value);

template<typename... Types>
int32_t Convert2Value(napi_env env, napi_value jsValue, std::variant<Types...> &value);

using Descriptor = std::function<std::vector<napi_property_descriptor>()>;
const std::optional<JsFeatureSpace> GetJsFeatureSpace(const std::string &name);
/* napi_define_class  wrapper */
napi_value DefineClass(napi_env env, const std::string &spaceName, const std::string &className,
    const Descriptor &descriptor, napi_callback ctor);
napi_value GetClass(napi_env env, const std::string &spaceName, const std::string &className);
std::string Convert2String(napi_env env, napi_value jsStr);

int32_t Convert2JSValue(napi_env env, std::string value, napi_value &output);
int32_t Convert2JSValue(napi_env env, bool value, napi_value &output);
int32_t Convert2JSValue(napi_env env, double value, napi_value &output);

napi_value Convert2JSValue(napi_env env, const std::vector<std::string> &value);
napi_value Convert2JSValue(napi_env env, const std::string &value);
napi_value Convert2JSValue(napi_env env, const std::vector<uint8_t> &value);
napi_value Convert2JSValue(napi_env env, int32_t value);
napi_value Convert2JSValue(napi_env env, uint32_t value);
napi_value Convert2JSValue(napi_env env, int64_t value);
napi_value Convert2JSValue(napi_env env, double value);
napi_value Convert2JSValue(napi_env env, bool value);
napi_value Convert2JSValue(napi_env env, const std::map<std::string, int> &value);
napi_value Convert2JSValue(napi_env env, const std::monostate &value);

template<typename T>
napi_value Convert2JSValue(napi_env env, const T &value);

template<typename T>
napi_value Convert2JSValue(napi_env env, const std::vector<T> &value);

template<typename K, typename V>
napi_value Convert2JSValue(napi_env env, const std::map<K, V> &value);

template<typename... Types>
napi_value Convert2JSValue(napi_env env, const std::variant<Types...> &value);

template<typename T>
std::string ToString(const T &key);

template<typename K>
std::enable_if_t<!std::is_same_v<K, std::string>, std::string> ConvertMapKey(const K &key)
{
    return ToString(key);
}

template<typename K>
std::enable_if_t<std::is_same_v<K, std::string>, const std::string &> ConvertMapKey(const K &key)
{
    return key;
}

template<typename T>
int32_t GetCPPValue(napi_env env, napi_value jsValue, T &value)
{
    return napi_invalid_arg;
}

template<typename T, typename First, typename... Types>
int32_t GetCPPValue(napi_env env, napi_value jsValue, T &value)
{
    First cValue;
    auto ret = Convert2Value(env, jsValue, cValue);
    if (ret == napi_ok) {
        value = cValue;
        return ret;
    }
    return GetCPPValue<T, Types...>(env, jsValue, value);
}

template<typename T>
napi_value GetJSValue(napi_env env, const T &value)
{
    return nullptr;
}

template<typename T, typename First, typename... Types>
napi_value GetJSValue(napi_env env, const T &value)
{
    auto *val = std::get_if<First>(&value);
    if (val != nullptr) {
        return Convert2JSValue(env, *val);
    }
    return GetJSValue<T, Types...>(env, value);
}
} // namespace JSUtils

template<typename T>
int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::vector<T> &value)
{
    bool isArray = false;
    napi_is_array(env, jsValue, &isArray);
    if (!isArray) {
        return napi_invalid_arg;
    }

    uint32_t arrLen = 0;
    napi_get_array_length(env, jsValue, &arrLen);
    if (arrLen == 0) {
        return napi_ok;
    }

    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element;
        napi_get_element(env, jsValue, i, &element);
        T item;
        auto status = Convert2Value(env, element, item);
        if (status != napi_ok) {
            return napi_invalid_arg;
        }
        value.push_back(std::move(item));
    }
    return napi_ok;
}

template<typename K, typename V>
napi_value JSUtils::Convert2JSValue(napi_env env, const std::map<K, V> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_object(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    for (const auto &[key, val] : value) {
        const std::string &name = ConvertMapKey(key);
        status = napi_set_named_property(env, jsValue, name.c_str(), Convert2JSValue(env, val));
        if (status != napi_ok) {
            return nullptr;
        }
    }
    return jsValue;
}

template<typename... Types>
int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::variant<Types...> &value)
{
    napi_valuetype type;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type == napi_undefined) {
        return napi_invalid_arg;
    }
    return GetCPPValue<decltype(value), Types...>(env, jsValue, value);
}

template<typename T>
napi_value JSUtils::Convert2JSValue(napi_env env, const std::vector<T> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_array_with_length(env, value.size(), &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    for (size_t i = 0; i < value.size(); ++i) {
        napi_set_element(env, jsValue, i, Convert2JSValue(env, value[i]));
    }
    return jsValue;
}

template<typename... Types>
napi_value JSUtils::Convert2JSValue(napi_env env, const std::variant<Types...> &value)
{
    return GetJSValue<decltype(value), Types...>(env, value);
}
} // namespace AppDataMgrJsKit
} // namespace OHOS
#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H
