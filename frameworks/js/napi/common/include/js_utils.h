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

#include <stdint.h>

#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <variant>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppDataMgrJsKit {
namespace JSUtils {
#define DECLARE_JS_PROPERTY(env, key, value) \
    napi_property_descriptor(DECLARE_NAPI_DEFAULT_PROPERTY((key), Convert2JSValue((env), (value))))

#define ASSERT(condition, message, retVal)                       \
    do {                                                         \
        if (!(condition)) {                                      \
            LOG_ERROR("test (" #condition ") failed: " message); \
            return retVal;                                       \
        }                                                        \
    } while (0)
static constexpr int OK = 0;
static constexpr int ERR = -1;
static constexpr uint32_t ASYNC_RST_SIZE = 2;
static constexpr uint32_t DEFAULT_VALUE_LENGTH = 1024;
static constexpr uint32_t MAX_VALUE_LENGTH = 1024 * 1024 * 8; // the max length of all kand of out string value
static constexpr uint32_t SYNC_RESULT_ELEMENT_NUM = 2;
struct JsFeatureSpace {
    const char *spaceName;
    const char *nameBase64;
    bool isComponent;
};

void SetHapVersion(int32_t hapversion);
int32_t GetHapVersion();

int32_t Convert2Value(napi_env env, napi_value jsValue, napi_value &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, bool &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, double &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, int64_t &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::string &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::vector<uint8_t> &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::vector<float> &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::monostate &value);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, int32_t> &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, bool> &output);

bool IsNull(napi_env env, napi_value value);

bool Equal(napi_env env, napi_ref ref, napi_value value);

template<typename T>
int32_t Convert2Value(napi_env env, napi_value jsValue, T &output);

template<typename T>
int32_t Convert2ValueExt(napi_env env, napi_value jsValue, T &output);

int32_t Convert2ValueExt(napi_env env, napi_value jsValue, uint32_t &output);
int32_t Convert2ValueExt(napi_env env, napi_value jsValue, int32_t &output);
int32_t Convert2ValueExt(napi_env env, napi_value jsValue, int64_t &output);

template<typename T>
int32_t Convert2Value(napi_env env, napi_value jsValue, std::vector<T> &value);

template<typename T>
int32_t Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, T> &value);

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

napi_value Convert2JSValue(napi_env env, const std::string &value);
napi_value Convert2JSValue(napi_env env, const std::vector<uint8_t> &value);
napi_value Convert2JSValue(napi_env env, const std::vector<float> &value);
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

template<typename T>
napi_value Convert2JSValue(napi_env env, const std::tuple<int32_t, std::string, T> &value);

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

std::pair<napi_status, napi_value> GetInnerValue(napi_env env, napi_value in, const std::string &prop, bool optional);

template<typename T>
inline std::enable_if_t<std::is_same_v<T, int32_t> || std::is_same_v<T, uint32_t>, int32_t> GetNamedProperty(
    napi_env env, napi_value in, const std::string &prop, T &value, bool optional = false)
{
    auto [status, jsValue] = GetInnerValue(env, in, prop, optional);
    if (jsValue == nullptr) {
        return status;
    }
    return Convert2ValueExt(env, jsValue, value);
};

template<typename T>
inline std::enable_if_t<!std::is_same_v<T, int32_t> && !std::is_same_v<T, uint32_t>, int32_t> GetNamedProperty(
    napi_env env, napi_value in, const std::string &prop, T &value, bool optional = false)
{
    auto [status, jsValue] = GetInnerValue(env, in, prop, optional);
    if (jsValue == nullptr) {
        return status;
    }
    return Convert2Value(env, jsValue, value);
};

template<typename T>
inline int32_t SetNamedProperty(napi_env env, napi_value in, const std::string &prop, T value)
{
    return napi_set_named_property(env, in, prop.c_str(), Convert2JSValue(env, value));
};

napi_value ToJsObject(napi_env env, napi_value sendableValue);
napi_value ToJsArray(napi_env env, napi_value sendableValue);
napi_value ToJsTypedArray(napi_env env, napi_value sendableValue);
napi_value Convert2JSValue(napi_env env, napi_value sendableValue);
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

template<typename T>
int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, T> &value)
{
    napi_value jsMapList = nullptr;
    uint32_t jsCount = 0;
    napi_status status = napi_get_property_names(env, jsValue, &jsMapList);
    if (status != napi_ok) {
        return napi_invalid_arg;
    }
    status = napi_get_array_length(env, jsMapList, &jsCount);
    if (status != napi_ok || jsCount <= 0) {
        return napi_invalid_arg;
    }
    napi_value jsKey = nullptr;
    napi_value jsVal = nullptr;
    for (uint32_t index = 0; index < jsCount; index++) {
        status = napi_get_element(env, jsMapList, index, &jsKey);
        if (status != napi_ok) {
            return napi_invalid_arg;
        }
        std::string key;
        int ret = Convert2Value(env, jsKey, key);
        if (status != napi_ok) {
            return napi_invalid_arg;
        }
        status = napi_get_property(env, jsValue, jsKey, &jsVal);
        if (status != napi_ok || jsVal == nullptr) {
            return napi_invalid_arg;
        }
        T val;
        ret = Convert2Value(env, jsVal, val);
        if (status != napi_ok) {
            return napi_invalid_arg;
        }
        value.insert(std::pair<std::string, T>(key, val));
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

template<typename T>
napi_value JSUtils::Convert2JSValue(napi_env env, const std::tuple<int32_t, std::string, T> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_object(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    napi_value code = Convert2JSValue(env, std::get<0>(value));
    napi_value description = Convert2JSValue(env, std::get<1>(value));
    napi_value val = Convert2JSValue(env, std::get<2>(value));
    if (description == nullptr || val == nullptr) {
        return nullptr;
    }
    napi_set_named_property(env, jsValue, "code", code);
    napi_set_named_property(env, jsValue, "description", description);
    napi_set_named_property(env, jsValue, "value", val);
    return jsValue;
}

template<typename... Types>
int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::variant<Types...> &value)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok) {
        return napi_invalid_arg;
    }
    if (type == napi_undefined) {
        return napi_generic_failure;
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