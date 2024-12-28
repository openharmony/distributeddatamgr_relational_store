/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTEDDATAMGR_APPDATAMGR_JS_SENDABLE_UTILS_H
#define DISTRIBUTEDDATAMGR_APPDATAMGR_JS_SENDABLE_UTILS_H

#include <cstdint>

#include "js_native_api.h"
#include "js_utils.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppDataMgrJsKit {
namespace JSUtils {
#define DECLARE_SENDABLE_PROPERTY(env, key, value) \
    napi_property_descriptor(DECLARE_NAPI_DEFAULT_PROPERTY((key), Convert2Sendable((env), (value))))

int32_t Convert2Sendable(napi_env env, std::string value, napi_value &output);
int32_t Convert2Sendable(napi_env env, bool value, napi_value &output);
int32_t Convert2Sendable(napi_env env, double value, napi_value &output);

napi_value Convert2Sendable(napi_env env, const std::string &value);
napi_value Convert2Sendable(napi_env env, const std::vector<uint8_t> &value);
napi_value Convert2Sendable(napi_env env, const std::vector<float> &value);
napi_value Convert2Sendable(napi_env env, int32_t value);
napi_value Convert2Sendable(napi_env env, uint32_t value);
napi_value Convert2Sendable(napi_env env, int64_t value);
napi_value Convert2Sendable(napi_env env, double value);
napi_value Convert2Sendable(napi_env env, bool value);
napi_value Convert2Sendable(napi_env env, const std::monostate &value);
napi_value Convert2Sendable(napi_env env, const std::nullptr_t &value);

template<typename T>
napi_value Convert2Sendable(napi_env env, const T &value);

template<typename T>
napi_value Convert2Sendable(napi_env env, const std::vector<T> &value);

template<typename K, typename V>
napi_value Convert2Sendable(napi_env env, const std::map<K, V> &value);

template<typename K, typename V>
napi_value Convert2Sendable(napi_env env, const std::unordered_map<K, V> &value);

template<typename... Types>
napi_value Convert2Sendable(napi_env env, const std::variant<Types...> &value);

template<typename T>
napi_value GetSendableValue(napi_env env, const T &value)
{
    return nullptr;
}

template<typename T, typename First, typename... Types>
napi_value GetSendableValue(napi_env env, const T &value)
{
    auto *val = std::get_if<First>(&value);
    if (val != nullptr) {
        return Convert2Sendable(env, *val);
    }
    return GetSendableValue<T, Types...>(env, value);
}

napi_value ToSendableObject(napi_env env, napi_value jsValue);
napi_value ToSendableArray(napi_env env, napi_value jsValue);
napi_value ToSendableTypedArray(napi_env env, napi_value jsValue);
napi_value Convert2Sendable(napi_env env, napi_value jsValue);
} // namespace JSUtils

template<typename T>
napi_value JSUtils::Convert2Sendable(napi_env env, const std::vector<T> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_sendable_array_with_length(env, value.size(), &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    for (size_t i = 0; i < value.size(); ++i) {
        napi_set_element(env, jsValue, i, Convert2Sendable(env, value[i]));
    }
    return jsValue;
}

template<typename K, typename V>
napi_value JSUtils::Convert2Sendable(napi_env env, const std::map<K, V> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_sendable_map(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    for (const auto &[key, val] : value) {
        napi_value jsKey = Convert2Sendable(env, key);
        status = napi_map_set_property(env, jsValue, jsKey, Convert2Sendable(env, val));
        if (status != napi_ok) {
            return nullptr;
        }
    }
    return jsValue;
}

template<typename K, typename V>
napi_value JSUtils::Convert2Sendable(napi_env env, const std::unordered_map<K, V> &value)
{
    napi_value jsValue;
    napi_status status = napi_create_sendable_map(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    for (const auto &[key, val] : value) {
        napi_value jsKey = Convert2Sendable(env, key);
        status = napi_map_set_property(env, jsValue, jsKey, Convert2Sendable(env, val));
        if (status != napi_ok) {
            return nullptr;
        }
    }
    return jsValue;
}

template<typename... Types>
napi_value JSUtils::Convert2Sendable(napi_env env, const std::variant<Types...> &value)
{
    return GetSendableValue<decltype(value), Types...>(env, value);
}
} // namespace AppDataMgrJsKit
} // namespace OHOS
#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_JS_SENDABLE_UTILS_H