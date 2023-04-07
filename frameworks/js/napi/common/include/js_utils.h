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

#include <iostream>
#include <map>
#include <string>
#include <variant>
#include <vector>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppDataMgrJsKit {
namespace JSUtils {
constexpr int OK = 0;
constexpr int ERR = -1;
constexpr int32_t DEFAULT_BUF_SIZE = 1024;
// 1 is the margin
constexpr int32_t BUF_CACHE_MARGIN = 4 + 1;
constexpr int32_t ASYNC_RST_SIZE = 2;
constexpr int32_t MAX_VALUE_LENGTH = 8 * 1024;
constexpr int32_t SYNC_RESULT_ELEMNT_NUM = 2;

std::string Convert2String(napi_env env, napi_value jsStr, bool useDefaultBufSize = true);
int32_t Convert2Value(napi_env env, napi_value jsBool, bool &output);
int32_t Convert2Value(napi_env env, napi_value jsNum, double &output);
int32_t Convert2Value(napi_env env, napi_value jsStr, std::string &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::vector<uint8_t> &output);
std::vector<std::string> Convert2StrVector(napi_env env, napi_value value);
std::vector<uint8_t> Convert2U8Vector(napi_env env, napi_value jsValue);
std::string ConvertAny2String(napi_env env, napi_value jsValue);

template<typename T>
int32_t Convert2Value(napi_env env, napi_value jsValue, T &output);
template<typename T>
int32_t Convert2Value(napi_env env, napi_value jsValue, std::vector<T> &value);
template<typename... _Types>
int32_t Convert2Value(napi_env env, napi_value jsValue, const std::variant<_Types...> &value);

template<typename... _Types>
napi_value Convert2JSValue(napi_env env, const std::variant<_Types...> &value);

int32_t Convert2JSValue(napi_env env, std::string value, napi_value &output);
int32_t Convert2JSValue(napi_env env, bool value, napi_value &output);
int32_t Convert2JSValue(napi_env env, double value, napi_value &output);

napi_value Convert2JSValue(napi_env env, const std::vector<std::string> &value);
napi_value Convert2JSValue(napi_env env, const std::string &value);
napi_value Convert2JSValue(napi_env env, const std::vector<uint8_t> &value);
napi_value Convert2JSValue(napi_env env, int32_t value);
napi_value Convert2JSValue(napi_env env, int64_t value);
napi_value Convert2JSValue(napi_env env, double value);
napi_value Convert2JSValue(napi_env env, bool value);
napi_value Convert2JSValue(napi_env env, const std::map<std::string, int> &value);
napi_value Convert2JSValue(napi_env env, const std::monostate &value);
template<typename T>
napi_value Convert2JSValue(napi_env env, const T &value);
template<typename T>
napi_value Convert2JSValue(napi_env env, const std::vector<T> &value);

template<typename... _Types>
napi_value Convert2JSValue(napi_env env, const std::variant<_Types...> &value);

template<typename _T>
int32_t GetCPPValue(napi_env env, napi_value jsValue, _T &value)
{
    return napi_invalid_arg;
}

template<typename _T, typename _First, typename... _Types>
int32_t GetCPPValue(napi_env env, napi_value jsValue, _T &value)
{
    _First cValue;
    auto ret = Convert2Value(env, jsValue, cValue);
    if (ret != napi_invalid_arg) {
        if (ret == napi_ok) {
            value = cValue;
        }
        return ret;
    }
    return GetCPPValue<_T, _Types...>(env, jsValue, value);
}

template<typename _T>
napi_value GetJSValue(napi_env env, const _T &value)
{
    return nullptr;
}

template<typename _T, typename _First, typename... _Types>
napi_value GetJSValue(napi_env env, const _T &value)
{
    auto *val = std::get_if<_First>(&value);
    if (val == nullptr) {
        return Convert2JSValue(env, *val);
    }
    return GetJSValue<_T, _Types...>(env, value);
}
} // namespace JSUtils

template<typename T>
int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::vector<T> &value)
{
    uint32_t arrLen = 0;
    napi_get_array_length(env, value, &arrLen);
    if (arrLen == 0) {
        return napi_ok;
    }
    std::vector<std::string> result;
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element;
        napi_get_element(env, value, i, &element);
        T value;
        Convert2Value(env, element, value);
        result.push_back(std::move(value));
    }
    return napi_ok;
}

template<typename... _Types>
int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, const std::variant<_Types...> &value)
{
    return GetCPPValue<decltype(value), _Types...>(env, jsValue, value);
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

template<typename... _Types>
napi_value JSUtils::Convert2JSValue(napi_env env, const std::variant<_Types...> &value)
{
    return GetJSValue<decltype(value), _Types...>(env, value);
}
} // namespace AppDataMgrJsKit
} // namespace OHOS

#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H
