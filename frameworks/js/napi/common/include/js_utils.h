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

using Descriptor = std::function<std::vector<napi_property_descriptor>()>;

/* napi_define_class  wrapper */
napi_value DefineClass(napi_env env, const std::string &name, const Descriptor &descriptor, napi_callback ctor);
napi_value GetClass(napi_env env, const std::string &spaceName, const std::string &className);
std::string Convert2String(napi_env env, napi_value jsStr, bool useDefaultBufSize = true);
int32_t Convert2Bool(napi_env env, napi_value jsBool, bool &output);
int32_t Convert2Int32(napi_env env, napi_value jsNum, int32_t &output);
int32_t Convert2Double(napi_env env, napi_value jsNum, double &output);
int32_t Convert2String(napi_env env, napi_value jsStr, std::string &output);
int32_t Convert2U8Vector(napi_env env, napi_value jsValue, std::vector<uint8_t> &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, int32_t> &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, bool> &output);
int32_t Convert2Value(napi_env env, napi_value jsBool, bool &output);
int32_t Convert2Value(napi_env env, napi_value jsNum, int32_t &output);
int32_t Convert2Value(napi_env env, napi_value jsStr, std::string &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, int32_t> &output);
int32_t Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, bool> &output);
std::vector<std::string> Convert2StrVector(napi_env env, napi_value value);
std::vector<uint8_t> Convert2U8Vector(napi_env env, napi_value jsValue);
std::string ConvertAny2String(napi_env env, const napi_value jsValue);


int32_t Convert2StrVector(napi_env env, napi_value value, std::vector<std::string> &output);
int32_t Convert2BoolVector(napi_env env, napi_value value, std::vector<bool> &output);
int32_t Convert2DoubleVector(napi_env env, napi_value value, std::vector<double> &output);

napi_value Convert2JSValue(napi_env env, const std::vector<std::string> &value);
napi_value Convert2JSValue(napi_env env, const std::string &value);
napi_value Convert2JSValue(napi_env env, const std::vector<uint8_t> &value);
napi_value Convert2JSValue(napi_env env, int32_t value);
napi_value Convert2JSValue(napi_env env, int64_t value);
napi_value Convert2JSValue(napi_env env, double value);
napi_value Convert2JSValue(napi_env env, bool value);
napi_value Convert2JSValue(napi_env env, const std::map<std::string, int> &value);
napi_value Convert2JSValue(napi_env env, const std::monostate &value);

int32_t Convert2JSValue(napi_env env, std::string value, napi_value &output);
int32_t Convert2JSValue(napi_env env, bool value, napi_value &output);
int32_t Convert2JSValue(napi_env env, double value, napi_value &output);
int32_t Convert2JSStringArr(napi_env env, std::vector<std::string> value, napi_value &output);
int32_t Convert2JSBoolArr(napi_env env, std::vector<bool> value, napi_value &output);
int32_t Convert2JSDoubleArr(napi_env env, std::vector<double> value, napi_value &output);

template<typename T> napi_value Convert2JSValue(napi_env env, const T &value);

template<typename _T> napi_value GetJSValue(napi_env env, const _T &value)
{
    return nullptr;
}

template<typename _T, typename _First, typename... _Types> napi_value GetJSValue(napi_env env, const _T &value)
{
    auto *val = std::get_if<_First>(&value);
    if (val != nullptr) {
        return Convert2JSValue(env, *val);
    }
    return GetJSValue<_T, _Types...>(env, value);
}

template<typename... _Types> napi_value Convert2JSValue(napi_env env, const std::variant<_Types...> &value)
{
    return GetJSValue<decltype(value), _Types...>(env, value);
}
} // namespace JSUtils
} // namespace AppDataMgrJsKit
} // namespace OHOS

#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_JSUTILS_H
