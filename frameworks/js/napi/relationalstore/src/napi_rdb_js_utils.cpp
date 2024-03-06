/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "napi_rdb_js_utils.h"

#include "logger.h"
#include "result_set.h"

#define NAPI_CALL_RETURN_ERR(theCall, retVal) \
    do {                                    \
        if ((theCall) != napi_ok) {         \
            return retVal;                  \
        }                                   \
    } while (0)

namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {
using namespace OHOS::Rdb;
using namespace NativeRdb;

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, Asset &output)
{
    napi_valuetype type;
    napi_status status = napi_typeof(env, jsValue, &type);
    bool isArray;
    napi_status status_array = napi_is_array(env, jsValue, &isArray);
    if (status != napi_ok || type != napi_object || status_array != napi_ok || isArray) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    NAPI_CALL_RETURN_ERR(GET_PROPERTY(env, jsValue, output, name), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GET_PROPERTY(env, jsValue, output, uri), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GET_PROPERTY(env, jsValue, output, createTime), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GET_PROPERTY(env, jsValue, output, modifyTime), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GET_PROPERTY(env, jsValue, output, size), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GET_PROPERTY(env, jsValue, output, path), napi_invalid_arg);
    output.hash = output.modifyTime + "_" + output.size;
    auto jsStatus = GetNamedProperty(env, jsValue, "status");
    if (jsStatus != nullptr) {
        Convert2ValueExt(env, jsStatus, output.status);
    }
    if (output.status != AssetValue::STATUS_DELETE) {
        output.status = AssetValue::STATUS_UNKNOWN;
    }
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value input, DistributedRdb::DistributedConfig &output)
{
    napi_valuetype type;
    napi_status status = napi_typeof(env, input, &type);
    if (status != napi_ok || type != napi_object) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    auto ret = Convert2Value(env, GetNamedProperty(env, input, "autoSync"), output.autoSync);
    if (ret != napi_ok) {
        return napi_invalid_arg;
    }
    return ret;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ValueObject &valueObject)
{
    auto status = Convert2Value(env, jsValue, valueObject.value);
    if (status != napi_ok) {
        return napi_invalid_arg;
    }
    return napi_ok;
}

template<>
napi_value Convert2JSValue(napi_env env, const Asset &value)
{
    napi_value object;
    NAPI_CALL_RETURN_ERR(napi_create_object(env, &object), object);
    NAPI_CALL_RETURN_ERR(ADD_JS_PROPERTY(env, object, value, name), object);
    NAPI_CALL_RETURN_ERR(ADD_JS_PROPERTY(env, object, value, uri), object);
    NAPI_CALL_RETURN_ERR(ADD_JS_PROPERTY(env, object, value, createTime), object);
    NAPI_CALL_RETURN_ERR(ADD_JS_PROPERTY(env, object, value, modifyTime), object);
    NAPI_CALL_RETURN_ERR(ADD_JS_PROPERTY(env, object, value, size), object);
    NAPI_CALL_RETURN_ERR(ADD_JS_PROPERTY(env, object, value, path), object);
    NAPI_CALL_RETURN_ERR(ADD_JS_PROPERTY(env, object, value, status), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const RowEntity &rowEntity)
{
    napi_value ret;
    NAPI_CALL(env, napi_create_object(env, &ret));
    auto &values = rowEntity.Get();
    for (auto const &[key, object] : values) {
        napi_value value = JSUtils::Convert2JSValue(env, object);
        NAPI_CALL(env, napi_set_named_property(env, ret, key.c_str(), value));
    }
    return ret;
}

template<>
napi_value Convert2JSValue(napi_env env, const ValueObject &valueObject)
{
    return JSUtils::Convert2JSValue(env, valueObject.value);
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::Statistic &statistic)
{
    napi_value jsValue;
    napi_status status = napi_create_object(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    napi_value total = Convert2JSValue(env, statistic.total);
    napi_value success = Convert2JSValue(env, statistic.success);
    napi_value failed = Convert2JSValue(env, statistic.failed);
    napi_value untreated = Convert2JSValue(env, statistic.untreated);

    napi_set_named_property(env, jsValue, "total", total);
    napi_set_named_property(env, jsValue, "success", success);
    napi_set_named_property(env, jsValue, "successful", success);
    napi_set_named_property(env, jsValue, "failed", failed);
    napi_set_named_property(env, jsValue, "remained", untreated);
    return jsValue;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::TableDetail &tableDetail)
{
    napi_value jsValue;
    napi_status status = napi_create_object(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    napi_value upload = Convert2JSValue(env, tableDetail.upload);
    napi_value download = Convert2JSValue(env, tableDetail.download);
    napi_set_named_property(env, jsValue, "upload", upload);
    napi_set_named_property(env, jsValue, "download", download);
    return jsValue;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::TableDetails &tableDetails)
{
    napi_value jsValue;
    napi_status status = napi_create_array_with_length(env, tableDetails.size(), &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    int index = 0;
    for (const auto &[device, result] : tableDetails) {
        napi_value jsElement;
        // The length of the converted JavaScript array is 2
        status = napi_create_array_with_length(env, 2, &jsElement);
        if (status != napi_ok) {
            return nullptr;
        }
        napi_set_element(env, jsElement, 0, Convert2JSValue(env, device));
        napi_set_element(env, jsElement, 1, Convert2JSValue(env, result));
        napi_set_element(env, jsValue, index++, jsElement);
    }
    return jsValue;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::ProgressDetail &progressDetail)
{
    napi_value jsValue;
    napi_status status = napi_create_object(env, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    napi_value schedule = Convert2JSValue(env, progressDetail.progress);
    napi_value code = Convert2JSValue(env, progressDetail.code);
    napi_value details = Convert2JSValue(env, progressDetail.details);
    if (details == nullptr) {
        return nullptr;
    }
    napi_set_named_property(env, jsValue, "schedule", schedule);
    napi_set_named_property(env, jsValue, "code", code);
    napi_set_named_property(env, jsValue, "details", details);
    return jsValue;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::Details &details)
{
    return nullptr;
}

template<>
napi_value Convert2JSValue(napi_env env, const JSChangeInfo &value)
{
    napi_value object;
    auto status = napi_create_object(env, &object);
    if (status != napi_ok) {
        return nullptr;
    }
    ADD_JS_PROPERTY(env, object, value, table);
    ADD_JS_PROPERTY(env, object, value, type);
    ADD_JS_PROPERTY(env, object, value, inserted);
    ADD_JS_PROPERTY(env, object, value, updated);
    ADD_JS_PROPERTY(env, object, value, deleted);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const Date &date)
{
    napi_value jsValue;
    napi_status status = napi_create_date(env, date, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

template<>
std::string ToString(const PRIKey &key)
{
    auto strVal = std::get_if<std::string>(&key);
    if (strVal != nullptr) {
        return *strVal;
    }
    auto intVal = std::get_if<int64_t>(&key);
    if (intVal != nullptr) {
        return std::to_string(*intVal);
    }
    auto dbVal = std::get_if<double>(&key);
    if (dbVal != nullptr) {
        return std::to_string(static_cast<int64_t>(*dbVal));
    }
    return {};
}
}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit