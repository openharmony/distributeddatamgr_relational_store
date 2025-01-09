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

#define LOG_TAG "JSSendableUtils"
#include "js_sendable_utils.h"

#include <cstring>

#include "js_utils.h"
#include "logger.h"
#include "securec.h"
using namespace OHOS::Rdb;
namespace OHOS {
namespace AppDataMgrJsKit {
napi_value JSUtils::Convert2Sendable(napi_env env, const std::string &value)
{
    return Convert2JSValue(env, value);
}

napi_value JSUtils::Convert2Sendable(napi_env env, const std::vector<uint8_t> &value)
{
    napi_value jsValue = nullptr;
    void *native = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_sendable_arraybuffer(env, value.size(), &native, &buffer);
    if (status != napi_ok) {
        LOG_ERROR("napi_create_sendable_arraybuffer failed %{public}d", status);
        return nullptr;
    }
    if (value.size() != 0) {
        std::copy(value.begin(), value.end(), static_cast<uint8_t *>(native));
    }
    status = napi_create_sendable_typedarray(env, napi_uint8_array, value.size(), buffer, 0, &jsValue);
    if (status != napi_ok) {
        LOG_ERROR("napi_create_sendable_typedarray failed %{public}d", status);
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2Sendable(napi_env env, int32_t value)
{
    return Convert2JSValue(env, value);
}

napi_value JSUtils::Convert2Sendable(napi_env env, uint32_t value)
{
    return Convert2JSValue(env, value);
}

napi_value JSUtils::Convert2Sendable(napi_env env, int64_t value)
{
    return Convert2JSValue(env, value);
}

napi_value JSUtils::Convert2Sendable(napi_env env, double value)
{
    return Convert2JSValue(env, value);
}

napi_value JSUtils::Convert2Sendable(napi_env env, bool value)
{
    return Convert2JSValue(env, value);
}

napi_value JSUtils::Convert2Sendable(napi_env env, const std::vector<float> &value)
{
    napi_value jsValue = nullptr;
    float *native = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_sendable_arraybuffer(env, value.size() * sizeof(float), (void **)&native, &buffer);
    if (status != napi_ok) {
        LOG_ERROR("napi_create_sendable_arraybuffer failed %{public}d", status);
        return nullptr;
    }
    if (value.size() != 0) {
        std::copy(value.begin(), value.end(), static_cast<float *>(native));
    }
    status = napi_create_sendable_typedarray(env, napi_float32_array, value.size(), buffer, 0, &jsValue);
    if (status != napi_ok) {
        LOG_ERROR("napi_create_sendable_typedarray failed %{public}d", status);
        return nullptr;
    }
    return jsValue;
}

int32_t JSUtils::Convert2Sendable(napi_env env, std::string value, napi_value &output)
{
    return Convert2JSValue(env, value, output);
}

int32_t JSUtils::Convert2Sendable(napi_env env, bool value, napi_value &output)
{
    return Convert2JSValue(env, value, output);
}

int32_t JSUtils::Convert2Sendable(napi_env env, double value, napi_value &output)
{
    return Convert2JSValue(env, value, output);
}

napi_value JSUtils::Convert2Sendable(napi_env env, const std::monostate &value)
{
    return Convert2JSValue(env, value);
}

napi_value JSUtils::ToSendableObject(napi_env env, napi_value jsValue)
{
    LOG_DEBUG("jsObject -> sendableObject");
    napi_value keys = nullptr;
    napi_status status = napi_get_all_property_names(env, jsValue, napi_key_own_only,
        static_cast<napi_key_filter>(napi_key_enumerable | napi_key_skip_symbols), napi_key_numbers_to_strings, &keys);
    ASSERT(status == napi_ok, "napi_get_all_property_names failed", nullptr);
    uint32_t length = 0;
    status = napi_get_array_length(env, keys, &length);
    ASSERT(status == napi_ok, "napi_get_array_length failed", nullptr);
    std::vector<napi_property_descriptor> descriptors;
    // keysHold guarantees that the string address is valid before create the sendable object.
    std::vector<std::string> keysHold(length, "");
    for (uint32_t i = 0; i < length; ++i) {
        napi_value key = nullptr;
        status = napi_get_element(env, keys, i, &key);
        ASSERT(status == napi_ok, "napi_get_element failed", nullptr);
        JSUtils::Convert2Value(env, key, keysHold[i]);
        napi_value value = nullptr;
        status = napi_get_named_property(env, jsValue, keysHold[i].c_str(), &value);
        ASSERT(status == napi_ok, "napi_get_named_property failed", nullptr);
        descriptors.emplace_back(DECLARE_SENDABLE_PROPERTY(env, keysHold[i].c_str(), value));
    }
    napi_value sendableObject = nullptr;
    status = napi_create_sendable_object_with_properties(env, descriptors.size(), descriptors.data(), &sendableObject);
    ASSERT(status == napi_ok, "napi_create_sendable_object_with_properties failed", nullptr);
    return sendableObject;
}

napi_value JSUtils::ToSendableArray(napi_env env, napi_value jsValue)
{
    LOG_DEBUG("jsArray -> sendableArray");
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, jsValue, &arrLen);
    ASSERT(status == napi_ok, "napi_get_array_length failed", nullptr);
    napi_value sendableArray = nullptr;
    status = napi_create_sendable_array_with_length(env, arrLen, &sendableArray);
    ASSERT(status == napi_ok, "napi_create_sendable_array_with_length failed", nullptr);
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element;
        status = napi_get_element(env, jsValue, i, &element);
        ASSERT(status == napi_ok, "napi_get_element failed", nullptr);
        status = napi_set_element(env, sendableArray, i, Convert2Sendable(env, element));
        ASSERT(status == napi_ok, "napi_set_element failed", nullptr);
    }
    return sendableArray;
}

napi_value JSUtils::ToSendableTypedArray(napi_env env, napi_value jsValue)
{
    LOG_DEBUG("jsTypedArryay -> sendableTypedArryay");
    napi_typedarray_type type;
    size_t length = 0;
    void *tmp = nullptr;
    napi_status status = napi_get_typedarray_info(env, jsValue, &type, &length, &tmp, nullptr, nullptr);
    ASSERT(status == napi_ok, "napi_get_typedarray_info failed", nullptr);

    if (type != napi_uint8_array && type != napi_float32_array) {
        LOG_ERROR("Type is invalid %{public}d", type);
        return nullptr;
    }
    napi_value sendableTypedArryay = nullptr;
    void *native = nullptr;
    napi_value buffer = nullptr;
    status = napi_create_sendable_arraybuffer(env, length, (void **)&native, &buffer);
    ASSERT(status == napi_ok, "napi_create_sendable_arraybuffer failed", nullptr);
    if (length > 0) {
        errno_t result = memcpy_s(native, length, tmp, length);
        if (result != EOK) {
            LOG_ERROR("memcpy_s failed, result is %{public}d", result);
            return nullptr;
        }
    }
    auto size = (type == napi_uint8_array) ? length : length / sizeof(float);
    status = napi_create_sendable_typedarray(env, type, size, buffer, 0, &sendableTypedArryay);
    ASSERT(status == napi_ok, "napi_create_sendable_typedarray failed", nullptr);
    return sendableTypedArryay;
}

napi_value JSUtils::Convert2Sendable(napi_env env, napi_value jsValue)
{
    bool result = false;
    napi_status status = napi_is_sendable(env, jsValue, &result);
    ASSERT(status == napi_ok, "napi_is_sendable failed", nullptr);
    if (result) {
        return jsValue;
    }
    status = napi_is_array(env, jsValue, &result);
    ASSERT(status == napi_ok, "napi_is_array failed", nullptr);
    if (result) {
        return ToSendableArray(env, jsValue);
    }
    status = napi_is_typedarray(env, jsValue, &result);
    ASSERT(status == napi_ok, "napi_is_typedarray failed", nullptr);
    if (result) {
        return ToSendableTypedArray(env, jsValue);
    }
    return ToSendableObject(env, jsValue);
}
} // namespace AppDataMgrJsKit
} // namespace OHOS