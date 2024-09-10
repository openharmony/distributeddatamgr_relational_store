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
#define LOG_TAG "JSUtils"

#include "js_utils.h"

#include <cstring>

#include "js_native_api_types.h"
#include "logger.h"
#include "securec.h"
using namespace OHOS::Rdb;

#define CHECK_RETURN_RET(assertion, message, revt)                   \
    do {                                                             \
        if (!(assertion)) {                                          \
            LOG_WARN("assertion (" #assertion ") failed: " message); \
            return revt;                                             \
        }                                                            \
    } while (0)

namespace OHOS {
namespace AppDataMgrJsKit {
namespace JSUtils {
    static int32_t g_hapVersion = -1;  // the current apiVersion of hap
}

static constexpr JSUtils::JsFeatureSpace FEATURE_NAME_SPACES[] = {
    { "ohos.data.cloudData", "ZGF0YS5jbG91ZERhdGE=", true },
    { "ohos.data.dataAbility", "ZGF0YS5kYXRhQWJpbGl0eQ==", true },
    { "ohos.data.dataShare", "ZGF0YS5kYXRhU2hhcmU=", false },
    { "ohos.data.distributedDataObject", "ZGF0YS5kaXN0cmlidXRlZERhdGFPYmplY3Q=", false },
    { "ohos.data.distributedKVStore", "ZGF0YS5kaXN0cmlidXRlZEtWU3RvcmU=", false },
    { "ohos.data.rdb", "ZGF0YS5yZGI=", true },
    { "ohos.data.relationalStore", "ZGF0YS5yZWxhdGlvbmFsU3RvcmU=", true },
};

void JSUtils::SetHapVersion(int32_t hapversion)
{
    g_hapVersion = hapversion;
}

int32_t JSUtils::GetHapVersion()
{
    return g_hapVersion;
}

const std::optional<JSUtils::JsFeatureSpace> JSUtils::GetJsFeatureSpace(const std::string &name)
{
    auto jsFeature = JsFeatureSpace{ name.data(), nullptr, false };
    auto iter = std::lower_bound(FEATURE_NAME_SPACES,
        FEATURE_NAME_SPACES + sizeof(FEATURE_NAME_SPACES) / sizeof(FEATURE_NAME_SPACES[0]), jsFeature,
        [](const JsFeatureSpace &JsFeatureSpace1, const JsFeatureSpace &JsFeatureSpace2) {
            return strcmp(JsFeatureSpace1.spaceName, JsFeatureSpace2.spaceName) < 0;
        });
    if (iter < FEATURE_NAME_SPACES + sizeof(FEATURE_NAME_SPACES) / sizeof(FEATURE_NAME_SPACES[0]) &&
        strcmp(iter->spaceName, name.data()) == 0) {
        return *iter;
    }
    return std::nullopt;
}

std::pair<napi_status, napi_value> JSUtils::GetInnerValue(
    napi_env env, napi_value in, const std::string &prop, bool optional)
{
    bool hasProp = false;
    napi_status status = napi_has_named_property(env, in, prop.c_str(), &hasProp);
    if (status != napi_ok) {
        return std::make_pair(napi_generic_failure, nullptr);
    }
    if (!hasProp) {
        status = optional ? napi_ok : napi_generic_failure;
        return std::make_pair(status, nullptr);
    }
    napi_value inner = nullptr;
    status = napi_get_named_property(env, in, prop.c_str(), &inner);
    if (status != napi_ok || inner == nullptr) {
        return std::make_pair(napi_generic_failure, nullptr);
    }
    if (optional && JSUtils::IsNull(env, inner)) {
        return std::make_pair(napi_ok, nullptr);
    }
    return std::make_pair(napi_ok, inner);
}

std::string JSUtils::Convert2String(napi_env env, napi_value jsStr)
{
    std::string value = ""; // TD: need to check everywhere in use whether empty is work well.
    JSUtils::Convert2Value(env, jsStr, value);
    return value;
}

int32_t JSUtils::Convert2ValueExt(napi_env env, napi_value jsValue, uint32_t &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type != napi_number) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    status = napi_get_value_uint32(env, jsValue, &output);
    if (status != napi_ok) {
        LOG_DEBUG("napi_get_value_uint32 failed, status = %{public}d", status);
        return status;
    }
    return status;
}

int32_t JSUtils::Convert2ValueExt(napi_env env, napi_value jsValue, int32_t &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type != napi_number) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    status = napi_get_value_int32(env, jsValue, &output);
    if (status != napi_ok) {
        LOG_DEBUG("napi_get_value_int32 failed, status = %{public}d", status);
        return status;
    }
    return status;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, napi_value &output)
{
    output = jsValue;
    return napi_ok;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, bool &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type != napi_boolean) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    bool bValue = false;
    status = napi_get_value_bool(env, jsValue, &bValue);
    if (status != napi_ok) {
        LOG_ERROR("napi_get_value_bool failed, status = %{public}d", status);
        return status;
    }
    output = bValue;
    return status;
}

int32_t JSUtils::Convert2ValueExt(napi_env env, napi_value jsValue, int64_t &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type != napi_number) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    status = napi_get_value_int64(env, jsValue, &output);
    if (status != napi_ok) {
        LOG_DEBUG("napi_get_value_int64 failed, status = %{public}d", status);
        return status;
    }
    return status;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, double &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type != napi_number) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    double number = 0.0;
    status = napi_get_value_double(env, jsValue, &number);
    if (status != napi_ok) {
        LOG_DEBUG("napi_get_value_double failed, status = %{public}d", status);
        return status;
    }
    output = number;
    return status;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, int64_t &output)
{
    return napi_invalid_arg;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::vector<float> &output)
{
    bool isTypedArray = false;
    napi_is_typedarray(env, jsValue, &isTypedArray);
    if (!isTypedArray) {
        return napi_invalid_arg;
    }

    napi_typedarray_type type;
    napi_value input_buffer = nullptr;
    size_t byte_offset = 0;
    size_t length = 0;
    void *tmp = nullptr;
    auto status = napi_get_typedarray_info(env, jsValue, &type, &length, &tmp, &input_buffer, &byte_offset);
    if (status != napi_ok || type != napi_float32_array) {
        return napi_invalid_arg;
    }

    output = (tmp != nullptr
                  ? std::vector<float>(static_cast<float *>(tmp), static_cast<float *>(tmp) + length / sizeof(float))
                  : std::vector<float>());
    return status;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::string &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type != napi_string) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    size_t buffSize = 0;
    napi_get_value_string_utf8(env, jsValue, nullptr, 0, &buffSize);

    // cut down with 0 if more than MAX_VALUE_LENGTH
    if (buffSize >= JSUtils::MAX_VALUE_LENGTH - 1) {
        buffSize = JSUtils::MAX_VALUE_LENGTH - 1;
    }
    std::unique_ptr<char[]> buffer = std::make_unique<char[]>(buffSize + 1);
    if (!buffer) {
        LOG_ERROR("buffer data is nullptr.");
        return napi_invalid_arg;
    }
    status = napi_get_value_string_utf8(env, jsValue, buffer.get(), buffSize + 1, &buffSize);
    if (status != napi_ok) {
        LOG_ERROR("napi_get_value_string_utf8 failed, status = %{public}d", status);
        return status;
    }
    output = std::string(buffer.get());

    return status;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::vector<uint8_t> &output)
{
    bool isTypedArray = false;
    napi_is_typedarray(env, jsValue, &isTypedArray);
    if (!isTypedArray) {
        return napi_invalid_arg;
    }

    napi_typedarray_type type;
    napi_value input_buffer = nullptr;
    size_t byte_offset = 0;
    size_t length = 0;
    void *tmp = nullptr;
    auto status = napi_get_typedarray_info(env, jsValue, &type, &length, &tmp, &input_buffer, &byte_offset);
    if (status != napi_ok || type != napi_uint8_array) {
        return napi_invalid_arg;
    }

    output = (tmp != nullptr ? std::vector<uint8_t>(static_cast<uint8_t *>(tmp), static_cast<uint8_t *>(tmp) + length)
                             : std::vector<uint8_t>());
    return status;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::monostate &value)
{
    napi_value tempValue = nullptr;
    napi_get_null(env, &tempValue);
    bool equal = false;
    napi_strict_equals(env, jsValue, tempValue, &equal);
    if (equal) {
        value = std::monostate();
        return napi_ok;
    }
    LOG_DEBUG("jsValue is not null.");
    return napi_invalid_arg;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, int32_t> &output)
{
    LOG_DEBUG("napi_value -> std::map<std::string, int32_t> ");
    output.clear();
    napi_value jsMapList = nullptr;
    uint32_t jsCount = 0;
    napi_status status = napi_get_property_names(env, jsValue, &jsMapList);
    CHECK_RETURN_RET(status == napi_ok, "get_property_names failed", napi_invalid_arg);
    status = napi_get_array_length(env, jsMapList, &jsCount);
    LOG_DEBUG("jsCOUNT: %{public}d", jsCount);
    CHECK_RETURN_RET(status == napi_ok && jsCount > 0, "get_map failed", napi_invalid_arg);
    napi_value jsKey = nullptr;
    napi_value jsVal = nullptr;
    for (uint32_t index = 0; index < jsCount; index++) {
        status = napi_get_element(env, jsMapList, index, &jsKey);
        CHECK_RETURN_RET(status == napi_ok && jsKey != nullptr, "no element", napi_invalid_arg);
        std::string key;
        int ret = Convert2Value(env, jsKey, key);
        CHECK_RETURN_RET(ret == napi_ok, "convert key failed", ret);
        status = napi_get_property(env, jsValue, jsKey, &jsVal);
        CHECK_RETURN_RET(status == napi_ok && jsVal != nullptr, "no element", napi_invalid_arg);
        int32_t val;
        ret = Convert2ValueExt(env, jsVal, val);
        CHECK_RETURN_RET(ret == napi_ok, "convert val failed", ret);
        output.insert(std::pair<std::string, int32_t>(key, val));
    }
    return napi_ok;
}

int32_t JSUtils::Convert2Value(napi_env env, napi_value jsValue, std::map<std::string, bool> &output)
{
    LOG_DEBUG("napi_value -> std::map<std::string, bool> ");
    output.clear();
    napi_value jsMapList = nullptr;
    uint32_t jsCount = 0;
    napi_status status = napi_get_property_names(env, jsValue, &jsMapList);
    CHECK_RETURN_RET(status == napi_ok, "get_property_names failed", napi_invalid_arg);
    status = napi_get_array_length(env, jsMapList, &jsCount);
    LOG_DEBUG("jsCount: %{public}d", jsCount);
    CHECK_RETURN_RET(status == napi_ok && jsCount > 0, "get_map failed", napi_invalid_arg);
    napi_value jsKey = nullptr;
    napi_value jsVal = nullptr;
    for (uint32_t index = 0; index < jsCount; index++) {
        status = napi_get_element(env, jsMapList, index, &jsKey);
        CHECK_RETURN_RET(status == napi_ok && jsKey != nullptr, "no element", napi_invalid_arg);
        std::string key;
        int ret = Convert2Value(env, jsKey, key);
        CHECK_RETURN_RET(ret == napi_ok, "convert key failed", ret);
        status = napi_get_property(env, jsValue, jsKey, &jsVal);
        CHECK_RETURN_RET(status == napi_ok && jsVal != nullptr, "no element", napi_invalid_arg);
        bool val;
        ret = Convert2Value(env, jsVal, val);
        CHECK_RETURN_RET(ret == napi_ok, "convert val failed", ret);
        output.insert(std::pair<std::string, bool>(key, val));
    }
    return napi_ok;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::string &value)
{
    napi_value jsValue = nullptr;
    if (napi_create_string_utf8(env, value.c_str(), value.size(), &jsValue) != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::vector<uint8_t> &value)
{
    napi_value jsValue = nullptr;
    void *native = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_arraybuffer(env, value.size(), &native, &buffer);
    if (status != napi_ok) {
        return nullptr;
    }
    for (size_t i = 0; i < value.size(); i++) {
        *(static_cast<uint8_t *>(native) + i) = value[i];
    }
    status = napi_create_typedarray(env, napi_uint8_array, value.size(), buffer, 0, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, int32_t value)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_create_int32(env, value, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, uint32_t value)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_create_uint32(env, value, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, int64_t value)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_create_int64(env, value, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, double value)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_create_double(env, value, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, bool value)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_get_boolean(env, value, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::vector<float> &value)
{
    napi_value jsValue = nullptr;
    float *native = nullptr;
    napi_value buffer = nullptr;
    napi_status status = napi_create_arraybuffer(env, value.size() * sizeof(float), (void **)&native, &buffer);
    if (status != napi_ok) {
        return nullptr;
    }
    if (native == nullptr) {
        return nullptr;
    }
    for (size_t i = 0; i < value.size(); i++) {
        *(native + i) = value[i];
    }
    status = napi_create_typedarray(env, napi_float32_array, value.size(), buffer, 0, &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }
    return jsValue;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::map<std::string, int> &value)
{
    napi_value jsValue = nullptr;
    napi_status status = napi_create_array_with_length(env, value.size(), &jsValue);
    if (status != napi_ok) {
        return nullptr;
    }

    int index = 0;
    for (const auto &[device, result] : value) {
        napi_value jsElement = nullptr;
        status = napi_create_array_with_length(env, SYNC_RESULT_ELEMENT_NUM, &jsElement);
        if (status != napi_ok) {
            return nullptr;
        }
        napi_set_element(env, jsElement, 0, Convert2JSValue(env, device));
        napi_set_element(env, jsElement, 1, Convert2JSValue(env, result));
        napi_set_element(env, jsValue, index++, jsElement);
    }

    return jsValue;
}

int32_t JSUtils::Convert2JSValue(napi_env env, std::string value, napi_value &output)
{
    std::string tempStr = std::string(value);
    if (napi_create_string_utf8(env, tempStr.c_str(), tempStr.size(), &output) != napi_ok) {
        LOG_ERROR("Convert2JSValue create JS string failed.");
        return ERR;
    }
    return napi_ok;
}

int32_t JSUtils::Convert2JSValue(napi_env env, bool value, napi_value &output)
{
    if (napi_get_boolean(env, value, &output) != napi_ok) {
        LOG_ERROR("Convert2JSValue create JS bool failed.");
        return ERR;
    }
    return napi_ok;
}

int32_t JSUtils::Convert2JSValue(napi_env env, double value, napi_value &output)
{
    if (napi_create_double(env, value, &output) != napi_ok) {
        LOG_ERROR("Convert2JSValue create JS double failed.");
        return ERR;
    }
    return napi_ok;
}

napi_value JSUtils::Convert2JSValue(napi_env env, const std::monostate &value)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

bool JSUtils::IsNull(napi_env env, napi_value value)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, value, &type);
    return status == napi_ok && (type == napi_undefined || type == napi_null);
}

napi_value JSUtils::DefineClass(napi_env env, const std::string &spaceName, const std::string &className,
    const Descriptor &descriptor, napi_callback ctor)
{
    auto featureSpace = GetJsFeatureSpace(spaceName);
    if (!featureSpace.has_value() || !featureSpace->isComponent) {
        return nullptr;
    }
    auto constructor = GetClass(env, spaceName, className);
    if (constructor != nullptr) {
        return constructor;
    }
    auto rootPropName = std::string(featureSpace->nameBase64);
    napi_value root = nullptr;
    bool hasRoot = false;
    napi_value global = nullptr;
    napi_get_global(env, &global);
    napi_has_named_property(env, global, rootPropName.c_str(), &hasRoot);
    if (hasRoot) {
        napi_get_named_property(env, global, rootPropName.c_str(), &root);
    } else {
        napi_create_object(env, &root);
        napi_set_named_property(env, global, rootPropName.c_str(), root);
    }

    std::string propName = "constructor_of_" + className;
    bool hasProp = false;
    napi_has_named_property(env, root, propName.c_str(), &hasProp);
    if (hasProp) {
        napi_get_named_property(env, root, propName.c_str(), &constructor);
        if (constructor != nullptr) {
            LOG_DEBUG("got %{public}s from %{public}s", propName.c_str(), featureSpace->spaceName);
            return constructor;
        }
        hasProp = false; // no constructor.
    }
    auto properties = descriptor();
    NAPI_CALL(env, napi_define_class(env, className.c_str(), className.size(), ctor, nullptr, properties.size(),
                       properties.data(), &constructor));
    NAPI_ASSERT(env, constructor != nullptr, "napi_define_class failed!");

    if (!hasProp) {
        napi_set_named_property(env, root, propName.c_str(), constructor);
        LOG_DEBUG("save %{public}s to %{public}s", propName.c_str(), featureSpace->spaceName);
    }
    return constructor;
}

napi_value JSUtils::GetClass(napi_env env, const std::string &spaceName, const std::string &className)
{
    auto featureSpace = GetJsFeatureSpace(spaceName);
    if (!featureSpace.has_value()) {
        return nullptr;
    }
    auto rootPropName = std::string(featureSpace->nameBase64);
    napi_value root = nullptr;
    napi_value global = nullptr;
    napi_get_global(env, &global);
    bool hasRoot;
    napi_has_named_property(env, global, rootPropName.c_str(), &hasRoot);
    if (!hasRoot) {
        return nullptr;
    }
    napi_get_named_property(env, global, rootPropName.c_str(), &root);
    std::string propName = "constructor_of_" + className;
    napi_value constructor = nullptr;
    bool hasProp = false;
    napi_has_named_property(env, root, propName.c_str(), &hasProp);
    if (!hasProp) {
        return nullptr;
    }
    napi_get_named_property(env, root, propName.c_str(), &constructor);
    if (constructor != nullptr) {
        LOG_DEBUG("got %{public}s from %{public}s", propName.c_str(), featureSpace->spaceName);
        return constructor;
    }
    hasProp = false; // no constructor.
    return constructor;
}

bool JSUtils::Equal(napi_env env, napi_ref ref, napi_value value)
{
    napi_value callback = nullptr;
    napi_get_reference_value(env, ref, &callback);

    bool isEquals = false;
    napi_strict_equals(env, value, callback, &isEquals);
    return isEquals;
}

napi_value JSUtils::ToJsObject(napi_env env, napi_value sendableValue)
{
    LOG_DEBUG("sendableObject -> jsObject");
    napi_value keys = nullptr;
    napi_status status = napi_get_all_property_names(env, sendableValue, napi_key_own_only,
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
        status = napi_get_named_property(env, sendableValue, keysHold[i].c_str(), &value);
        ASSERT(status == napi_ok, "napi_get_named_property failed", nullptr);
        descriptors.emplace_back(DECLARE_JS_PROPERTY(env, keysHold[i].c_str(), value));
    }
    napi_value jsObject = nullptr;
    status = napi_create_object_with_properties(env, &jsObject, descriptors.size(), descriptors.data());
    ASSERT(status == napi_ok, "napi_create_object_with_properties failed", nullptr);
    return jsObject;
}

napi_value JSUtils::ToJsArray(napi_env env, napi_value sendableValue)
{
    LOG_DEBUG("sendableArray -> jsArray");
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, sendableValue, &arrLen);
    ASSERT(status == napi_ok, "napi_get_array_length failed", nullptr);
    napi_value jsArray = nullptr;
    status = napi_create_array_with_length(env, arrLen, &jsArray);
    ASSERT(status == napi_ok, "napi_create_array_with_length failed", nullptr);
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element;
        status = napi_get_element(env, sendableValue, i, &element);
        ASSERT(status == napi_ok, "napi_get_element failed", nullptr);
        status = napi_set_element(env, jsArray, i, Convert2JSValue(env, element));
        ASSERT(status == napi_ok, "napi_set_element failed", nullptr);
    }
    return jsArray;
}

napi_value JSUtils::ToJsTypedArray(napi_env env, napi_value sendableValue)
{
    LOG_DEBUG("sendableTypedArray -> jsTypedArray");
    napi_typedarray_type type;
    size_t length = 0;
    void *tmp = nullptr;
    napi_status status = napi_get_typedarray_info(env, sendableValue, &type, &length, &tmp, nullptr, nullptr);
    ASSERT(status == napi_ok, "napi_get_typedarray_info failed", nullptr);

    if (type != napi_uint8_array && type != napi_float32_array) {
        LOG_ERROR("type is invalid %{public}d", type);
        return nullptr;
    }
    napi_value jsTypedArray = nullptr;
    void *native = nullptr;
    napi_value buffer = nullptr;
    status = napi_create_arraybuffer(env, length, (void **)&native, &buffer);
    ASSERT(status == napi_ok, "napi_create_arraybuffer failed", nullptr);
    if (length > 0) {
        errno_t result = memcpy_s(native, length, tmp, length);
        if (result != EOK) {
            LOG_ERROR("memcpy_s failed, result is %{public}d", result);
            return nullptr;
        }
    }
    auto size = (type == napi_uint8_array) ? length : length / sizeof(float);
    status = napi_create_typedarray(env, type, size, buffer, 0, &jsTypedArray);
    ASSERT(status == napi_ok, "napi_create_typedarray failed", nullptr);
    return jsTypedArray;
}

napi_value JSUtils::Convert2JSValue(napi_env env, napi_value sendableValue)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, sendableValue, &type);
    ASSERT(status == napi_ok, "napi_typeof failed", nullptr);
    if (type != napi_object) {
        return sendableValue;
    }
    bool result = false;
    status = napi_is_sendable(env, sendableValue, &result);
    ASSERT(status == napi_ok, "napi_is_sendable failed", nullptr);
    if (!result) {
        return sendableValue;
    }

    status = napi_is_array(env, sendableValue, &result);
    ASSERT(status == napi_ok, "napi_is_array failed", nullptr);
    if (result) {
        return ToJsArray(env, sendableValue);
    }
    status = napi_is_typedarray(env, sendableValue, &result);
    ASSERT(status == napi_ok, "napi_is_typedarray failed", nullptr);
    if (result) {
        return ToJsTypedArray(env, sendableValue);
    }
    return ToJsObject(env, sendableValue);
}
} // namespace AppDataMgrJsKit
} // namespace OHOS