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
#define LOG_TAG "ValuesBucket"
#include "napi_values_bucket.h"

#include "js_utils.h"
#include "logger.h"
#include "value_object.h"

using namespace OHOS::Rdb;
using namespace OHOS::AppDataMgrJsKit;
using namespace OHOS::NativeRdb;

__attribute__((visibility("default"))) napi_value NAPI_OHOS_Data_RdbJsKit_ValuesBucketProxy_NewInstance(
    napi_env env, ValuesBucket &valuesBucket)
{
    napi_value ret = nullptr;
    NAPI_CALL(env, napi_create_object(env, &ret));
    for (auto &[key, value]: valuesBucket.values_) {
        napi_value jsValue = JSUtils::Convert2JSValue(env, value.value);
        NAPI_CALL(env, napi_set_named_property(env, ret, key.c_str(), jsValue));
    }

    return ret;
}

__attribute__((visibility("default"))) ValuesBucket *NAPI_OHOS_Data_RdbJsKit_ValuesBucketProxy_GetNativeObject(
    napi_env env, napi_value &arg)
{
    ValuesBucket *valuesBucket = new (std::nothrow) ValuesBucket;
    if (valuesBucket == nullptr) {
        LOG_ERROR("ValuesBucket new failed, valuesBucket is nullptr");
        return nullptr;
    }
    napi_value keys = nullptr;
    napi_get_property_names(env, arg, &keys);
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, keys, &arrLen);
    if (status != napi_ok) {
        LOG_DEBUG("ValuesBucket errr");
        return valuesBucket;
    }
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value key = nullptr;
        napi_get_element(env, keys, i, &key);
        std::string keyStr = JSUtils::Convert2String(env, key);
        napi_value value = nullptr;
        napi_get_property(env, arg, key, &value);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if (valueType == napi_string) {
            std::string valueString = JSUtils::Convert2String(env, value);
            valuesBucket->PutString(keyStr, valueString);
        } else if (valueType == napi_number) {
            double valueNumber;
            napi_get_value_double(env, value, &valueNumber);
            valuesBucket->PutDouble(keyStr, valueNumber);
        } else if (valueType == napi_boolean) {
            bool valueBool = false;
            napi_get_value_bool(env, value, &valueBool);
            valuesBucket->PutBool(keyStr, valueBool);
        } else if (valueType == napi_null) {
            valuesBucket->PutNull(keyStr);
        } else if (valueType == napi_object) {
            std::vector<uint8_t> val = {};
            JSUtils::Convert2Value(env, value, val);
            valuesBucket->PutBlob(keyStr, val);
        } else {
            LOG_WARN("valuesBucket error");
        }
    }
    return valuesBucket;
}