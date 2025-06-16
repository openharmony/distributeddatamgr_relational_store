/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define LOG_TAG "NapiRdbStoreConvertUtils"
#include "napi_rdb_store_convert_utils.h"

#include "js_native_api.h"
#include "js_native_api_types.h"
#include "js_sendable_utils.h"
#include "js_utils.h"
#include "logger.h"
#include "napi_rdb_error.h"
#include "napi_rdb_js_utils.h"
#include "napi_rdb_sendable_utils.h"

using namespace OHOS::RelationalStoreJsKit;
using namespace OHOS::AppDataMgrJsKit::JSUtils;
namespace OHOS {
namespace SendableRdb {

constexpr int32_t KEY_INDEX = 0;
constexpr int32_t VALUE_INDEX = 1;

napi_value FromSendableValuesBucket(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    RDB_NAPI_ASSERT(env, status == napi_ok && argc == 1, std::make_shared<ParamNumError>("1"));

    bool isMap = false;
    status = napi_is_map(env, args[0], &isMap);
    RDB_NAPI_ASSERT(env, status == napi_ok && isMap,
        std::make_shared<ParamError>("ValuesBucket is invalid" + std::to_string(status)));

    uint32_t length = 0;
    status = napi_map_get_size(env, args[0], &length);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_map_get_size failed."));
    napi_value entries = nullptr;
    status = napi_map_get_entries(env, args[0], &entries);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_map_get_entries failed."));
    napi_value object = nullptr;
    status = napi_create_object(env, &object);
    for (uint32_t i = 0; i < length; ++i) {
        napi_value iter = nullptr;
        status = napi_map_iterator_get_next(env, entries, &iter);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_map_iterator_get_next failed."));
        napi_value values = nullptr;
        status = napi_get_named_property(env, iter, "value", &values);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_named_property value failed."));

        napi_value key = nullptr;
        status = napi_get_element(env, values, KEY_INDEX, &key);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_element key failed."));

        napi_value value = nullptr;
        status = napi_get_element(env, values, VALUE_INDEX, &value);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_element value failed."));

        status = napi_set_property(env, object, key, Convert2JSValue(env, value));
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_set_property failed."));
    }

    return object;
}

napi_value ToSendableValuesBucket(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    RDB_NAPI_ASSERT(env, status == napi_ok && argc == 1, std::make_shared<ParamNumError>("1"));

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, args[0], &type);
    RDB_NAPI_ASSERT(env, status == napi_ok && type == napi_object,
        std::make_shared<ParamError>("ValuesBucket is invalid" + std::to_string(status)));

    napi_value keys = nullptr;
    napi_get_all_property_names(env, args[0], napi_key_own_only,
        static_cast<napi_key_filter>(napi_key_enumerable | napi_key_skip_symbols), napi_key_numbers_to_strings, &keys);
    uint32_t length = 0;
    status = napi_get_array_length(env, keys, &length);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_array_length failed."));

    napi_value map = nullptr;
    status = napi_create_sendable_map(env, &map);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_create_sendable_map failed."));
    for (uint32_t i = 0; i < length; ++i) {
        napi_value key = nullptr;
        status = napi_get_element(env, keys, i, &key);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_element failed."));
        napi_value value = nullptr;
        status = napi_get_property(env, args[0], key, &value);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_property failed."));
        status = napi_map_set_property(env, map, key, Convert2Sendable(env, value));

        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_map_set_property failed."));
    }
    return map;
}

napi_value FromSendableAsset(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    RDB_NAPI_ASSERT(env, status == napi_ok && argc == 1, std::make_shared<ParamNumError>("1"));

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, args[0], &type);
    RDB_NAPI_ASSERT(env, status == napi_ok && type == napi_object,
        std::make_shared<ParamError>("Asset is invalid" + std::to_string(status)));

    return Convert2JSValue(env, args[0]);
}

napi_value ToSendableAsset(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    RDB_NAPI_ASSERT(env, status == napi_ok && argc == 1, std::make_shared<ParamNumError>("1"));

    napi_valuetype type = napi_undefined;
    status = napi_typeof(env, args[0], &type);
    RDB_NAPI_ASSERT(env, status == napi_ok && type == napi_object,
        std::make_shared<ParamError>("Asset is invalid" + std::to_string(status)));

    return Convert2Sendable(env, args[0]);
}

napi_value FromSendableValues(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    RDB_NAPI_ASSERT(env, status == napi_ok && argc == 1, std::make_shared<ParamNumError>("1"));
  
    bool isArray = false;
    status = napi_is_array(env, args[0], &isArray);
    RDB_NAPI_ASSERT(env, status == napi_ok && isArray,
        std::make_shared<ParamError>("values is invalid" + std::to_string(status)));

    uint32_t length = 0;
    status = napi_get_array_length(env, args[0], &length);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_array_length failed."));
    napi_value outArray;
    status = napi_create_array(env, &outArray);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_create_array failed."));
    for (uint32_t i = 0; i < length; ++i) {
        napi_value item = nullptr;
        status = napi_get_element(env, args[0], i, &item);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_element failed."));
        napi_value jsvalue = Convert2JSValue(env, item);
        status = napi_set_element(env, outArray, i, jsvalue);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_set_element failed."));
    }
    return outArray;
}

napi_value ToSendableValues(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    RDB_NAPI_ASSERT(env, status == napi_ok && argc == 1, std::make_shared<ParamNumError>("1"));

    bool isArray = false;
    status = napi_is_array(env, args[0], &isArray);
    RDB_NAPI_ASSERT(env, status == napi_ok && isArray,
        std::make_shared<ParamError>("values is invalid" + std::to_string(status)));

    uint32_t length = 0;
    status = napi_get_array_length(env, args[0], &length);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_array_length failed."));

    napi_value outArray;
    status = napi_create_sendable_array(env, &outArray);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_create_sendable_array failed."));
    for (uint32_t i = 0; i < length; ++i) {
        napi_value item = nullptr;
        status = napi_get_element(env, args[0], i, &item);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_get_element failed."));
        ValueObject object;
        status = (napi_status)Convert2Value(env, item, object);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("Convert2Value failed."));
        napi_value sendablevalue = Convert2Sendable(env, object);

        status = napi_set_element(env, outArray, i, sendablevalue);
        RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<InnerError>("napi_set_element failed."));
    }
    return outArray;
}

napi_value InitRdbStoreUtils(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("fromSendableValuesBucket", FromSendableValuesBucket),
        DECLARE_NAPI_FUNCTION("toSendableValuesBucket", ToSendableValuesBucket),
        DECLARE_NAPI_FUNCTION("fromSendableAsset", FromSendableAsset),
        DECLARE_NAPI_FUNCTION("toSendableAsset", ToSendableAsset),
        DECLARE_NAPI_FUNCTION("fromSendableValues", FromSendableValues),
        DECLARE_NAPI_FUNCTION("toSendableValues", ToSendableValues),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace SendableRdb
} // namespace OHOS