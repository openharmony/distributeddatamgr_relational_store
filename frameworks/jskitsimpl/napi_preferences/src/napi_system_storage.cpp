/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_system_storage.h"

#include <string>

#include "js_ability.h"
#include "js_logger.h"
#include "js_utils.h"
#include "preferences_errno.h"
#include "preferences_helper.h"

using namespace OHOS::AppDataMgrJsKit;
using namespace OHOS::NativePreferences;

namespace OHOS {
namespace SystemStorageJsKit {
struct SyncContext {
    std::string key;
    std::string def;
    std::string val;
    napi_value success;
    napi_value fail;
    napi_value complete;
    int32_t output = E_ERROR;
};

static const unsigned int MAX_KEY_LENGTH = 32;

static const unsigned int MAX_VALUE_LENGTH = 128;

static const int32_t FAILCOUNT = 2;

static const int32_t SUCCOUNT = 1;

static void ParseString(napi_env env, napi_value &object, const char *name, const bool enable, std::string &output)
{
    napi_value value = nullptr;
    if (napi_get_named_property(env, object, name, &value) == napi_ok) {
        std::string key = JSUtils::Convert2String(env, value, JSUtils::DEFAULT_BUF_SIZE);
        NAPI_ASSERT_RETURN_VOID(env, enable || !key.empty(), "StorageOptions is empty.");
        output = std::move(key);
    }
}

static void ParseFunction(napi_env env, napi_value &object, const char *name, napi_value &output)
{
    napi_value value = nullptr;
    output = nullptr;
    if (napi_get_named_property(env, object, name, &value) == napi_ok) {
        napi_valuetype valueType = napi_null;
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, value, &valueType));
        NAPI_ASSERT_RETURN_VOID(env, valueType == napi_function, "Wrong argument, function expected.");
        output = value;
    }
}

static const std::string GetMessageInfo(int errCode)
{
    std::string message;
    switch (errCode) {
        case E_KEY_EMPTY:
            message = "The key string is null or empty.";
            break;
        case E_VALUE_EXCEED_LENGTH_LIMIT:
            message = "The key string length should shorter than 32.";
            break;
        case E_KEY_EXCEED_LENGTH_LIMIT:
            message = "The value string length should shorter than 128.";
            break;
        case E_INVALID_ARGS:
            message = "The input args is invalid.";
            break;
        default:
            message = "Unknown err";
    }
    return message;
}

static void CallFunctions(napi_env env, const SyncContext &context)
{
    size_t len = 0;
    if (context.output == E_OK && context.success != nullptr) {
        napi_value succRes[SUCCOUNT] = { 0 };
        len = context.val.size();
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, context.val.c_str(), len, &succRes[0]));
        napi_value succCallbackResult = nullptr;
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, nullptr, context.success, SUCCOUNT, succRes, &succCallbackResult));
    }

    if (context.output != E_OK && context.fail != nullptr) {
        napi_value failRes[FAILCOUNT] = { 0 };
        std::string message = GetMessageInfo(context.output);
        len = message.size();
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, message.c_str(), len, &failRes[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, context.output, &failRes[1]));
        napi_value failCallbackResult = nullptr;
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, nullptr, context.fail, FAILCOUNT, failRes, &failCallbackResult));
    }

    if (context.complete != nullptr) {
        napi_value completeCallbackResult = nullptr;
        NAPI_CALL_RETURN_VOID(
            env, napi_call_function(env, nullptr, context.complete, 0, nullptr, &completeCallbackResult));
    }
}

static std::string GetPrefName(napi_env env)
{
    auto ctx = JSAbility::GetContext(env, nullptr);
    return ctx->GetPreferencesDir() + "/default.xml";
}

static int32_t ParseArgs(napi_env env, napi_callback_info info, SyncContext &context)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    NAPI_CALL_BASE(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr), E_ERROR);
    NAPI_ASSERT_BASE(env, argc == 1, "Not enough arguments, expected 1.", E_INVALID_ARGS);
    napi_valuetype valueType = napi_null;
    NAPI_CALL_BASE(env, napi_typeof(env, argv[0], &valueType), E_ERROR);
    NAPI_ASSERT_BASE(env, valueType == napi_object, "Wrong argument type, object expected.", E_INVALID_ARGS);

    ParseString(env, argv[0], "key", true, context.key);
    ParseString(env, argv[0], "value", false, context.val);
    ParseString(env, argv[0], "default", false, context.def);

    ParseFunction(env, argv[0], "success", context.success);
    ParseFunction(env, argv[0], "fail", context.fail);
    ParseFunction(env, argv[0], "complete", context.complete);

    return E_OK;
}

napi_value NapiGet(napi_env env, napi_callback_info info)
{
    SyncContext context {};
    context.output = ParseArgs(env, info, context);
    napi_value ret = nullptr;
    if (context.output != E_OK) {
        CallFunctions(env, context);
        napi_create_int32(env, context.output, &ret);
        return ret;
    }

    if (context.key.size() > MAX_KEY_LENGTH) {
        context.output = E_KEY_EXCEED_LENGTH_LIMIT;
        CallFunctions(env, context);
        napi_create_int32(env, context.output, &ret);
        return ret;
    }

    std::string prefName = GetPrefName(env);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(prefName, context.output);
    std::string tmpValue = pref->GetString(context.key, context.def);
    if (tmpValue.size() > MAX_VALUE_LENGTH) {
        context.output = E_VALUE_EXCEED_LENGTH_LIMIT;
        napi_create_int32(env, context.output, &ret);
        return ret;
    }
    context.val = tmpValue;
    CallFunctions(env, context);

    napi_create_int32(env, E_OK, &ret);
    return ret;
}

napi_value NapiSet(napi_env env, napi_callback_info info)
{
    SyncContext context {};
    context.output = ParseArgs(env, info, context);
    napi_value ret = nullptr;
    if (context.output != E_OK) {
        CallFunctions(env, context);
        napi_create_int32(env, context.output, &ret);
        return ret;
    }

    if (context.key.size() > MAX_KEY_LENGTH) {
        context.output = E_KEY_EXCEED_LENGTH_LIMIT;
        CallFunctions(env, context);
        napi_create_int32(env, context.output, &ret);
        return ret;
    }
    if (context.val.size() > MAX_VALUE_LENGTH) {
        context.output = E_VALUE_EXCEED_LENGTH_LIMIT;
        CallFunctions(env, context);
        napi_create_int32(env, context.output, &ret);
        return ret;
    }

    std::string prefName = GetPrefName(env);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(prefName, context.output);
    if (context.output != E_OK) {
        CallFunctions(env, context);
        return ret;
    }
    context.output = pref->PutString(context.key, context.val);
    pref->FlushSync();
    CallFunctions(env, context);
    napi_create_int32(env, E_OK, &ret);
    return ret;
}

napi_value NapiDelete(napi_env env, napi_callback_info info)
{
    SyncContext context {};
    context.output = ParseArgs(env, info, context);
    napi_value ret = nullptr;
    if (context.output != E_OK) {
        CallFunctions(env, context);
        napi_create_int32(env, context.output, &ret);
        return ret;
    }

    if (context.key.size() > MAX_KEY_LENGTH) {
        context.output = E_KEY_EXCEED_LENGTH_LIMIT;
        CallFunctions(env, context);
        napi_create_int32(env, context.output, &ret);
        return ret;
    }

    std::string prefName = GetPrefName(env);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(prefName, context.output);
    if (context.output != E_OK) {
        napi_create_int32(env, context.output, &ret);
        return ret;
    }
    context.output = pref->Delete(context.key);
    CallFunctions(env, context);
    napi_create_int32(env, E_OK, &ret);
    return ret;
}

napi_value NapiClear(napi_env env, napi_callback_info info)
{
    SyncContext context {};
    context.output = ParseArgs(env, info, context);
    napi_value ret = nullptr;
    if (context.output != E_OK) {
        CallFunctions(env, context);
        napi_create_int32(env, context.output, &ret);
        return ret;
    }

    std::string prefName = GetPrefName(env);
    std::shared_ptr<Preferences> pref = PreferencesHelper::GetPreferences(prefName, context.output);
    if (context.output != E_OK) {
        CallFunctions(env, context);
        napi_create_int32(env, context.output, &ret);
        return ret;
    }
    context.output = pref->Clear();
    CallFunctions(env, context);
    napi_create_int32(env, E_OK, &ret);
    return ret;
}

napi_value InitSystemStorage(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("get", NapiGet),
        DECLARE_NAPI_FUNCTION("delete", NapiDelete),
        DECLARE_NAPI_FUNCTION("clear", NapiClear),
        DECLARE_NAPI_FUNCTION("set", NapiSet),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace SystemStorageJsKit
} // namespace OHOS