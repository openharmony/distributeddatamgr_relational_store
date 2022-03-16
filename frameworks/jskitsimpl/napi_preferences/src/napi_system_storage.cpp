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

#include <string>
#include <linux/limits.h>
#include "js_logger.h"
#include "js_utils.h"
#include "napi_system_storage.h"

namespace OHOS {
namespace SystemStorageJsKit {
typedef struct {
    std::string key;
    std::string def;
    std::string val;
    napi_ref success;
    napi_ref fail;
    napi_ref complete;
    napi_status output = napi_generic_failure;
    napi_async_work request;
} AsyncContext;

void ParseString(napi_env env, napi_value &object, const char *name, const bool enable, std::string &output)
{
    napi_value value = nullptr;
    if (napi_get_named_property(env, object, name, &value) == napi_ok) {
        std::string key =
            AppDataMgrJsKit::JSUtils::Convert2String(env, value, AppDataMgrJsKit::JSUtils::DEFAULT_BUF_SIZE);
        NAPI_ASSERT_RETURN_VOID(env, enable && !key.empty(), "StorageOptions is empty.");
        output = std::move(key);
    }
}

void ParseFunction(napi_env env, napi_value &object, const char *name, napi_ref &output)
{
    napi_value value = nullptr;
    if (napi_get_named_property(env, object, name, &value) == napi_ok) {
        napi_valuetype valueType = napi_null;
        NAPI_CALL_RETURN_VOID(env, napi_typeof(env, value, &valueType));
        NAPI_ASSERT_RETURN_VOID(env, valueType == napi_function, "Wrong argument, function expected.");
        NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, value, 1, &output));
    }
}
void complete(napi_env env, napi_status status, void *data)
{
    AsyncContext *ctx = static_cast<AsyncContext *>(data);
    if (status != napi_ok) {
        napi_throw_type_error(env, nullptr, "Execute callback failed.");
        return;
    }
    napi_value successCallBack;
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, ctx->success, &successCallBack));
    napi_value result;
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, successCallBack, 0, nullptr, &result));

    napi_delete_reference(env, ctx->success);
    napi_delete_reference(env, ctx->fail);
    napi_delete_reference(env, ctx->complete);
    napi_delete_async_work(env, ctx->request);

    delete ctx;
}
napi_value Operate(napi_env env, napi_callback_info info, const char *resource, napi_async_execute_callback execute)
{
    size_t argc = 1;
    napi_value argv[1];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    NAPI_ASSERT(env, argc == 1, "Not enough arguments, expected 1.");
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    NAPI_ASSERT(env, valueType == napi_object, "Wrong argument type, object expected.");

    AsyncContext *context = new AsyncContext();

    ParseString(env, argv[0], "key", true, context->key);
    ParseString(env, argv[0], "value", false, context->val);
    ParseString(env, argv[0], "default", false, context->def);

    ParseFunction(env, argv[0], "success", context->success);
    ParseFunction(env, argv[0], "fail", context->fail);
    ParseFunction(env, argv[0], "complete", context->complete);

    napi_value resourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, resource, NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, execute,
                       complete, context, &context->request));
    NAPI_CALL(env, napi_queue_async_work(env, context->request));

    napi_value ret = nullptr;
    napi_get_undefined(env, &ret);
    return ret;
}

napi_value NapiGet(napi_env env, napi_callback_info info)
{
    return Operate(env, info, "get", [](napi_env env, void *data) {
        AsyncContext *context = static_cast<AsyncContext *>(data);
        context->val = context->def;
        context->output = napi_ok;
    });
}

napi_value InitSystemStorage(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("get", NapiGet),
        DECLARE_NAPI_FUNCTION("delete", NapiGet),
        DECLARE_NAPI_FUNCTION("clear", NapiGet),
        DECLARE_NAPI_FUNCTION("set", NapiGet),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace SystemStorageJsKit
} // namespace OHOS