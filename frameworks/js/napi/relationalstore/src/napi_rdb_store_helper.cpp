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
#define LOG_TAG "NapiRdbStoreHelper"
#include "napi_rdb_store_helper.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "logger.h"
#include "napi_async_call.h"
#include "napi_rdb_error.h"
#include "napi_rdb_js_utils.h"
#include "napi_rdb_store.h"
#include "napi_rdb_trace.h"
#include "rdb_errno.h"
#include "rdb_open_callback.h"
#include "rdb_store_config.h"
#include "unistd.h"

using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;
using namespace OHOS::AppDataMgrJsKit::JSUtils;

namespace OHOS {
namespace RelationalStoreJsKit {
using ContextParam = AppDataMgrJsKit::JSUtils::ContextParam;

class DefaultOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override
    {
        return E_OK;
    }
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

napi_value GetRdbStore(napi_env env, napi_callback_info info)
{
    struct DeleteContext : public ContextBase {
        ContextParam param;
        RdbConfig config;
        std::shared_ptr<RdbStore> proxy;
    };
    auto context = std::make_shared<DeleteContext>();
    auto input = [context, info](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        int errCode = Convert2Value(env, argv[0], context->param);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal context."));

        errCode = Convert2Value(env, argv[1], context->config);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal StoreConfig or name."));

        auto [code, err] = GetRealPath(env, argv[0], context->config, context->param);
        CHECK_RETURN_SET_E(OK == code, err);
    };
    auto exec = [context]() -> int {
        int errCode = OK;
        DefaultOpenCallback callback;
        context->proxy =
            RdbHelper::GetRdbStore(GetRdbStoreConfig(context->config, context->param), -1, callback, errCode);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = RdbStoreProxy::NewInstance(env, context->proxy, context->param.isSystemApp);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value DeleteRdbStore(napi_env env, napi_callback_info info)
{
    struct DeleteContext : public ContextBase {
        ContextParam param;
        RdbConfig config;
    };
    auto context = std::make_shared<DeleteContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        int errCode = Convert2Value(env, argv[0], context->param);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal context."));

        if (IsNapiString(env, argv[1])) {
            errCode = Convert2Value(env, argv[1], context->config.name);
            CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal path."));
        } else {
            errCode = Convert2Value(env, argv[1], context->config);
            CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal StoreConfig or name."));
        }

        auto [code, err] = GetRealPath(env, argv[0], context->config, context->param);
        CHECK_RETURN_SET_E(OK == code, err);
    };
    auto exec = [context]() -> int {
        return RdbHelper::DeleteRdbStore(context->config.path);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, OK, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value InitRdbHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION_WITH_DATA("getRdbStore", GetRdbStore, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getRdbStoreSync", GetRdbStore, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("deleteRdbStore", DeleteRdbStore, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("deleteRdbStoreSync", DeleteRdbStore, SYNC),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace RelationalStoreJsKit
} // namespace OHOS
