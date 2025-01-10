/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "GdbStoreHelperProxy"
#include "napi_gdb_store_helper.h"

#include <regex>

#include "gdb_helper.h"
#include "logger.h"
#include "napi_gdb_context.h"
#include "napi_gdb_js_utils.h"
#include "napi_gdb_store.h"

namespace OHOS::GraphStoreJsKit {
using namespace OHOS::DistributedDataAip;

static constexpr int MAX_GDB_DB_NAME_LENGTH = 128;

bool IsValidDbName(const std::string &name)
{
    if (name.empty() || name.size() > MAX_GDB_DB_NAME_LENGTH) {
        return false;
    }
    const std::regex pattern("^[a-zA-Z0-9_]+$");
    return std::regex_match(name, pattern);
}

napi_value GetStore(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<GdbStoreContext>();
    auto input = [context, info](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>(" 2 "));
        int errCode = AppDataMgrJsKit::JSUtils::Convert2Value(env, argv[0], context->param);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal context."));
        CHECK_RETURN_SET_E(context->param.isSystemApp, std::make_shared<NonSystemError>());
        errCode = AppDataMgrJsKit::JSUtils::Convert2Value(env, argv[1], context->config);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal StoreConfig or name."));
        CHECK_RETURN_SET_E(IsValidDbName(context->config.GetName()), std::make_shared<ParamError>("Illegal name."));
        auto [code, err] = AppDataMgrJsKit::JSUtils::GetRealPath(context->config, context->param);
        CHECK_RETURN_SET_E(OK == code, err);
    };
    auto exec = [context]() -> int {
        context->gdbStore = GDBHelper::GetDBStore(context->config, context->intOutput);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        CHECK_RETURN_SET_E(context->intOutput == OK, std::make_shared<InnerError>(context->intOutput));
        result = GdbStoreProxy::NewInstance(env, context->gdbStore, context->param.isSystemApp);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_INNER_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value DeleteStore(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<GdbStoreContext>();
    auto input = [context, info](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>(" 2 "));
        int errCode = AppDataMgrJsKit::JSUtils::Convert2Value(env, argv[0], context->param);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal context."));
        CHECK_RETURN_SET_E(context->param.isSystemApp, std::make_shared<NonSystemError>());
        errCode = AppDataMgrJsKit::JSUtils::Convert2Value(env, argv[1], context->config);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal StoreConfig or name."));
        CHECK_RETURN_SET_E(IsValidDbName(context->config.GetName()), std::make_shared<ParamError>("Illegal name."));
        auto [code, err] = AppDataMgrJsKit::JSUtils::GetRealPath(context->config, context->param);
        CHECK_RETURN_SET_E(OK == code, err);
    };
    auto exec = [context]() -> int {
        context->intOutput = GDBHelper::DeleteDBStore(context->config);
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        CHECK_RETURN_SET_E(context->intOutput == OK, std::make_shared<InnerError>(context->intOutput));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value InitGdbHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION_WITH_DATA("getStore", GetStore, AIP_ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("deleteStore", DeleteStore, AIP_ASYNC),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace OHOS::GraphStoreJsKit