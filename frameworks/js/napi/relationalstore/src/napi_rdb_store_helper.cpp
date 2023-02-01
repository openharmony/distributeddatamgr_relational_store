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
#include <functional>
#include <string>
#include <vector>

#include "js_ability.h"
#include "js_logger.h"
#include "js_utils.h"
#include "napi_async_call.h"
#include "napi_rdb_error.h"
#include "napi_rdb_store.h"
#include "napi_rdb_store_helper.h"
#include "napi_rdb_trace.h"
#include "rdb_errno.h"
#include "rdb_open_callback.h"
#include "rdb_store_config.h"
#include "sqlite_database_utils.h"
#include "unistd.h"

using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS {
namespace RelationalStoreJsKit {
struct HelperRdbContext : public Context {
    RdbStoreConfig config;
    std::shared_ptr<RdbStore> proxy;
    std::shared_ptr<OHOS::AppDataMgrJsKit::Context> abilitycontext;
    bool isSystemAppCalled;

    HelperRdbContext() : config(""), proxy(nullptr), isSystemAppCalled(false)
    {
    }
    virtual ~HelperRdbContext(){};
};

void ParserThis(const napi_env &env, const napi_value &self, std::shared_ptr<HelperRdbContext> context)
{
    napi_unwrap(env, self, &context->boundObj);
}

int ParseContext(const napi_env &env, const napi_value &object, std::shared_ptr<HelperRdbContext> context)
{
    auto abilitycontext = JSAbility::GetContext(env, object);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("context", "a Context.");
    RDB_CHECK_RETURN_CALL_RESULT(abilitycontext != nullptr, context->SetError(paramError));
    context->abilitycontext = abilitycontext;
    return OK;
}

int ParseDatabaseName(const napi_env &env, const napi_value &object, std::shared_ptr<HelperRdbContext> context)
{
    napi_value value;
    napi_get_named_property(env, object, "name", &value);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("config", "a StoreConfig.");
    RDB_CHECK_RETURN_CALL_RESULT(value != nullptr, context->SetError(paramError));

    std::string name = JSUtils::Convert2String(env, value);
    RDB_CHECK_RETURN_CALL_RESULT(!name.empty(), context->SetError(paramError));
    if (name.find("/") != std::string::npos) {
        paramError = std::make_shared<ParamTypeError>("StoreConfig.name", "a file name without path");
        RDB_CHECK_RETURN_CALL_RESULT(false, context->SetError(paramError));
    }

    context->config.SetName(std::move(name));
    return OK;
}

int ParseIsEncrypt(const napi_env &env, const napi_value &object, std::shared_ptr<HelperRdbContext> context)
{
    napi_value value = nullptr;
    napi_status status = napi_get_named_property(env, object, "encrypt", &value);
    if (status == napi_ok && value != nullptr) {
        bool isEncrypt = false;
        JSUtils::Convert2Bool(env, value, isEncrypt);
        context->config.SetEncryptStatus(isEncrypt);
    }
    return OK;
}

int ParseContextProperty(const napi_env &env, std::shared_ptr<HelperRdbContext> context)
{
    if (context->abilitycontext == nullptr) {
        int status = ParseContext(env, nullptr, context); // when no context as arg got from application.
        std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("context", "a Context.");
        RDB_CHECK_RETURN_CALL_RESULT(status == OK, context->SetError(paramError));
    }
    context->config.SetModuleName(context->abilitycontext->GetModuleName());
    context->config.SetArea(context->abilitycontext->GetArea());
    context->config.SetBundleName(context->abilitycontext->GetBundleName());
    context->config.SetUri(context->abilitycontext->GetUri());
    context->config.SetReadPermission(context->abilitycontext->GetReadPermission());
    context->config.SetWritePermission(context->abilitycontext->GetWritePermission());
    context->isSystemAppCalled = context->abilitycontext->IsSystemAppCalled();
    return OK;
}

int ParseDatabaseDir(const napi_env &env, std::shared_ptr<HelperRdbContext> context)
{
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("context", "a Context.");
    RDB_CHECK_RETURN_CALL_RESULT(context->abilitycontext != nullptr, context->SetError(paramError));
    int errorCode = E_OK;
    std::string databaseName = context->config.GetName();
    std::string databaseDir = context->abilitycontext->GetDatabaseDir();
    std::string realPath = SqliteDatabaseUtils::GetDefaultDatabasePath(databaseDir, databaseName, errorCode);
    paramError = std::make_shared<ParamTypeError>("config", "a StoreConfig.");
    RDB_CHECK_RETURN_CALL_RESULT(errorCode == E_OK, context->SetError(paramError));
    context->config.SetPath(std::move(realPath));
    return OK;
}

int ParseSecurityLevel(const napi_env &env, const napi_value &object, std::shared_ptr<HelperRdbContext> context)
{
    napi_value value = nullptr;
    bool hasProp = false;
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("config", "a StoreConfig.");
    napi_status status = napi_has_named_property(env, object, "securityLevel", &hasProp);
    if (status != napi_ok || !hasProp) {
        LOG_ERROR("napi_has_named_property failed! code:%{public}d!, hasProp:%{public}d!", status, hasProp);
        RDB_CHECK_RETURN_CALL_RESULT(false, context->SetError(paramError));
    }
    status = napi_get_named_property(env, object, "securityLevel", &value);
    if (status != napi_ok) {
        LOG_ERROR("napi_get_named_property failed! code:%{public}d!", status);
        RDB_CHECK_RETURN_CALL_RESULT(false, context->SetError(paramError));
    }

    int32_t securityLevel;
    napi_get_value_int32(env, value, &securityLevel);
    SecurityLevel sl = static_cast<SecurityLevel>(securityLevel);
    LOG_DEBUG("Get sl:%{public}d", securityLevel);

    bool isValidSecurityLevel = sl >= SecurityLevel::S1 && sl < SecurityLevel::LAST;
    if (!isValidSecurityLevel) {
        LOG_ERROR("The securityLevel should be S1-S4!");
        RDB_CHECK_RETURN_CALL_RESULT(false, context->SetError(paramError));
    }
    context->config.SetSecurityLevel(sl);

    LOG_DEBUG("ParseSecurityLevel end");
    return OK;
}

int ParseStoreConfig(const napi_env &env, const napi_value &object, std::shared_ptr<HelperRdbContext> context)
{
    RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseDatabaseName(env, object, context));
    RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseIsEncrypt(env, object, context));
    RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseSecurityLevel(env, object, context));
    RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseContextProperty(env, context));
    RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseDatabaseDir(env, context));
    return OK;
}

int ParsePath(const napi_env &env, const napi_value &arg, std::shared_ptr<HelperRdbContext> context)
{
    std::string path = JSUtils::Convert2String(env, arg);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("name", "a without path non empty string.");
    RDB_CHECK_RETURN_CALL_RESULT(!path.empty(), context->SetError(paramError));

    size_t pos = path.find_first_of('/');
    RDB_CHECK_RETURN_CALL_RESULT(pos == std::string::npos, context->SetError(paramError));

    std::string databaseDir = context->abilitycontext->GetDatabaseDir();
    int errorCode = E_OK;
    std::string realPath = SqliteDatabaseUtils::GetDefaultDatabasePath(databaseDir, path, errorCode);
    RDB_CHECK_RETURN_CALL_RESULT(errorCode == E_OK, context->SetError(paramError));

    context->config.SetPath(realPath);
    return OK;
}

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
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RelationalStoreJsKit::GetRdbStore start");
    auto context = std::make_shared<HelperRdbContext>();
    auto input = [context, info](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("context", "a Context.");
        RDB_CHECK_RETURN_CALL_RESULT(JSAbility::CheckContext(env, info), context->SetError(paramError));

        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseContext(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseStoreConfig(env, argv[1], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RelationalStoreJsKit::GetRdbStore Async");
        int errCode = OK;
        DefaultOpenCallback callback;
        context->proxy = RdbHelper::GetRdbStore(context->config, -1, callback, errCode);
        std::shared_ptr<Error> dbInvalidError = std::make_shared<DbInvalidError>();
        RDB_CHECK_RETURN_CALL_RESULT(errCode == E_OK && context->proxy != nullptr, context->SetError(dbInvalidError));
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        result = RdbStoreProxy::NewInstance(env, context->proxy, context->isSystemAppCalled);
        LOG_DEBUG("RelationalStoreJsKit::GetRdbStore end");
        return (result != nullptr) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value DeleteRdbStore(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RelationalStoreJsKit::DeleteRdbStore start");
    auto context = std::make_shared<HelperRdbContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseContext(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePath(env, argv[1], context));
        return OK;
    };
    auto exec = [context]() -> int {
        int errCode = RdbHelper::DeleteRdbStore(context->config.GetPath());
        LOG_DEBUG("RelationalStoreJsKit::DeleteRdbStore failed %{public}d", errCode);
        std::shared_ptr<Error> dbInvalidError = std::make_shared<DbInvalidError>();
        RDB_CHECK_RETURN_CALL_RESULT(errCode != E_EMPTY_FILE_NAME, context->SetError(dbInvalidError));
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_create_int64(env, OK, &result);
        LOG_DEBUG("RelationalStoreJsKit::DeleteRdbStore end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value InitRdbHelper(napi_env env, napi_value exports)
{
    LOG_INFO("RelationalStoreJsKit::InitRdbHelper begin");
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getRdbStore", GetRdbStore),
        DECLARE_NAPI_FUNCTION("deleteRdbStore", DeleteRdbStore),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    LOG_INFO("RelationalStoreJsKit::InitRdbHelper end");
    return exports;
}
} // namespace RelationalStoreJsKit
} // namespace OHOS