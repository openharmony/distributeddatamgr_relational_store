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
namespace RdbJsKit {
const int APIVERSION_V9 = 9;
const int APIVERSION_V8 = 8;

class OpenCallback : public OHOS::NativeRdb::RdbOpenCallback {
public:
    OpenCallback() = default;

    OpenCallback(napi_env env, napi_value jsObj) : env_(env)
    {
        napi_create_reference(env, jsObj, 1, &ref_);
        napi_value property;
        napi_get_named_property(env_, jsObj, "onOpen", &property);
        napi_create_reference(env, property, 1, &onOpen_);
        napi_get_named_property(env_, jsObj, "onCreate", &property);
        napi_create_reference(env, property, 1, &onCreate_);
        napi_get_named_property(env_, jsObj, "onUpgrade", &property);
        napi_create_reference(env, property, 1, &onUpgrade_);
        napi_get_named_property(env_, jsObj, "onDowngrade", &property);
        napi_create_reference(env, property, 1, &onDowngrade_);
    }

    ~OpenCallback()
    {
        if (env_ != nullptr) {
            napi_delete_reference(env_, ref_);
            napi_delete_reference(env_, onOpen_);
            napi_delete_reference(env_, onCreate_);
            napi_delete_reference(env_, onUpgrade_);
            napi_delete_reference(env_, onDowngrade_);
        }
    }

    OpenCallback(const OpenCallback &obj) = delete;

    OpenCallback &operator=(const OpenCallback &obj) = delete;

    OpenCallback(OpenCallback &&obj) noexcept
    {
        operator=(std::move(obj));
    }

    OpenCallback &operator=(OpenCallback &&obj) noexcept
    {
        if (this == &obj) {
            return *this;
        }
        if (env_ != nullptr && ref_ != nullptr) {
            napi_delete_reference(env_, ref_);
        }
        env_ = obj.env_;
        ref_ = obj.ref_;
        onOpen_ = obj.onOpen_;
        onCreate_ = obj.onCreate_;
        onDowngrade_ = obj.onDowngrade_;
        onUpgrade_ = obj.onUpgrade_;
        callbacks_ = std::move(obj.callbacks_);
        obj.env_ = nullptr;
        obj.ref_ = nullptr;
        obj.onOpen_ = nullptr;
        obj.onCreate_ = nullptr;
        obj.onDowngrade_ = nullptr;
        obj.onUpgrade_ = nullptr;
        return *this;
    }

    int OnCreate(OHOS::NativeRdb::RdbStore &rdbStore) override
    {
        callbacks_.emplace_back([this]() -> int {
            napi_value self;
            napi_status status = napi_get_reference_value(env_, ref_, &self);
            if (status != napi_ok) {
                LOG_ERROR("OnCreate get self reference failed, code:%{public}d", status);
                return E_ERROR;
            }
            napi_value method;
            status = napi_get_reference_value(env_, onCreate_, &method);
            if (status != napi_ok) {
                LOG_ERROR("OnCreate get method reference failed, code:%{public}d", status);
                return E_ERROR;
            }
            napi_value retValue = nullptr;
            status = napi_call_function(env_, self, method, 0, nullptr, &retValue);
            if (status != napi_ok) {
                LOG_ERROR("OnCreate call js method failed, code:%{public}d", status);
                return E_ERROR;
            }
            return E_OK;
        });
        return E_OK;
    }

    int OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        callbacks_.emplace_back([this, oldVersion, newVersion]() -> int {
            napi_value self;
            napi_status status = napi_get_reference_value(env_, ref_, &self);
            if (status != napi_ok) {
                LOG_ERROR("OnUpgrade get self reference failed, code:%{public}d", status);
                return E_ERROR;
            }
            napi_value method;
            status = napi_get_reference_value(env_, onUpgrade_, &method);
            if (status != napi_ok) {
                LOG_ERROR("OnUpgrade get method reference failed, code:%{public}d", status);
                return E_ERROR;
            }
            napi_value result[JSUtils::ASYNC_RST_SIZE] = { 0 };
            napi_get_undefined(env_, &result[0]);
            napi_create_object(env_, &result[1]);
            napi_value version;
            napi_create_int32(env_, newVersion, &version);
            napi_set_named_property(env_, result[1], "currentVersion", version);
            napi_create_int32(env_, oldVersion, &version);
            napi_set_named_property(env_, result[1], "targetVersion", version);
            napi_value retValue = nullptr;
            status = napi_call_function(env_, self, method, JSUtils::ASYNC_RST_SIZE, result, &retValue);
            if (status != napi_ok) {
                LOG_ERROR("OnUpgrade call js method failed, code:%{public}d", status);
                return E_ERROR;
            }
            return E_OK;
        });
        return E_OK;
    }

    int OnDowngrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        callbacks_.emplace_back([this, oldVersion, newVersion]() -> int {
            napi_value self;
            napi_status status = napi_get_reference_value(env_, ref_, &self);
            if (status != napi_ok) {
                LOG_ERROR("OnDowngrade get self reference failed, code:%{public}d", status);
                return E_ERROR;
            }
            napi_value method;
            status = napi_get_reference_value(env_, onDowngrade_, &method);
            if (status != napi_ok) {
                LOG_ERROR("OnDowngrade get method reference failed, code:%{public}d", status);
                return E_ERROR;
            }
            napi_value result[JSUtils::ASYNC_RST_SIZE] = { 0 };
            napi_get_undefined(env_, &result[0]);
            napi_create_object(env_, &result[1]);
            napi_value version;
            napi_create_int32(env_, newVersion, &version);
            napi_set_named_property(env_, result[1], "currentVersion", version);
            napi_create_int32(env_, oldVersion, &version);
            napi_set_named_property(env_, result[1], "targetVersion", version);
            napi_value retValue = nullptr;
            status = napi_call_function(env_, self, method, JSUtils::ASYNC_RST_SIZE, result, &retValue);
            if (status != napi_ok) {
                LOG_ERROR("OnDowngrade call js method failed, code:%{public}d", status);
                return E_ERROR;
            }
            return E_OK;
        });
        return E_OK;
    }

    int OnOpen(OHOS::NativeRdb::RdbStore &rdbStore) override
    {
        callbacks_.emplace_back([this]() -> int {
            napi_value self;
            napi_status status = napi_get_reference_value(env_, ref_, &self);
            if (status != napi_ok) {
                LOG_ERROR("OnOpen get self reference failed, code:%{public}d", status);
                return E_ERROR;
            }
            napi_value method;
            status = napi_get_reference_value(env_, onOpen_, &method);
            if (status != napi_ok) {
                LOG_ERROR("OnOpen get method reference failed, code:%{public}d", status);
                return E_ERROR;
            }
            napi_value retValue = nullptr;
            status = napi_call_function(env_, self, method, 0, nullptr, &retValue);
            if (status != napi_ok) {
                LOG_ERROR("OnOpen call js method failed, code:%{public}d", status);
                return E_ERROR;
            }
            return E_OK;
        });
        return E_OK;
    }

    void DelayNotify()
    {
        for (auto &callback : callbacks_) {
            callback();
        }
    }

private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
    napi_ref onOpen_ = nullptr;
    napi_ref onCreate_ = nullptr;
    napi_ref onUpgrade_ = nullptr;
    napi_ref onDowngrade_ = nullptr;
    std::vector<std::function<int(void)>> callbacks_;
};

struct HelperRdbContext : public BaseContext {
    RdbStoreConfig config;
    int32_t version;
    bool iscontext;
    OpenCallback openCallback;
    std::shared_ptr<RdbStore> proxy;
    std::shared_ptr<OHOS::AppDataMgrJsKit::Context> abilitycontext;

    HelperRdbContext() : config(""), version(0), iscontext(false), openCallback(), proxy(nullptr)
    {
    }
    virtual ~HelperRdbContext(){};
};

using ParseStoreConfigFunction = int (*)(
    const napi_env &env, const napi_value &object, std::shared_ptr<HelperRdbContext> context);

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
    return OK;
}

int ParseDatabaseDir(const napi_env &env, std::shared_ptr<HelperRdbContext> context)
{
    std::string databaseDir = context->abilitycontext->GetDatabaseDir();
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("context", "a Context.");
    RDB_CHECK_RETURN_CALL_RESULT(context->abilitycontext != nullptr, context->SetError(paramError));
    int errorCode = E_OK;
    std::string databaseName = context->config.GetName();
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

    bool isValidSecurityLevel = sl >= SecurityLevel::S1 && sl < SecurityLevel::LAST;
    if (!isValidSecurityLevel) {
        LOG_ERROR("The securityLevel should be S1-S4!");
        RDB_CHECK_RETURN_CALL_RESULT(false, context->SetError(paramError));
    }
    context->config.SetSecurityLevel(sl);

    return OK;
}

int ParseStoreConfig(const napi_env &env, const napi_value &object, std::shared_ptr<HelperRdbContext> context)
{
    RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseDatabaseName(env, object, context));
    RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseIsEncrypt(env, object, context));
    RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseContextProperty(env, context));
    RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseDatabaseDir(env, context));
    return OK;
}

int ParseStoreConfigV9(const napi_env &env, const napi_value &object, std::shared_ptr<HelperRdbContext> context)
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

    if (context->abilitycontext == nullptr) {
        // when no context as arg got from application.
        ParseContext(env, nullptr, context);
    }
    std::string databaseDir = context->abilitycontext->GetDatabaseDir();
    int errorCode = E_OK;
    std::string realPath = SqliteDatabaseUtils::GetDefaultDatabasePath(databaseDir, path, errorCode);
    RDB_CHECK_RETURN_CALL_RESULT(errorCode == E_OK, context->SetError(paramError));

    context->config.SetPath(realPath);
    return OK;
}

int ParseVersion(const napi_env &env, const napi_value &arg, std::shared_ptr<HelperRdbContext> context)
{
    napi_get_value_int32(env, arg, &context->version);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("version", "an integer greater than 0.");
    RDB_CHECK_RETURN_CALL_RESULT(context->version > 0, context->SetError(paramError));
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

napi_value InnerGetRdbStore(napi_env env, napi_callback_info info, std::shared_ptr<HelperRdbContext> context,
    ParseStoreConfigFunction parseStoreConfig)
{
    context->iscontext = JSAbility::CheckContext(env, info);
    // context: Context, config: StoreConfig, version: number
    auto input = [context, parseStoreConfig](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        if (context->iscontext || context->apiversion > APIVERSION_V8) {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("3 or 4");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 3 || argc == 4, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseContext(env, argv[0], context));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(parseStoreConfig(env, argv[1], context));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseVersion(env, argv[2], context));
        } else {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(parseStoreConfig(env, argv[0], context));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseVersion(env, argv[1], context));
        }
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() -> int {
        int errCode = OK;
        DefaultOpenCallback callback;
        context->proxy = RdbHelper::GetRdbStore(context->config, context->version, callback, errCode);
        std::shared_ptr<Error> dbInvalidError = std::make_shared<DbInvalidError>();
        RDB_CHECK_RETURN_CALL_RESULT(errCode == E_OK && context->proxy != nullptr, context->SetError(dbInvalidError));
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        result = RdbStoreProxy::NewInstance(env, context->proxy, context->apiversion);
        context->openCallback.DelayNotify();
        return (result != nullptr) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value GetRdbStore(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<HelperRdbContext>();
    context->apiversion = APIVERSION_V8;
    return InnerGetRdbStore(env, info, context, ParseStoreConfig);
}

napi_value GetRdbStoreV9(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<HelperRdbContext>();
    context->apiversion = APIVERSION_V9;
    return InnerGetRdbStore(env, info, context, ParseStoreConfigV9);
}

napi_value InnerDeleteRdbStore(napi_env env, napi_callback_info info, std::shared_ptr<HelperRdbContext> context)
{
    context->iscontext = JSAbility::CheckContext(env, info);
    // context: Context, config: StoreConfig, version: number
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        if (context->iscontext || context->apiversion > APIVERSION_V8) {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseContext(env, argv[0], context));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePath(env, argv[1], context));
        } else {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePath(env, argv[0], context));
        }
        return OK;
    };
    auto exec = [context]() -> int {
        int errCode = RdbHelper::DeleteRdbStore(context->config.GetPath());
        std::shared_ptr<Error> dbInvalidError = std::make_shared<DbInvalidError>();
        RDB_CHECK_RETURN_CALL_RESULT(errCode != E_EMPTY_FILE_NAME, context->SetError(dbInvalidError));
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_create_int64(env, OK, &result);
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);
    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value DeleteRdbStore(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<HelperRdbContext>();
    context->apiversion = APIVERSION_V8;
    return InnerDeleteRdbStore(env, info, context);
}

napi_value DeleteRdbStoreV9(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<HelperRdbContext>();
    context->apiversion = APIVERSION_V9;
    return InnerDeleteRdbStore(env, info, context);
}

napi_value InitRdbHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("getRdbStore", GetRdbStore),
        DECLARE_NAPI_FUNCTION("deleteRdbStore", DeleteRdbStore),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace RdbJsKit
} // namespace OHOS
