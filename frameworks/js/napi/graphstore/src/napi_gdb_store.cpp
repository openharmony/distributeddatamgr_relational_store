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
#define LOG_TAG "GdbStoreProxy"
#include "napi_gdb_store.h"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <vector>

#include "js_utils.h"
#include "logger.h"
#include "napi_gdb_context.h"
#include "napi_gdb_error.h"
#include "napi_gdb_js_utils.h"

namespace OHOS::GraphStoreJsKit {

GdbStoreProxy::GdbStoreProxy()
{
}

GdbStoreProxy::~GdbStoreProxy()
{
}

GdbStoreProxy::GdbStoreProxy(std::shared_ptr<DBStore> gdbStore)
{
    if (GetInstance() == gdbStore) {
        return;
    }
    SetInstance(std::move(gdbStore));
}

GdbStoreProxy &GdbStoreProxy::operator=(std::shared_ptr<DBStore> gdbStore)
{
    if (GetInstance() == gdbStore) {
        return *this;
    }
    SetInstance(std::move(gdbStore));
    return *this;
}

bool GdbStoreProxy::IsSystemAppCalled()
{
    return isSystemAppCalled_;
}

Descriptor GdbStoreProxy::GetDescriptors()
{
    return []() -> std::vector<napi_property_descriptor> {
        std::vector<napi_property_descriptor> properties = {
            DECLARE_NAPI_FUNCTION("read", Read),
            DECLARE_NAPI_FUNCTION("write", Write),
            DECLARE_NAPI_FUNCTION("close", Close),
        };
        return properties;
    };
}

void GdbStoreProxy::Init(napi_env env, napi_value exports)
{
    auto jsCtor = OHOS::AppDataMgrJsKit::JSUtils::DefineClass(
        env, "ohos.data.graphStore", "GraphStore", GetDescriptors(), Initialize, true);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "GraphStore", jsCtor));
}

void GdbStoreProxy::Destructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    auto *obj = static_cast<GdbStoreProxy *>(nativeObject);
    delete obj;
}

napi_value GdbStoreProxy::New(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1] = { 0 };
    napi_value thisVar = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr);

    // get native object
    auto *obj = new GdbStoreProxy();
    ASSERT_CALL(env,
        napi_wrap(env, thisVar, obj, GdbStoreProxy::Destructor,
            nullptr, // finalize_hint
            nullptr),
        obj);
    return thisVar;
}

napi_value GdbStoreProxy::Initialize(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, NULL, NULL, &self, nullptr));
    auto finalize = [](napi_env env, void *data, void *hint) {
        if (data != hint) {
            LOG_ERROR("GdbStoreProxy memory corrupted! data:0x%016" PRIXPTR "hint:0x%016" PRIXPTR, uintptr_t(data),
                uintptr_t(hint));
            return;
        }
        GdbStoreProxy *proxy = reinterpret_cast<GdbStoreProxy *>(data);
        proxy->SetInstance(nullptr);
        delete proxy;
    };
    auto *proxy = new (std::nothrow) GdbStoreProxy();
    if (proxy == nullptr) {
        return nullptr;
    }
    napi_status status = napi_wrap_sendable(env, self, proxy, finalize, proxy);
    if (status != napi_ok) {
        LOG_ERROR("GdbStoreProxy napi_wrap failed! code:%{public}d!", status);
        finalize(env, proxy, proxy);
        return nullptr;
    }
    return self;
}

napi_value GdbStoreProxy::NewInstance(napi_env env, std::shared_ptr<DBStore> value, bool isSystemAppCalled)
{
    if (value == nullptr) {
        LOG_ERROR("dbstore is nullptr");
        return nullptr;
    }
    napi_value cons = OHOS::AppDataMgrJsKit::JSUtils::GetClass(env, "ohos.data.graphStore", "GraphStore");
    if (cons == nullptr) {
        LOG_ERROR("Constructor of ResultSet is nullptr!");
        return nullptr;
    }

    napi_value instance = nullptr;
    auto status = napi_new_instance(env, cons, 0, nullptr, &instance);
    if (status != napi_ok) {
        LOG_ERROR("GdbStoreProxy::NewInstance napi_new_instance failed! code:%{public}d!", status);
        return nullptr;
    }

    GdbStoreProxy *proxy = nullptr;
    status = napi_unwrap_sendable(env, instance, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("GdbStoreProxy::NewInstance native instance is nullptr! code:%{public}d!", status);
        return instance;
    }
    proxy->queue_ = std::make_shared<AppDataMgrJsKit::UvQueue>(env);
    proxy->SetInstance(std::move(value));
    proxy->isSystemAppCalled_ = isSystemAppCalled;
    return instance;
}

GdbStoreProxy *GetNativeInstance(napi_env env, napi_value self)
{
    GdbStoreProxy *proxy = nullptr;
    napi_status status = napi_unwrap_sendable(env, self, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("GdbStoreProxy native instance is nullptr! code:%{public}d!", status);
        return nullptr;
    }
    return proxy;
}

int ParseThis(const napi_env &env, const napi_value &self, const std::shared_ptr<GdbStoreContext> &context)
{
    GdbStoreProxy *obj = GetNativeInstance(env, self);
    CHECK_RETURN_SET(obj != nullptr, std::make_shared<ParamError>("GdbStore", "not nullptr."));
    CHECK_RETURN_SET(obj->GetInstance() != nullptr, std::make_shared<InnerError>(E_GRD_DB_INSTANCE_ABNORMAL));
    context->boundObj = obj;
    context->gdbStore = obj->GetInstance();
    return OK;
}

int ParseGql(const napi_env env, const napi_value arg, const std::shared_ptr<GdbStoreContext> &context)
{
    context->gql = OHOS::AppDataMgrJsKit::JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->gql.empty(), std::make_shared<ParamError>("gql", "not empty"));
    CHECK_RETURN_SET(context->gql.size() <= GdbStoreProxy::MAX_GQL_LEN,
        std::make_shared<ParamError>("gql", "too long"));
    return OK;
}

napi_value GdbStoreProxy::Read(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<GdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1, std::make_shared<ParamNumError>(" 1 "));
        CHECK_RETURN(OK == ParseThis(env, self, context));
        CHECK_RETURN(OK == ParseGql(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->gdbStore != nullptr);
        auto gdbStore = std::move(context->gdbStore);
        auto queryResult = gdbStore->QueryGql(context->gql);
        context->result = queryResult.second;
        context->intOutput = queryResult.first;
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = AppDataMgrJsKit::JSUtils::Convert2Sendable(env, context->result);
        CHECK_RETURN_SET_E(context->intOutput == OK, std::make_shared<InnerError>(context->intOutput));
    };
    context->SetAction(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value GdbStoreProxy::Write(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<GdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1, std::make_shared<ParamNumError>(" 1 "));
        CHECK_RETURN(OK == ParseThis(env, self, context));
        CHECK_RETURN(OK == ParseGql(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->gdbStore != nullptr);
        auto gdbStore = std::move(context->gdbStore);
        auto executeResult = gdbStore->ExecuteGql(context->gql);
        context->result = executeResult.second;
        context->intOutput = executeResult.first;
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = AppDataMgrJsKit::JSUtils::Convert2Sendable(env, context->result);
        CHECK_RETURN_SET_E(context->intOutput == OK, std::make_shared<InnerError>(context->intOutput));
    };
    context->SetAction(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value GdbStoreProxy::Close(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<GdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        GdbStoreProxy *proxy = GetNativeInstance(env, self);
        CHECK_RETURN_SET(proxy != nullptr, std::make_shared<ParamError>("GdbStore", "not nullptr."));
        if (proxy->GetInstance() == nullptr) {
            LOG_WARN("GdbStoreProxy native instance is nullptr!");
            return OK;
        }
        context->boundObj = proxy;
        context->gdbStore = proxy->GetInstance();

        auto *obj = reinterpret_cast<GdbStoreProxy *>(context->boundObj);
        obj->SetInstance(nullptr);
        return OK;
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->gdbStore != nullptr);
        context->gdbStore = nullptr;
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}
} // namespace OHOS::GraphStoreJsKit