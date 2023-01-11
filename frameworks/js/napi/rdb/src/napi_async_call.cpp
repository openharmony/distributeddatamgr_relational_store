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

#include "js_logger.h"
#include "napi_async_call.h"
#include "napi_rdb_trace.h"

namespace OHOS {
namespace AppDataMgrJsKit {
AsyncCall::AsyncCall(napi_env env, napi_callback_info info, std::shared_ptr<Context> context) : env_(env)
{
    context->_env = env;
    size_t argc = MAX_INPUT_COUNT;
    napi_value self = nullptr;
    napi_value argv[MAX_INPUT_COUNT] = { nullptr };
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, &self, nullptr));

    context_ = new AsyncContext(env);
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, argv[argc - 1], &valueType);
    if (valueType == napi_function) {
        LOG_DEBUG("asyncCall set callback");
        NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, argv[argc - 1], 1, &context_->callback));
        argc = argc - 1;
    }
    // int -->input_(env, argc, argv, self)
    int status = (*context)(env, argc, argv, self);
    // if input return is not ok, then napi_throw_error context error
    RDB_NAPI_ASSERT_RETURN_VOID_FROMV9(env, status == OK, context->error, context->apiversion);
    context_->ctx = std::move(context);
    napi_create_reference(env, self, 1, &context_->self);
}

AsyncCall::~AsyncCall()
{
    if (context_ == nullptr) {
        return;
    }

    delete context_;
}

napi_value AsyncCall::Call(napi_env env, Context::ExecAction exec)
{
    // if input throw error , then context_->ctx is nullptr, then return nullptr, worker stop;
    if ((context_ == nullptr) || (context_->ctx == nullptr)) {
        LOG_DEBUG("context_ or context_->ctx is null");
        return nullptr;
    }
    LOG_DEBUG("async call exec begin");
    context_->ctx->exec_ = std::move(exec);
    napi_value promise = nullptr;
    if (context_->callback == nullptr) {
        napi_create_promise(env, &context_->defer, &promise);
    } else {
        napi_get_undefined(env, &promise);
    }
    napi_async_work work = context_->work;
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "AsyncCall", NAPI_AUTO_LENGTH, &resource);
    // create async work, execute function is OnExecute, complete function is OnComplete
    napi_create_async_work(env, nullptr, resource, AsyncCall::OnExecute, AsyncCall::OnComplete, context_, &work);
    context_->work = work;
    context_ = nullptr;
    // add async work to execute queue
    napi_queue_async_work(env, work);
    LOG_DEBUG("async call exec end");
    return promise;
}

// sync call, no used.
napi_value AsyncCall::SyncCall(napi_env env, AsyncCall::Context::ExecAction exec)
{
    if ((context_ == nullptr) || (context_->ctx == nullptr)) {
        LOG_DEBUG("context_ or context_->ctx is null");
        return nullptr;
    }
    context_->ctx->exec_ = std::move(exec);
    napi_value promise = nullptr;
    if (context_->callback == nullptr) {
        napi_create_promise(env, &context_->defer, &promise);
    } else {
        napi_get_undefined(env, &promise);
    }
    AsyncCall::OnExecute(env, context_);
    AsyncCall::OnComplete(env, napi_ok, context_);
    return promise;
}

void AsyncCall::OnExecute(napi_env env, void *data)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("run the async runnable");
    AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
    context->ctx->execStatus = context->ctx->Exec();
}

void AsyncCall::SetBusinessError(napi_env env, napi_value *businessError, std::shared_ptr<Error> error, int apiversion)
{
    LOG_DEBUG("SetBusinessError enter");
    napi_value code = nullptr;
    napi_value msg = nullptr;
    napi_create_object(env, businessError);
    if (apiversion < APIVERSION_V9) {
        napi_create_string_utf8(env, "async error.", NAPI_AUTO_LENGTH, &msg);
        napi_set_named_property(env, *businessError, "message", msg);
        return;
    }
    // if error is not inner error
    if (error != nullptr && error->GetCode() != E_INNER_ERROR) {
        LOG_DEBUG("SetBusinessError enter V9");
        napi_create_int32(env, error->GetCode(), &code);
        napi_create_string_utf8(env, error->GetMessage().c_str(), NAPI_AUTO_LENGTH, &msg);
        napi_set_named_property(env, *businessError, "code", code);
        napi_set_named_property(env, *businessError, "message", msg);
    }
}

void AsyncCall::OnComplete(napi_env env, napi_status status, void *data)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("run the js callback function");
    AsyncContext *context = reinterpret_cast<AsyncContext *>(data);
    napi_value output = nullptr;
    int outStatus = ERR;
    // if async execute status is not napi_ok then un-execute out function
    if (context->ctx->execStatus == OK) {
        outStatus = (*context->ctx)(env, output);
    }
    napi_value result[ARG_BUTT] = { 0 };
    // if out function status is ok then async renturn output data, else return error.
    if (outStatus == OK) {
        napi_get_undefined(env, &result[ARG_ERROR]);
        if (output != nullptr) {
            result[ARG_DATA] = output;
        } else {
            napi_get_undefined(env, &result[ARG_DATA]);
        }
    } else {
        napi_value businessError = nullptr;
        SetBusinessError(env, &businessError, context->ctx->error, context->ctx->apiversion);
        result[ARG_ERROR] = businessError;
        napi_get_undefined(env, &result[ARG_DATA]);
    }
    if (context->defer != nullptr) {
        // promise
        if (status == napi_ok && outStatus == OK) {
            napi_resolve_deferred(env, context->defer, result[ARG_DATA]);
        } else {
            napi_reject_deferred(env, context->defer, result[ARG_ERROR]);
        }
    } else {
        // callback
        napi_value callback = nullptr;
        napi_get_reference_value(env, context->callback, &callback);
        napi_value returnValue;
        napi_call_function(env, nullptr, callback, ARG_BUTT, result, &returnValue);
    }
}
} // namespace AppDataMgrJsKit
} // namespace OHOS