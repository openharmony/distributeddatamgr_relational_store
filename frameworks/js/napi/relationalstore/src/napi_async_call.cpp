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
#define LOG_TAG "AsyncCall"
#include "napi_async_call.h"

#include "logger.h"
#include "napi_rdb_trace.h"
#include "rdb_errno.h"

using namespace OHOS::Rdb;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS {
namespace RelationalStoreJsKit {
bool g_async = true; // do not reset the value, used in DECLARE_NAPI_FUNCTION_WITH_DATA only
bool g_sync = false; // do not reset the value, used in DECLARE_NAPI_FUNCTION_WITH_DATA only
void Context::SetAction(
    napi_env env, napi_callback_info info, InputAction input, ExecuteAction exec, OutputAction output)
{
    env_ = env;
    size_t argc = MAX_INPUT_COUNT;
    napi_value self = nullptr;
    napi_value argv[MAX_INPUT_COUNT] = { nullptr };
    void *data = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, &self, &data));

    if (argc > 0) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[argc - 1], &valueType);
        if (valueType == napi_function) {
            LOG_DEBUG("asyncCall set callback");
            NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, argv[argc - 1], 1, &callback_));
            argc = argc - 1;
        }
    }
    if (data) {
        isAsync_ = *reinterpret_cast<bool *>(data);
    }

    // int -->input_(env, argc, argv, self)
    input(env, argc, argv, self);

    // if input return is not ok, then napi_throw_error context error
    RDB_NAPI_ASSERT_BASE(env, error == nullptr, error, NAPI_RETVAL_NOTHING);
    output_ = std::move(output);
    exec_ = std::move(exec);
    napi_create_reference(env, self, 1, &self_);
}

void Context::SetAll(
    napi_env env, napi_callback_info info, InputAction input, ExecuteAction exec, OutputAction output)
{
    env_ = env;
    size_t argc = MAX_INPUT_COUNT;
    napi_value self = nullptr;
    napi_value argv[MAX_INPUT_COUNT] = { nullptr };
    NAPI_CALL_RETURN_VOID(env, napi_get_cb_info(env, info, &argc, argv, &self, nullptr));

    // int -->input_(env, argc, argv, self)
    input(env, argc, argv, self);

    // if input return is not ok, then napi_throw_error context error
    RDB_NAPI_ASSERT_BASE(env, error == nullptr, error, NAPI_RETVAL_NOTHING);
    output_ = std::move(output);
    exec_ = std::move(exec);
    napi_create_reference(env, self, 1, &self_);
}

void Context::SetError(std::shared_ptr<Error> err)
{
    error = err;
}

Context::~Context()
{
    if (env_ == nullptr) {
        return;
    }
    if (work_ != nullptr) {
        napi_delete_async_work(env_, work_);
    }
    if (callback_ != nullptr) {
        napi_delete_reference(env_, callback_);
    }
    napi_delete_reference(env_, self_);
    env_ = nullptr;
}

void AsyncCall::SetBusinessError(napi_env env, std::shared_ptr<Error> error, napi_value *businessError)
{
    LOG_DEBUG("SetBusinessError enter");
    napi_value code = nullptr;
    napi_value msg = nullptr;
    napi_create_object(env, businessError);
    // if error is not inner error
    if (error != nullptr) {
        napi_create_int32(env, error->GetCode(), &code);
        napi_create_string_utf8(env, error->GetMessage().c_str(), NAPI_AUTO_LENGTH, &msg);
        napi_set_named_property(env, *businessError, "code", code);
        napi_set_named_property(env, *businessError, "message", msg);
    }
}

napi_value AsyncCall::Call(napi_env env, std::shared_ptr<Context> context)
{
    return context->isAsync_ ? Async(env, context) : Sync(env, context);
}

napi_value AsyncCall::Async(napi_env env, std::shared_ptr<Context> context)
{
    napi_value promise = nullptr;
    if (context->callback_ == nullptr) {
        napi_status status = napi_create_promise(env, &context->defer_, &promise);
        RDB_NAPI_ASSERT_BASE(env, status == napi_ok,
            std::make_shared<InnerError>("failed(" + std::to_string(status) + ") to create promise"), nullptr);
    } else {
        napi_get_undefined(env, &promise);
    }
    context->keep_ = context;
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "RelationalStoreAsyncCall", NAPI_AUTO_LENGTH, &resource);
    // create async work, execute function is OnExecute, complete function is OnComplete
    napi_create_async_work(env, nullptr, resource, AsyncCall::OnExecute, AsyncCall::OnComplete,
        reinterpret_cast<void *>(context.get()), &context->work_);
    // add async work to execute queue
    auto status = napi_queue_async_work_with_qos(env, context->work_, napi_qos_user_initiated);
    if (status != napi_ok) {
        napi_get_undefined(env, &promise);
    }
    return promise;
}

napi_value AsyncCall::Sync(napi_env env, std::shared_ptr<Context> context)
{
    OnExecute(env, reinterpret_cast<void *>(context.get()));
    OnComplete(env, reinterpret_cast<void *>(context.get()));
    return context->result_;
}

void AsyncCall::OnExecute(napi_env env, void *data)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    Context *context = reinterpret_cast<Context *>(data);
    if (context->error == nullptr && context->exec_) {
        context->execCode_ = context->exec_();
    }
    context->exec_ = nullptr;
}

void AsyncCall::OnComplete(napi_env env, void *data)
{
    Context *context = reinterpret_cast<Context *>(data);
    if (context->execCode_ != NativeRdb::E_OK) {
        context->SetError(std::make_shared<InnerError>(context->execCode_));
    }
    // if async execute status is not napi_ok then un-execute out function
    if ((context->error == nullptr) && context->output_) {
        context->output_(env, context->result_);
    }
    context->output_ = nullptr;
}

void AsyncCall::OnComplete(napi_env env, napi_status status, void *data)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    OnComplete(env, data);
    OnReturn(env, status, data);
}

void AsyncCall::OnReturn(napi_env env, napi_status status, void *data)
{
    Context *context = reinterpret_cast<Context *>(data);
    napi_value result[ARG_BUTT] = { 0 };
    // if out function status is ok then async renturn output data, else return error.
    if (context->error == nullptr) {
        napi_get_undefined(env, &result[ARG_ERROR]);
        if (context->result_ != nullptr) {
            result[ARG_DATA] = context->result_;
        } else {
            napi_get_undefined(env, &result[ARG_DATA]);
        }
    } else {
        SetBusinessError(env, context->error, &result[ARG_ERROR]);
        napi_get_undefined(env, &result[ARG_DATA]);
    }
    if (context->defer_ != nullptr) {
        // promise
        if (status == napi_ok && (context->error == nullptr)) {
            napi_resolve_deferred(env, context->defer_, result[ARG_DATA]);
        } else {
            napi_reject_deferred(env, context->defer_, result[ARG_ERROR]);
        }
    } else {
        // callback
        napi_value callback = nullptr;
        napi_get_reference_value(env, context->callback_, &callback);
        napi_value returnValue = nullptr;
        napi_call_function(env, nullptr, callback, ARG_BUTT, result, &returnValue);
    }
    context->keep_.reset();
}
} // namespace RelationalStoreJsKit
} // namespace OHOS
