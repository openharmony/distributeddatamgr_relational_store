/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "event_handler.h"
#define LOG_TAG "UvQueue"
#include "js_uv_queue.h"
#include <memory>
#include "js_scope.h"
#include "logger.h"
namespace OHOS::AppDataMgrJsKit {
using namespace OHOS::Rdb;
constexpr size_t ARGC_MAX = 6;
UvQueue::UvQueue(napi_env env) : env_(env)
{
    if (env != nullptr) {
        napi_get_uv_event_loop(env, &loop_);
    }
    handler_ = AppExecFwk::EventHandler::Current();
}

UvQueue::~UvQueue()
{
    LOG_DEBUG("no memory leak for queue-callback");
    env_ = nullptr;
    handler_ = nullptr;
}

void UvQueue::AsyncCall(UvCallback callback, Args args, Result result)
{
    if (loop_ == nullptr || callback.IsNull()) {
        LOG_ERROR("loop_ or callback is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        LOG_ERROR("no memory for uv_work_t");
        return;
    }
    auto entry = new (std::nothrow) UvEntry();
    if (entry == nullptr) {
        delete work;
        LOG_ERROR("no memory for UvEntry");
        return;
    }
    entry->env_ = env_;
    entry->object_ = callback.object_;
    entry->callback_ = callback.callback_;
    entry->repeat_ = callback.repeat_;
    entry->getter_ = std::move(callback.getter_);
    entry->args_ = std::move(args);
    entry->result_ = std::move(result);
    work->data = entry;
    int ret = uv_queue_work(loop_, work, DoWork, DoUvCallback);
    if (ret < 0) {
        LOG_ERROR("uv_queue_work failed, errCode:%{public}d", ret);
        delete entry;
        delete work;
    }
}

void UvQueue::AsyncCallInOrder(UvCallback callback, Args args, Result result)
{
    if (handler_ == nullptr || callback.IsNull()) {
        LOG_ERROR("handler_ or callback is nullptr");
        return;
    }
    auto entry = std::make_shared<UvEntry>();
    if (entry == nullptr) {
        LOG_ERROR("no memory for UvEntry");
        return;
    }
    entry->env_ = env_;
    entry->callback_ = callback.callback_;
    entry->repeat_ = callback.repeat_;
    entry->args_ = std::move(args);
    if (handler_ != nullptr) {
        handler_->PostTask(GenCallbackTask(entry));
    }
}

void UvQueue::AsyncPromise(UvPromise promise, UvQueue::Args args)
{
    if (loop_ == nullptr || promise.IsNull()) {
        LOG_ERROR("loop_ or promise is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        LOG_ERROR("no memory for uv_work_t");
        return;
    }
    auto entry = new (std::nothrow) UvEntry();
    if (entry == nullptr) {
        delete work;
        LOG_ERROR("no memory for UvEntry");
        return;
    }
    entry->env_ = env_;
    entry->defer_ = promise.defer_;
    entry->args_ = std::move(args);
    work->data = entry;
    int ret = uv_queue_work(loop_, work, DoWork, DoUvPromise);
    if (ret < 0) {
        LOG_ERROR("uv_queue_work failed, errCode:%{public}d", ret);
        delete entry;
        delete work;
    }
}

void UvQueue::Execute(UvQueue::Task task)
{
    if (loop_ == nullptr || !task) {
        LOG_ERROR("loop_ or task is nullptr");
        return;
    }
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        LOG_ERROR("no memory for uv_work_t");
        return;
    }
    auto entry = new (std::nothrow) Task();
    if (entry == nullptr) {
        delete work;
        LOG_ERROR("no memory for Task");
        return;
    }
    *entry = task;
    work->data = entry;
    int ret = uv_queue_work(loop_, work, DoExecute, [](uv_work_t *work, int status) { delete work; });
    if (ret < 0) {
        LOG_ERROR("uv_queue_work failed, errCode:%{public}d", ret);
        delete entry;
        delete work;
    }
}

napi_env UvQueue::GetEnv()
{
    return env_;
}

napi_value UvQueue::Resolved(napi_env env, napi_callback_info info)
{
    return Future(env, info, false);
}

napi_value UvQueue::Rejected(napi_env env, napi_callback_info info)
{
    return Future(env, info, true);
}

napi_value UvQueue::Future(napi_env env, napi_callback_info info, bool exception)
{
    size_t argc = ARGC_MAX;
    napi_value argv[ARGC_MAX] = { nullptr };
    void *data = nullptr;
    auto status = napi_get_cb_info(env, info, &argc, argv, nullptr, &data);
    if (status != napi_ok) {
        return nullptr;
    }
    auto *entry = static_cast<Result *>(data);
    if (entry) {
        (*entry)(env, argc, argv, exception);
        delete entry;
    }
    return nullptr;
}

void UvQueue::DoWork(uv_work_t *work)
{
}

void UvQueue::DoExecute(uv_work_t *work)
{
    Task *task = static_cast<Task *>(work->data);
    work->data = nullptr;
    (*task)();
    delete task;
}

void UvQueue::DoUvCallback(uv_work_t *work, int status)
{
    std::shared_ptr<UvEntry> entry(static_cast<UvEntry *>(work->data), [work](UvEntry *data) {
        delete data;
        delete work;
    });

    GenCallbackTask(entry)();
}

void UvQueue::DoUvPromise(uv_work_t *work, int status)
{
    std::shared_ptr<UvEntry> entry(static_cast<UvEntry *>(work->data), [work](UvEntry *data) {
        delete data;
        delete work;
    });

    Scope scope(entry->env_);
    napi_value method = entry->GetCallback();
    if (method == nullptr) {
        LOG_ERROR("the callback is invalid, maybe is cleared!");
        return;
    }
    napi_value argv[ARG_BUTT] = { nullptr };
    auto argc = entry->GetArgv(argv, ARG_BUTT);
    if (argv[ARG_ERROR] != nullptr || argc != ARG_BUTT) {
        napi_reject_deferred(entry->env_, entry->defer_, argv[ARG_ERROR]);
    } else {
        napi_resolve_deferred(entry->env_, entry->defer_, argv[ARG_DATA]);
    }
}

UvQueue::Task UvQueue::GenCallbackTask(std::shared_ptr<UvEntry> entry)
{
    return [entry]() {
        if (entry == nullptr) {
            return;
        }
        Scope scope(entry->env_);
        napi_value method = entry->GetCallback();
        if (method == nullptr) {
            entry->DelReference();
            LOG_ERROR("the callback is invalid, maybe is cleared!");
            return;
        }
        napi_value argv[ARGC_MAX] = { nullptr };
        auto argc = entry->GetArgv(argv, ARGC_MAX);
        auto object = entry->GetObject();
        napi_value promise = nullptr;
        auto status = napi_call_function(entry->env_, object, method, argc, argv, &promise);
        entry->DelReference();
        if (status != napi_ok) {
            LOG_ERROR("notify data change failed status:%{public}d.", status);
            return;
        }
        entry->BindPromise(promise);
    };
}

UvQueue::UvEntry::~UvEntry()
{
}

void UvQueue::UvEntry::DelReference()
{
    if (callback_ != nullptr && !repeat_) {
        napi_delete_reference(env_, callback_);
        callback_ = nullptr;
    }
    if (object_ != nullptr) {
        napi_delete_reference(env_, object_);
        object_ = nullptr;
    }
}

napi_value UvQueue::UvEntry::GetCallback()
{
    napi_value method = nullptr;
    if (callback_ != nullptr) {
        napi_get_reference_value(env_, callback_, &method);
    } else if (getter_) {
        method = getter_(env_);
    }
    return method;
}

int32_t UvQueue::UvEntry::GetArgv(napi_value *argv, int32_t max)
{
    int32_t argc = 0;
    if (args_) {
        argc = max;
        args_(env_, argc, argv);
    }
    return argc;
}

napi_value UvQueue::UvEntry::GetObject()
{
    napi_value object = nullptr;
    if (object_ == nullptr) {
        napi_get_global(env_, &object);
    } else {
        napi_get_reference_value(env_, object_, &object);
    }
    return object;
}

void UvQueue::UvEntry::BindPromise(napi_value promise)
{
    if (promise == nullptr || !result_) {
        return;
    }

    bool isPromise = false;
    auto status = napi_is_promise(env_, promise, &isPromise);
    if (status != napi_ok || !isPromise) {
        result_(env_, 1, &promise, false);
        return;
    }

    napi_value then = nullptr;
    if (napi_get_named_property(env_, promise, "then", &then) != napi_ok || then == nullptr) {
        return;
    }

    auto object = StealResult();
    napi_value argv[ARGC_MAX] = { nullptr };
    napi_create_function(env_, RESOLVED, RESOLVED_SIZE, Resolved, object, &argv[0]);
    napi_create_function(env_, REJECTED, REJECTED_SIZE, Rejected, object, &argv[1]);
    napi_value result = nullptr;
    // Enter 2 parameters argv[0] and argv[1]
    napi_call_function(env_, promise, then, 2, argv, &result);
}

UvQueue::Result *UvQueue::UvEntry::StealResult()
{
    if (!result_) {
        return nullptr;
    }
    auto *result = new Result();
    *result = std::move(result_);
    return result;
}
} // namespace OHOS::AppDataMgrJsKit
