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
#define LOG_TAG "NapiUvQueue"
#include "napi_uv_queue.h"

#include "logger.h"

namespace OHOS::RelationalStoreJsKit {
using namespace OHOS::Rdb;

NapiUvQueue::NapiUvQueue(napi_env env) : env_(env)
{
    if (env != nullptr) {
        napi_get_uv_event_loop(env, &loop_);
    }
}

NapiUvQueue::~NapiUvQueue()
{
    env_ = nullptr;
}

void NapiUvQueue::CallFunction(NapiCallbackGetter getter, NapiArgsGenerator genArgs)
{
    if (loop_ == nullptr || !getter) {
        LOG_ERROR("loop_ or callback is nullptr");
        return;
    }

    uv_work_t *work = new(std::nothrow) uv_work_t;
    if (work == nullptr) {
        LOG_ERROR("no memory for uv_work_t");
        return;
    }
    work->data = new UvEntry{ env_, std::move(getter), std::move(genArgs) };
    if (work->data == nullptr) {
        LOG_ERROR("no memory for UvEntry");
        delete work;
        work = nullptr;
        return;
    }
    int ret = uv_queue_work(loop_, work, [](uv_work_t *work) {}, NapiUvQueue::Work);
    if (ret < 0) {
        LOG_ERROR("uv_queue_work failed, errCode:%{public}d", ret);
        delete static_cast<UvEntry *>(work->data);
        work->data = nullptr;
        delete work;
        work = nullptr;
    }
}

void NapiUvQueue::Work(uv_work_t* work, int uvStatus)
{
    std::shared_ptr<UvEntry> entry(static_cast<UvEntry *>(work->data), [work](UvEntry* data) {
        delete data;
        delete work;
    });
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(entry->env, &scope);
    if (scope == nullptr) {
        delete work;
        return;
    }
    napi_value method = entry->callback(entry->env);
    if (method == nullptr) {
        LOG_ERROR("the callback is invalid, maybe is cleared!");
        if (scope != nullptr) {
            napi_close_handle_scope(entry->env, scope);
        }
        return;
    }
    int argc = 0;
    napi_value argv[MAX_CALLBACK_ARG_NUM] = {nullptr};
    if (entry->args) {
        entry->args(entry->env, argc, argv);
    }

    napi_value global = nullptr;
    napi_get_global(entry->env, &global);
    napi_value result = nullptr;
    napi_status status = napi_call_function(entry->env, global, method, argc, argv, &result);
    if (status != napi_ok) {
        LOG_ERROR("napi_call_function failed, status=%{public}d", status);
    }
    napi_close_handle_scope(entry->env, scope);
}

napi_env NapiUvQueue::GetEnv()
{
    return env_;
}
} // namespace OHOS::RelationalStoreJsKit