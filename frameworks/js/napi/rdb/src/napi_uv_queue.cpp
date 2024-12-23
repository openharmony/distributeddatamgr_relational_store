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
#include "uv.h"

namespace OHOS::RdbJsKit {
using namespace OHOS::Rdb;

NapiUvQueue::NapiUvQueue(napi_env env, napi_value callback)
    : env_(env)
{
    napi_create_reference(env, callback, 1, &callback_);
    napi_get_uv_event_loop(env, &loop_);
}

NapiUvQueue::~NapiUvQueue()
{
    napi_delete_reference(env_, callback_);
}

bool NapiUvQueue::operator==(napi_value value)
{
    napi_value callback = nullptr;
    napi_get_reference_value(env_, callback_, &callback);

    bool isEquals = false;
    napi_strict_equals(env_, value, callback, &isEquals);
    return isEquals;
}

void NapiUvQueue::CallFunction(NapiArgsGenerator genArgs)
{
    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }
    work->data = this;
    this->args = std::move(genArgs);

    int ret = uv_queue_work(loop_, work, [](uv_work_t* work) {}, [](uv_work_t* work, int st) {
            auto queue = static_cast<NapiUvQueue*>(work->data);
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(queue->env_, &scope);
            if (scope == nullptr) {
                delete work;
                return;
            }
            int argc = 0;
            napi_value argv[MAX_CALLBACK_ARG_NUM] = { nullptr };
            if (queue->args) {
                queue->args(queue->env_, argc, argv);
            }

            napi_value callback = nullptr;
            napi_get_reference_value(queue->env_, queue->callback_, &callback);
            napi_value global = nullptr;
            napi_get_global(queue->env_, &global);
            napi_value result = nullptr;
            napi_status status = napi_call_function(queue->env_, global, callback, argc, argv, &result);
            if (status != napi_ok) {
                LOG_ERROR("napi_call_function failed, status=%{public}d", status);
            }
            napi_close_handle_scope(queue->env_, scope);
            delete work;
        });
    if (ret < 0) {
        LOG_ERROR("uv_queue_work failed, errCode:%{public}d", ret);
        delete static_cast<NapiUvQueue *>(work->data);
        delete work;
    }
}
} // namespace OHOS::RdbJsKit
