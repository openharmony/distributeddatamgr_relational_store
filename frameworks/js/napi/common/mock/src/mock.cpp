/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "mock.h"

struct UvEntry {
    std::function<void()> callback;
};
napi_status SendEventMock(napi_env env,
                        const std::function<void()>& cb,
                        napi_event_priority priority,
                        const char* name)
{
    if (env == nullptr || cb == nullptr || priority < napi_eprio_vip || napi_eprio_vip > napi_eprio_idle) {
        return napi_status::napi_invalid_arg;
    }

    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(env, &loop);
    if (loop == nullptr) {
        return napi_status::napi_invalid_arg;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return napi_status::napi_invalid_arg;
    }
    auto entry = new (std::nothrow) UvEntry();
    if (entry == nullptr) {
        delete work;
        return napi_status::napi_invalid_arg;
    }
    entry->callback = cb;
    work->data = entry;

    int ret = uv_queue_work(loop, work, [](uv_work_t *data){return;}, [](uv_work_t *work, int status){
        if (work == nullptr || work->data == nullptr) {
            return;
        }
        auto entry = static_cast<UvEntry*>(work->data);
        if (entry->callback) {
            entry->callback();
        }
        delete entry;
        delete work;
        return;
    });
    if(ret < 0) {
        delete entry;
        delete work;
        return napi_status::napi_invalid_arg;
    }
    return napi_ok;
}