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
#ifndef DISTRIBUTEDDATAMGR_APPDATAMGR_UV_QUEUE_H
#define DISTRIBUTEDDATAMGR_APPDATAMGR_UV_QUEUE_H
#include <functional>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "uv.h"

namespace OHOS::AppDataMgrJsKit {
class UvQueue final {
public:
    using ArgsGenerator = std::function<void(napi_env env, int& argc, napi_value* argv)>;
    using CallbackGetter = std::function<napi_value(napi_env env)>;
    struct UvCallback {
        napi_ref callback_ = nullptr;
        bool repeat_ = false;
        CallbackGetter getter_;
        UvCallback(napi_ref callback, bool repeat = false) : callback_(callback), repeat_(repeat) {}
        UvCallback(CallbackGetter getter) : getter_(std::move(getter)) {}
        bool IsNull()
        {
            return (callback_ == nullptr && getter_ == nullptr);
        }
    };

    explicit UvQueue(napi_env env);
    ~UvQueue();

    napi_env GetEnv();
    void AsyncCall(UvCallback callback, ArgsGenerator genArgs = ArgsGenerator());
private:
    struct UvEntry {
        napi_env env;
        napi_ref callback;
        bool repeat = false;
        CallbackGetter getter;
        ArgsGenerator args;
        ~UvEntry()
        {
            if (callback != nullptr && !repeat) {
                napi_delete_reference(env, callback);
            }
        }
    };
    napi_env env_ = nullptr;
    uv_loop_s* loop_ = nullptr;
};
} // namespace OHOS::AppDataMgrJsKit
#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_UV_QUEUE_H
