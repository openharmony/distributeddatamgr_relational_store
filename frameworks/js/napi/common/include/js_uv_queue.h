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
#include "event_handler.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "uv.h"

namespace OHOS::AppDataMgrJsKit {
class UvQueue final {
public:
    using Task = std::function<void()>;
    using Args = std::function<void(napi_env env, int &argc, napi_value *argv)>;
    using Result = std::function<void(napi_env env, size_t count, napi_value *values, bool exception)>;
    using Callbacker = std::function<napi_value(napi_env env)>;
    enum { ARG_ERROR, ARG_DATA, ARG_BUTT };
    struct UvCallback {
        napi_ref object_ = nullptr;
        napi_ref callback_ = nullptr;
        Callbacker getter_;
        bool repeat_ = false;
        UvCallback(napi_ref callback, bool repeat = false) : callback_(callback), repeat_(repeat) { }
        UvCallback(napi_ref object, napi_ref callback) : object_(object), callback_(callback) { }
        UvCallback(Callbacker getter, napi_ref object = nullptr) : object_(object), getter_(std::move(getter)) { }
        bool IsNull()
        {
            return (callback_ == nullptr && getter_ == nullptr);
        }
    };

    struct UvPromise {
        napi_deferred defer_ = nullptr;
        UvPromise(napi_deferred defer) : defer_(defer) { }
        bool IsNull()
        {
            return (defer_ == nullptr);
        }
    };

    explicit UvQueue(napi_env env);
    ~UvQueue();

    napi_env GetEnv();
    void AsyncCall(UvCallback callback, Args args = Args(), Result result = Result());
    void AsyncCallInOrder(UvCallback callback, Args args = Args(), Result result = Result());
    void AsyncPromise(UvPromise promise, Args args = Args());
    void Execute(Task task);

private:
    static constexpr char RESOLVED[] = "resolved";
    static constexpr char REJECTED[] = "rejected";
    static constexpr size_t RESOLVED_SIZE = sizeof(RESOLVED);
    static constexpr size_t REJECTED_SIZE = sizeof(REJECTED);

    static napi_value Resolved(napi_env env, napi_callback_info info);
    static napi_value Rejected(napi_env env, napi_callback_info info);
    static napi_value Future(napi_env env, napi_callback_info info, bool exception);
    static void DoWork(uv_work_t *work);
    static void DoExecute(uv_work_t *work);
    static void DoUvCallback(uv_work_t *work, int status);
    static void DoUvPromise(uv_work_t *work, int status);

    struct UvEntry {
        napi_env env_ = nullptr;
        napi_ref object_ = nullptr;
        napi_ref callback_ = nullptr;
        napi_deferred defer_ = nullptr;
        bool repeat_ = false;
        Callbacker getter_;
        Args args_;
        Result result_;
        ~UvEntry();
        napi_value GetCallback();
        napi_value GetObject();
        void BindPromise(napi_value promise);
        void DelReference();
        Result *StealResult();
        int32_t GetArgv(napi_value *argv, int32_t max);
    };

    static Task GenCallbackTask(std::shared_ptr<UvEntry> entry);

    napi_env env_ = nullptr;
    uv_loop_s *loop_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
};
} // namespace OHOS::AppDataMgrJsKit
#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_UV_QUEUE_H
