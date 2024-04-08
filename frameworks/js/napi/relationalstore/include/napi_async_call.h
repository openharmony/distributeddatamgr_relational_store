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
#ifndef RDB_JS_NAPI_ASYNC_CALL_H
#define RDB_JS_NAPI_ASYNC_CALL_H

#include <cinttypes>
#include <chrono>
#include <atomic>
#include <functional>
#include <memory>

#include "js_utils.h"
#include "logger.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_rdb_error.h"

namespace OHOS {
namespace RelationalStoreJsKit {
using InputAction = std::function<void(napi_env, size_t, napi_value *, napi_value)>;
using OutputAction = std::function<void(napi_env, napi_value &)>;
using ExecuteAction = std::function<int()>;
extern bool g_async;
extern bool g_sync;
#define ASYNC &g_async
#define SYNC &g_sync

class ContextBase {
public:
    struct RecordData {
        std::atomic_uint64_t times_{0};
        int64_t lastTime_ = 0;
        RecordData() = default;
        RecordData(const RecordData &record)
        {
            times_.store(record.times_);
            lastTime_ = record.lastTime_;
        }
        RecordData& operator= (const RecordData &record)
        {
            times_.store(record.times_);
            lastTime_ = record.lastTime_;
            return *this;
        }
    };
    void SetAction(napi_env env, napi_callback_info info, InputAction input, ExecuteAction exec, OutputAction output);
    void SetAll(napi_env env, napi_callback_info info, InputAction input, ExecuteAction exec, OutputAction output);
    void SetError(std::shared_ptr<Error> error);
    virtual ~ContextBase();

    napi_env env_ = nullptr;
    bool isAsync_ = true;
    void *boundObj = nullptr;
    std::shared_ptr<Error> error;
    std::shared_ptr<RecordData> executed_;

    napi_ref self_ = nullptr;
    napi_ref callback_ = nullptr;
    napi_deferred defer_ = nullptr;
    napi_async_work work_ = nullptr;

    int execCode_ = OK;
    OutputAction output_ = nullptr;
    ExecuteAction exec_ = nullptr;
    napi_value result_ = nullptr;
    std::shared_ptr<ContextBase> keep_;
};

class AsyncCall final {
public:
    static napi_value Call(napi_env env, std::shared_ptr<ContextBase> context);

private:
    enum { ARG_ERROR, ARG_DATA, ARG_BUTT };
    using RecordData = ContextBase::RecordData;
    struct Record {
    public:
        RecordData total_;
        RecordData completed_;
        uint64_t reportTimes_ = 0;
        std::shared_ptr<RecordData> executed_ = std::make_shared<RecordData>();
    };
    static constexpr uint64_t EXCEPT_DELTA = 20;
    static void OnExecute(napi_env env, void *data);
    static void OnComplete(napi_env env, void *data);
    static void OnReturn(napi_env env, napi_status status, void *data);
    static void OnComplete(napi_env env, napi_status status, void *data);
    static void SetBusinessError(napi_env env, std::shared_ptr<Error> error, napi_value *businessError);
    static napi_value Async(napi_env env, std::shared_ptr<ContextBase> context);
    static napi_value Sync(napi_env env, std::shared_ptr<ContextBase> context);
    static thread_local Record record_;
};
} // namespace RelationalStoreJsKit
} // namespace OHOS
#endif
