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

#include <functional>
#include <memory>

#include "js_logger.h"
#include "js_utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_rdb_error.h"

namespace OHOS {
namespace AppDataMgrJsKit {
using InputAction = std::function<int(napi_env, size_t, napi_value *, napi_value)>;
using OutputAction = std::function<int(napi_env, napi_value &)>;
using ExecuteAction = std::function<int()>;

class BaseContext {
public:
    void SetAction(napi_env env, napi_callback_info info, InputAction input, ExecuteAction exec, OutputAction output);
    void SetError(std::shared_ptr<Error> error);
    virtual ~BaseContext();

    int apiversion = APIVERSION_V8;
    napi_env env_ = nullptr;
    void *boundObj = nullptr;
    int execStatus = ERR;
    std::shared_ptr<Error> error;

    napi_ref self_ = nullptr;
    napi_ref callback_ = nullptr;
    napi_deferred defer_ = nullptr;
    napi_async_work work_ = nullptr;

    OutputAction output_ = nullptr;
    ExecuteAction exec_ = nullptr;
    std::shared_ptr<BaseContext> keep_;
};

class AsyncCall final {
public:
    static napi_value Call(napi_env env, std::shared_ptr<BaseContext> context);

private:
    enum { ARG_ERROR, ARG_DATA, ARG_BUTT };
    static void OnExecute(napi_env env, void *data);
    static void OnComplete(napi_env env, napi_status status, void *data);
    static void SetBusinessError(napi_env env, napi_value *businessError, std::shared_ptr<Error> error, int apiversion);
};
} // namespace AppDataMgrJsKit
} // namespace OHOS
#endif
