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
namespace RelationalStoreJsKit {
class AsyncCall final {
public:
    class Context {
    public:
        std::shared_ptr<Error> error;
        napi_env _env = nullptr;
        void *boundObj = nullptr;
        int execStatus = ERR;
        using InputAction = std::function<int(napi_env, size_t, napi_value *, napi_value)>;
        using OutputAction = std::function<int(napi_env, napi_value &)>;
        using ExecAction = std::function<int(Context *)>;
        Context(InputAction input, OutputAction output) : input_(std::move(input)), output_(std::move(output)){};
        virtual ~Context(){};
        void SetAction(InputAction input, OutputAction output = nullptr)
        {
            input_ = input;
            output_ = output;
        }

        void SetAction(OutputAction output)
        {
            SetAction(nullptr, std::move(output));
        }

        void SetError(std::shared_ptr<Error> err)
        {
            error = err;
        }

        // input function
        virtual int operator()(napi_env env, size_t argc, napi_value *argv, napi_value self)
        {
            if (input_ == nullptr) {
                return OK;
            }
            int ret = input_(env, argc, argv, self);
            input_ = nullptr;
            return ret;
        }

        // output function
        virtual int operator()(napi_env env, napi_value &result)
        {
            if (output_ == nullptr) {
                result = nullptr;
                return OK;
            }
            int ret = output_(env, result);
            output_ = nullptr;
            return ret;
        }

        // execute function
        virtual int Exec()
        {
            if (exec_ == nullptr) {
                return ERR;
            }
            int ret = exec_(this);
            exec_ = nullptr;
            return ret;
        };

    protected:
        friend class AsyncCall;
        InputAction input_ = nullptr;
        OutputAction output_ = nullptr;
        ExecAction exec_ = nullptr;
    };

    // The default AsyncCallback in the parameters is at the end position.
    static constexpr size_t ASYNC_DEFAULT_POS = -1;
    AsyncCall(napi_env env, napi_callback_info info, std::shared_ptr<Context> context);
    ~AsyncCall();
    napi_value Call(napi_env env, Context::ExecAction exec = nullptr);
    napi_value SyncCall(napi_env env, Context::ExecAction exec = nullptr);

private:
    enum { ARG_ERROR, ARG_DATA, ARG_BUTT };
    static void OnExecute(napi_env env, void *data);
    static void OnComplete(napi_env env, napi_status status, void *data);
    struct AsyncContext {
        std::shared_ptr<Context> ctx = nullptr;
        napi_env env = nullptr;
        napi_ref callback = nullptr;
        napi_ref self = nullptr;
        napi_deferred defer = nullptr;
        napi_async_work work = nullptr;
        AsyncContext(napi_env nenv) : env(nenv)
        {
        }
        ~AsyncContext()
        {
            if (env != nullptr) {
                napi_delete_reference(env, callback);
                napi_delete_reference(env, self);
                napi_delete_async_work(env, work);
            }
        }
    };
    static void SetBusinessError(napi_env env, napi_value *businessError, std::shared_ptr<Error> error);

    AsyncContext *context_ = nullptr;
    napi_env env_ = nullptr;
};
} // namespace RelationalStoreJsKit
} // namespace OHOS
#endif
