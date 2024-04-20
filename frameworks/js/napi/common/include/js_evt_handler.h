/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTEDDATAMGR_APPDATAMGR_EVENT_HANDLER_H
#define DISTRIBUTEDDATAMGR_APPDATAMGR_EVENT_HANDLER_H

#include <functional>
#include "event_handler.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"

namespace OHOS::AppDataMgrJsKit {
class EvtHandler final {
public:
    using Task = std::function<void()>;
    using Args = std::function<void(napi_env env, int &argc, napi_value *argv)>;
    struct EvtCallback {
        napi_ref callback_ = nullptr;
        bool repeat_ = false;
        EvtCallback(napi_ref callback, bool repeat = false) : callback_(callback), repeat_(repeat) {}
        bool IsNull()
        {
            return callback_ == nullptr;
        }
    };
    explicit EvtHandler(napi_env env);
    ~EvtHandler();

    void PostTask(EvtCallback callback, Args args = Args());

private:
    struct EvtEntry {
        napi_env env_ = nullptr;
        napi_ref callback_ = nullptr;
        bool repeat_ = false;
        Args args_;
        ~EvtEntry();
        napi_value GetCallback();
        int32_t GetArgv(napi_value *argv, int32_t max);
    };

    Task GenCallbackTask(std::shared_ptr<EvtEntry> entry);
    napi_env env_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
};
} // namespace OHOS::AppDataMgrJsKit
#endif // DISTRIBUTEDDATAMGR_APPDATAMGR_EVENT_HANDLER_H