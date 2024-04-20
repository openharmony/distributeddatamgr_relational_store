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

#define LOG_TAG "EvtHandler"

#include "js_evt_handler.h"
#include "logger.h"
#include "js_scope.h"

namespace OHOS::AppDataMgrJsKit {
using namespace OHOS::Rdb;
constexpr size_t ARGC_MAX = 6;
EvtHandler::EvtHandler(napi_env env) : env_(env)
{
    if (env != nullptr) {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner()); 
    }
}

EvtHandler::~EvtHandler()
{
    LOG_DEBUG("no memory leak for evt-callback");
    env_ = nullptr;
    handler_ = nullptr;
}

void EvtHandler::PostTask(EvtCallback callback, Args args)
{
     if (handler_ == nullptr || callback.IsNull()) {
        LOG_ERROR("handler_ or callback is nullptr");
        return;
    }
    auto entry = std::make_shared<EvtEntry>();
    if (entry == nullptr) {
        LOG_ERROR("no memory for EvtEntry");
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

EvtHandler::Task EvtHandler::GenCallbackTask(std::shared_ptr<EvtEntry> entry)
{
    return [entry]() {
        if (entry == nullptr) {
            return;
        }
        Scope scope(entry->env_);
        napi_value method = entry->GetCallback();
        if (method == nullptr) {
            LOG_ERROR("the callback is invalid, maybe is cleared!");
            return;
        }
        napi_value argv[ARGC_MAX] = { nullptr };
        auto argc = entry->GetArgv(argv, ARGC_MAX);
        napi_value global = nullptr;
        napi_get_global(entry->env_, &global);
        napi_value result = nullptr;
        auto status = napi_call_function(entry->env_, global, method, argc, argv, &result);
        if (status != napi_ok) {
            LOG_ERROR("notify data change failed status:%{public}d.", status);
        }
    };
}

EvtHandler::EvtEntry::~EvtEntry()
{
    if (callback_ == nullptr || repeat_) {
        return;
    }
    napi_delete_reference(env_, callback_);
    callback_ = nullptr;
}

napi_value EvtHandler::EvtEntry::GetCallback()
{
    napi_value method = nullptr;
    if (callback_ != nullptr) {
        napi_get_reference_value(env_, callback_, &method);
    }
    return method;
}

int32_t EvtHandler::EvtEntry::GetArgv(napi_value *argv, int32_t max)
{
    int32_t argc = 0;
    if (args_) {
        argc = max;
        args_(env_, argc, argv);
    }
    return argc;
}
} // namespace OHOS::AppDataMgrJsKit