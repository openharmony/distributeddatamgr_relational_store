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
#define LOG_TAG "AniAsyncCall"
#include "ani_async_call.h"

#include "ani.h"
#include "ani_utils.h"
#include "event_handler.h"
#include "logger.h"
#include "taihe/runtime.hpp"
namespace OHOS {
namespace RdbTaihe {
using namespace OHOS::Rdb;
using namespace OHOS::RelationalStoreJsKit;
AniContext::~AniContext()
{
    ::taihe::env_guard gurd;
    auto env = gurd.get_env();
    if (env != nullptr) {
        env->GlobalReference_Delete(callbackRef_);
    }
}

bool AniContext::Init(uintptr_t callback)
{
    ::taihe::env_guard gurd;
    auto env = gurd.get_env();
    if (env == nullptr) {
        LOG_ERROR("Get env failed.");
        return false;
    }
    if (callback != 0) {
        auto status = env->GlobalReference_Create(reinterpret_cast<ani_object>(callback), &callbackRef_);
        if (status != ANI_OK) {
            LOG_ERROR("GlobalReference_Create failed. status = %{public}d", status);
            callbackRef_ = nullptr;
            return false;
        }
    } else {
        auto status = env->Promise_New(&deferred_, &promise_);
        if (status != ANI_OK || deferred_ == nullptr || promise_ == nullptr) {
            LOG_ERROR("Promise_New failed. status = %{public}d", status);
            return false;
        }
    }
    return true;
}

void AniAsyncCall::ReturnResult(std::shared_ptr<AniContext> ctx)
{
    ::taihe::env_guard gurd;
    auto env = gurd.get_env();
    if (env == nullptr) {
        LOG_ERROR("Get env failed.");
        return;
    }

    if (ctx->callbackRef_ == nullptr && ctx->deferred_ == nullptr) {
        return;
    }
    if (ctx->callbackRef_ != nullptr) {
        CallCallback(env, ctx);
    } else {
        CallPromise(env, ctx);
    }
}

void AniAsyncCall::CallPromise(ani_env *env, std::shared_ptr<AniContext> ctx)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return;
    }
    ani_status status = ANI_OK;
    auto err = ctx->error_;
    if (err != nullptr) {
        ani_ref aniError = nullptr;
        if (ani_utils::CreateBusinessError(env, err->GetCode(), err->GetMessage(), aniError) != ANI_OK) {
            return;
        }
        status = env->PromiseResolver_Reject(ctx->deferred_, static_cast<ani_error>(aniError));
        if (status != ANI_OK) {
            LOG_ERROR("RejectPromise failed status = %{public}d", status);
        }
        return;
    }
    if (ctx->result_ == nullptr) {
        status = env->GetUndefined(&ctx->result_);
        if (status != ANI_OK) {
            LOG_ERROR("GetUndefined failed status = %{public}d", status);
            return;
        }
    }
    status = env->PromiseResolver_Resolve(ctx->deferred_, ctx->result_);
    if (status != ANI_OK) {
        LOG_ERROR("ResolvePromise failed status = %{public}d", status);
    }
}
void AniAsyncCall::CallCallback(ani_env *env, std::shared_ptr<AniContext> ctx)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return;
    }
    ani_status status = ANI_OK;
    ani_ref args[ARG_BUTT] = {nullptr, nullptr};
    auto err = ctx->error_;
    if (err != nullptr) {
        if (ani_utils::CreateBusinessError(env, err->GetCode(), err->GetMessage(), args[ARG_ERROR]) != ANI_OK) {
            return;
        }
    } else {
        env->GetUndefined(&args[ARG_ERROR]);
    }
    if (ctx->result_ == nullptr) {
        env->GetUndefined(&args[ARG_DATA]);
    } else {
        args[ARG_DATA] = ctx->result_;
    }
    ani_ref result = nullptr;
    status = env->FunctionalObject_Call(static_cast<ani_fn_object>(ctx->callbackRef_), ARG_BUTT, args, &result);
    if (status != ANI_OK) {
        LOG_ERROR("FunctionalObject_Call failed status = %{public}d", status);
    }
}
}
}