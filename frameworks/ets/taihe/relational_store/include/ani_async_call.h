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
#ifndef OHOS_RELATION_STORE_ANI_ASYNC_CALL_H_
#define OHOS_RELATION_STORE_ANI_ASYNC_CALL_H_

#include <cstdint>
#include <memory>
#include <thread>

#include "ani.h"
#include "napi_rdb_error.h"
namespace OHOS {
namespace RdbTaihe {
class AniContext {
public:
    AniContext() = default;
    AniContext(const AniContext &) = delete;
    AniContext &operator=(const AniContext &) = delete;
    ~AniContext();
    bool Init(uintptr_t opq);

    ani_ref callbackRef_ = nullptr;
    ani_object promise_ = nullptr;
    ani_resolver deferred_ = nullptr;
    ani_ref result_ = nullptr;
    std::shared_ptr<RelationalStoreJsKit::Error> error_ = nullptr;
};

class AniAsyncCall {
public:
    enum { ARG_ERROR, ARG_DATA, ARG_BUTT };
    AniAsyncCall() = default;
    ~AniAsyncCall();
    static void ReturnResult(std::shared_ptr<AniContext> ctx);
    static void CallPromise(ani_env *env, std::shared_ptr<AniContext> ctx);
    static void CallCallback(ani_env *env, std::shared_ptr<AniContext> ctx);
};
}
}
#endif