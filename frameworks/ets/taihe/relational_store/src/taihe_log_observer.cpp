/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define LOG_TAG "TaiheLogObserver"
#include "logger.h"
#include "taihe_log_observer.h"

namespace ani_rdbutils {
using namespace OHOS::Rdb;

TaiheLogObserver::TaiheLogObserver(
    ani_env *env,
    ani_object callbackObj,
    std::shared_ptr<JsExceptionMessageCallbackType> callbackPtr
) : env_(env), callbackPtr_(callbackPtr)
{
    if (ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef_)) {
        LOG_ERROR("Call GlobalReference_Create failed");
    }
}

TaiheLogObserver::~TaiheLogObserver()
{
    if (env_ != nullptr && callbackRef_ != nullptr) {
        if (ANI_OK != env_->GlobalReference_Delete(callbackRef_)) {
            LOG_ERROR("Call GlobalReference_Delete failed");
        }
    }
    env_ = nullptr;
    callbackRef_ = nullptr;
    callbackPtr_ = nullptr;
}

bool TaiheLogObserver::IsEquals(ani_object callbackObj)
{
    if (env_ == nullptr) {
        LOG_ERROR("ANI env is nullptr.");
        return false;
    }
    ani_ref callbackRef;
    if (env_->GlobalReference_Create(callbackObj, &callbackRef) != ANI_OK) {
        LOG_ERROR("Call GlobalReference_Create failed");
        return false;
    }
    ani_boolean isEqual = false;
    if (env_->Reference_StrictEquals(callbackRef_, callbackRef, &isEqual) != ANI_OK) {
        LOG_ERROR("Call Reference_StrictEquals failed.");
    }
    if (env_->GlobalReference_Delete(callbackRef) != ANI_OK) {
        LOG_ERROR("Call GlobalReference_Delete failed");
    }
    return isEqual;
}

void TaiheLogObserver::OnErrorLog(const ExceptionMessage &message)
{
    if (callbackPtr_ == nullptr) {
        LOG_ERROR("Js callback is nullptr.");
        return;
    }
    auto jsMessage = ExceptionMessageToTaihe(message);
    (*callbackPtr_)(jsMessage);
}
}