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

#define LOG_TAG "TaiheSqlObserver"
#include "logger.h"
#include "taihe_sql_observer.h"

namespace ani_rdbutils {
using namespace OHOS::Rdb;

TaiheSqlObserver::TaiheSqlObserver(
    ani_env *env,
    ani_object callbackObj,
    std::shared_ptr<JsSqlExecutionCallbackType> callbackPtr
) : callbackPtr_(callbackPtr)
{
    if (ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef_)) {
        LOG_ERROR("Call GlobalReference_Create failed");
    }
}

TaiheSqlObserver::~TaiheSqlObserver()
{
    taihe::env_guard gurd;
    auto env = gurd.get_env();
    if (env != nullptr && callbackRef_ != nullptr) {
        if (ANI_OK != env->GlobalReference_Delete(callbackRef_)) {
            LOG_ERROR("Call GlobalReference_Delete failed");
        }
    }
    callbackRef_ = nullptr;
    callbackPtr_ = nullptr;
}

bool TaiheSqlObserver::IsEquals(ani_object callbackObj)
{
    taihe::env_guard gurd;
    auto env = gurd.get_env();
    if (env == nullptr) {
        LOG_ERROR("ANI env is nullptr.");
        return false;
    }
    ani_ref callbackRef;
    if (env->GlobalReference_Create(callbackObj, &callbackRef) != ANI_OK) {
        LOG_ERROR("Call GlobalReference_Create failed");
        return false;
    }
    ani_boolean isEqual = false;
    if (env->Reference_StrictEquals(callbackRef_, callbackRef, &isEqual) != ANI_OK) {
        LOG_ERROR("Call Reference_StrictEquals failed.");
    }
    if (env->GlobalReference_Delete(callbackRef) != ANI_OK) {
        LOG_ERROR("Call GlobalReference_Delete failed");
    }
    return isEqual;
}

void TaiheSqlObserver::OnStatistic(const SqlExecutionInfo &info)
{
    if (callbackPtr_ == nullptr) {
        LOG_ERROR("Js callback is nullptr.");
        return;
    }
    auto jsInfo = SqlExecutionToTaihe(info);
    (*callbackPtr_)(jsInfo);
}
}