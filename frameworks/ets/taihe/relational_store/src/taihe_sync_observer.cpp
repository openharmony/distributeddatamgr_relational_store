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

#define LOG_TAG "TaiheSyncObserver"
#include "logger.h"
#include "taihe_sync_observer.h"

namespace ani_rdbutils {
using namespace OHOS::Rdb;

TaiheSyncObserver::TaiheSyncObserver(
    ani_env *env,
    ani_ref callbackRef,
    std::shared_ptr<JsProgressDetailsCallbackType> callbackPtr
) : env_(env), callbackRef_(callbackRef), callbackPtr_(callbackPtr)
{
}

TaiheSyncObserver::~TaiheSyncObserver()
{
    if (env_ != nullptr && callbackRef_ != nullptr) {
        env_->GlobalReference_Delete(callbackRef_);
    }
    env_ = nullptr;
    callbackRef_ = nullptr;
    callbackPtr_ = nullptr;
}

bool TaiheSyncObserver::IsEquals(ani_ref ref)
{
    if (env_ == nullptr) {
        LOG_ERROR("ANI env is nullptr.");
        return false;
    }
    ani_boolean isEqual = false;
    if (env_->Reference_StrictEquals(callbackRef_, ref, &isEqual) != ANI_OK) {
        LOG_ERROR("Call Reference_StrictEquals failed.");
        return false;
    }
    return isEqual;
}

void TaiheSyncObserver::ProgressNotification(const OHOS::DistributedRdb::Details &details)
{
    if (callbackPtr_ == nullptr) {
        LOG_ERROR("Js callback is nullptr.");
        return;
    }
    for (auto &[key, value] : details) {
        auto jspara = ProgressDetailToTaihe(value);
        (*callbackPtr_)(jspara);
    }
}

int32_t TaiheSyncObserver::AddCallback(RdbObserversData &rdbObserversData,
    JsProgressDetailsCallbackType callbackFunc, uintptr_t opq, SubscribeFuncType subscribeFunc)
{
    ani_ref callbackRef;
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    if (ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        LOG_ERROR("Failed to register, create reference failed");
        return OHOS::NativeRdb::E_ERROR;
    }
    AniRefHolder aniRefHolder(env, callbackRef);
    std::unique_lock<std::mutex> locker(rdbObserversData.rdbObserversMutex_);
    auto &observers = rdbObserversData.syncObservers_;
    for (auto &obs : observers) {
        if (obs->IsEquals(callbackRef)) {
            LOG_INFO("This callback has already been registered.");
            return OHOS::NativeRdb::E_OK;
        }
    }
    auto callbackPtr = std::make_shared<JsProgressDetailsCallbackType>(callbackFunc);
    auto observer = std::make_shared<TaiheSyncObserver>(env, aniRefHolder.move(), callbackPtr);
    if (subscribeFunc(observer) != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("Failed to register, call subscribe failed.");
        return OHOS::NativeRdb::E_ERROR;
    }
    observers.push_back(observer);
    return OHOS::NativeRdb::E_OK;
}

void TaiheSyncObserver::RemoveCallback(RdbObserversData &rdbObserversData,
    std::optional<uintptr_t> opq, UnSubscribeFuncType unSubscribeFunc)
{
    std::unique_lock<std::mutex> locker(rdbObserversData.rdbObserversMutex_);
    auto &observers = rdbObserversData.syncObservers_;
    if (!opq.has_value()) {
        for (auto &observer : observers) {
            if (unSubscribeFunc(observer) != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
            }
        }
        observers.clear();
        return;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return;
    }
    ani_ref callbackRef;
    ani_object callbackObj = reinterpret_cast<ani_object>(opq.value());
    if (ANI_OK != env->GlobalReference_Create(callbackObj, &callbackRef)) {
        LOG_ERROR("Failed to register, create reference failed");
        return;
    }
    bool isFound = false;
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto &observer = *it;
        if (observer->IsEquals(callbackRef)) {
            if (unSubscribeFunc(observer) != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
            }
            isFound = true;
            observers.erase(it);
            break;
        }
    }
    if (!isFound) {
        LOG_ERROR("This callback has not been registered yet.");
    }
    env->GlobalReference_Delete(callbackRef);
}
}