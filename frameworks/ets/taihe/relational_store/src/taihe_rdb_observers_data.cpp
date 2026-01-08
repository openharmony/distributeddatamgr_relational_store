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

#define LOG_TAG "TaiheRdbObserversData"
#include "logger.h"
#include "taihe_rdb_observers_data.h"

namespace ani_rdbutils {
using namespace OHOS::Rdb;

int32_t TaiheRdbObserversData::OnDataChange(OHOS::DistributedRdb::SubscribeMode subscribeMode,
    RdbStoreVarCallbackType callbackFunc, uintptr_t opq, RdbStoreObserverSubscribeFuncType subscribeFunc)
{
    if (subscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, subscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = observers_[subscribeMode];
    for (auto &obs : observers) {
        if (obs->IsEquals(callbackObj)) {
            LOG_INFO("This callback has already been registered.");
            return OHOS::NativeRdb::E_OK;
        }
    }
    auto callbackPtr = std::make_shared<RdbStoreVarCallbackType>(callbackFunc);
    auto observer = std::make_shared<TaiheRdbStoreObserver>(env, callbackObj, callbackPtr, subscribeMode);
    auto errCode = subscribeFunc(observer);
    if (errCode != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("Failed to register, call subscribe failed.");
        return errCode;
    }
    observers.push_back(observer);
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OffDataChange(OHOS::DistributedRdb::SubscribeMode subscribeMode,
    std::optional<uintptr_t> opq, RdbStoreObserverUnSubscribeFuncType unSubscribeFunc)
{
    if (unSubscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, unsubscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = observers_[subscribeMode];
    if (!opq.has_value()) {
        for (auto &observer : observers) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
        }
        observers.clear();
        return OHOS::NativeRdb::E_OK;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq.value());
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto &observer = *it;
        if (observer->IsEquals(callbackObj)) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
            observers.erase(it);
            return OHOS::NativeRdb::E_OK;
        }
    }
    LOG_INFO("This callback has not been registered yet.");
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OnCommon(std::string event, OHOS::DistributedRdb::SubscribeMode subscribeMode,
    RdbStoreVarCallbackType callbackFunc, uintptr_t opq, RdbStoreObserverSubscribeFuncType subscribeFunc)
{
    if (subscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, subscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = subscribeMode == OHOS::DistributedRdb::SubscribeMode::LOCAL ?
        localObservers_[event] : localSharedObservers_[event];
    for (auto &obs : observers) {
        if (obs->IsEquals(callbackObj)) {
            LOG_INFO("This callback has already been registered.");
            return OHOS::NativeRdb::E_OK;
        }
    }
    auto callbackPtr = std::make_shared<RdbStoreVarCallbackType>(callbackFunc);
    auto observer = std::make_shared<TaiheRdbStoreObserver>(env, callbackObj, callbackPtr, subscribeMode);
    auto errCode = subscribeFunc(observer);
    if (errCode != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("Failed to register, call subscribe failed.");
        return errCode;
    }
    observers.push_back(observer);
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OffCommon(std::string event, OHOS::DistributedRdb::SubscribeMode subscribeMode,
    std::optional<uintptr_t> opq, RdbStoreObserverUnSubscribeFuncType unSubscribeFunc)
{
    if (unSubscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, unsubscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = subscribeMode == OHOS::DistributedRdb::SubscribeMode::LOCAL ?
        localObservers_[event] : localSharedObservers_[event];
    if (!opq.has_value()) {
        for (auto &observer : observers) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
        }
        observers.clear();
        return OHOS::NativeRdb::E_OK;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq.value());
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto &observer = *it;
        if (observer->IsEquals(callbackObj)) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
            observers.erase(it);
            return OHOS::NativeRdb::E_OK;
        }
    }
    LOG_INFO("This callback has not been registered yet.");
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OnAutoSyncProgress(JsProgressDetailsCallbackType callbackFunc,
    uintptr_t opq, SyncObserverSubscribeFuncType subscribeFunc)
{
    if (subscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, subscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = syncObservers_;
    for (auto &obs : observers) {
        if (obs->IsEquals(callbackObj)) {
            LOG_INFO("This callback has already been registered.");
            return OHOS::NativeRdb::E_OK;
        }
    }
    auto callbackPtr = std::make_shared<JsProgressDetailsCallbackType>(callbackFunc);
    auto observer = std::make_shared<TaiheSyncObserver>(env, callbackObj, callbackPtr);
    auto errCode = subscribeFunc(observer);
    if (errCode != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("Failed to register, call subscribe failed.");
        return errCode;
    }
    observers.push_back(observer);
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OffAutoSyncProgress(std::optional<uintptr_t> opq,
    SyncObserverUnSubscribeFuncType unSubscribeFunc)
{
    if (unSubscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, unsubscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = syncObservers_;
    if (!opq.has_value()) {
        for (auto &observer : observers) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
        }
        observers.clear();
        return OHOS::NativeRdb::E_OK;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq.value());
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto &observer = *it;
        if (observer->IsEquals(callbackObj)) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
            observers.erase(it);
            return OHOS::NativeRdb::E_OK;
        }
    }
    LOG_INFO("This callback has not been registered yet.");
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OnStatistics(JsSqlExecutionCallbackType callbackFunc,
    uintptr_t opq, SqlObserverSubscribeFuncType subscribeFunc)
{
    if (subscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, subscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = statisticses_;
    for (auto &obs : observers) {
        if (obs->IsEquals(callbackObj)) {
            LOG_INFO("This callback has already been registered.");
            return OHOS::NativeRdb::E_OK;
        }
    }
    auto callbackPtr = std::make_shared<JsSqlExecutionCallbackType>(callbackFunc);
    auto observer = std::make_shared<TaiheSqlObserver>(env, callbackObj, callbackPtr);
    auto errCode = subscribeFunc(observer);
    if (errCode != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("Failed to register, call subscribe failed.");
        return errCode;
    }
    observers.push_back(observer);
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OffStatistics(std::optional<uintptr_t> opq,
    SqlObserverUnSubscribeFuncType unSubscribeFunc)
{
    if (unSubscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, unsubscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = statisticses_;
    if (!opq.has_value()) {
        for (auto &observer : observers) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
        }
        observers.clear();
        return OHOS::NativeRdb::E_OK;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq.value());
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto &observer = *it;
        if (observer->IsEquals(callbackObj)) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
            observers.erase(it);
            return OHOS::NativeRdb::E_OK;
        }
    }
    LOG_INFO("This callback has not been registered yet.");
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OnPerfStat(JsSqlExecutionCallbackType callbackFunc,
    uintptr_t opq, SqlObserverSubscribeFuncType subscribeFunc)
{
    if (subscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, subscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = perfStats_;
    for (auto &obs : observers) {
        if (obs->IsEquals(callbackObj)) {
            LOG_INFO("This callback has already been registered.");
            return OHOS::NativeRdb::E_OK;
        }
    }
    auto callbackPtr = std::make_shared<JsSqlExecutionCallbackType>(callbackFunc);
    auto observer = std::make_shared<TaiheSqlObserver>(env, callbackObj, callbackPtr);
    auto errCode = subscribeFunc(observer);
    if (errCode != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("Failed to register, call subscribe failed.");
        return errCode;
    }
    observers.push_back(observer);
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OffPerfStat(std::optional<uintptr_t> opq,
    SqlObserverUnSubscribeFuncType unSubscribeFunc)
{
    if (unSubscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, unsubscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = perfStats_;
    if (!opq.has_value()) {
        for (auto &observer : observers) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
        }
        observers.clear();
        return OHOS::NativeRdb::E_OK;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq.value());
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto &observer = *it;
        if (observer->IsEquals(callbackObj)) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
            observers.erase(it);
            return OHOS::NativeRdb::E_OK;
        }
    }
    LOG_INFO("This callback has not been registered yet.");
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OnSqliteErrorOccurred(JsExceptionMessageCallbackType callbackFunc,
    uintptr_t opq, LogObserverSubscribeFuncType subscribeFunc)
{
    if (subscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, subscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = logObservers_;
    for (auto &obs : observers) {
        if (obs->IsEquals(callbackObj)) {
            LOG_INFO("This callback has already been registered.");
            return OHOS::NativeRdb::E_OK;
        }
    }
    auto callbackPtr = std::make_shared<JsExceptionMessageCallbackType>(callbackFunc);
    auto observer = std::make_shared<TaiheLogObserver>(env, callbackObj, callbackPtr);
    auto errCode = subscribeFunc(observer);
    if (errCode != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("Failed to register, call subscribe failed.");
        return errCode;
    }
    observers.push_back(observer);
    return OHOS::NativeRdb::E_OK;
}

int32_t TaiheRdbObserversData::OffSqliteErrorOccurred(std::optional<uintptr_t> opq,
    LogObserverUnSubscribeFuncType unSubscribeFunc)
{
    if (unSubscribeFunc == nullptr) {
        LOG_ERROR("Failed to register, unsubscribe function is nullptr.");
        return OHOS::NativeRdb::E_ERROR;
    }
    std::unique_lock<std::mutex> locker(rdbObserversMutex_);
    auto &observers = logObservers_;
    if (!opq.has_value()) {
        for (auto &observer : observers) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
        }
        observers.clear();
        return OHOS::NativeRdb::E_OK;
    }
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        LOG_ERROR("Failed to register, env is nullptr");
        return OHOS::NativeRdb::E_ERROR;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(opq.value());
    for (auto it = observers.begin(); it != observers.end(); ++it) {
        auto &observer = *it;
        if (observer->IsEquals(callbackObj)) {
            auto errCode = unSubscribeFunc(observer);
            if (errCode != OHOS::NativeRdb::E_OK) {
                LOG_ERROR("Call unregister failed.");
                return errCode;
            }
            observers.erase(it);
            return OHOS::NativeRdb::E_OK;
        }
    }
    LOG_INFO("This callback has not been registered yet.");
    return OHOS::NativeRdb::E_OK;
}
} // namespace ani_rdbutils