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

#include "relational_store_utils.h"
#include "cj_lambda.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_store.h"
#include "native_log.h"
#include "relational_store_impl_rdbstore.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
RdbStoreObserverImpl::RdbStoreObserverImpl(int64_t id, FuncType type, int32_t mode)
{
    callbackId = id;
    funcType = type;
    mode_ = mode;
    switch (type) {
        case NoParam: {
            auto cFunc = reinterpret_cast<void(*)()>(callbackId);
            func = CJLambda::Create(cFunc);
            break;
        }
        case ParamArrStr: {
            auto cFunc = reinterpret_cast<void(*)(CArrStr arr)>(callbackId);
            carrStrFunc = [ lambda = CJLambda::Create(cFunc)](const std::vector<std::string> &devices) ->
                void { lambda(VectorToCArrStr(devices)); };
            break;
        }
        case ParamChangeInfo: {
            auto cFunc = reinterpret_cast<void(*)(CArrRetChangeInfo arr)>(callbackId);
            changeInfoFunc = [ lambda = CJLambda::Create(cFunc)](const DistributedRdb::Origin &origin,
            const PrimaryFields &fields, DistributedRdb::RdbStoreObserver::ChangeInfo &&changeInfo) ->
                void { lambda(ToCArrRetChangeInfo(origin, fields, std::move(changeInfo))); };
            break;
        }
    }
}

SyncObserverImpl::SyncObserverImpl(int64_t id)
{
    callbackId = id;
    auto cFunc = reinterpret_cast<void(*)(CProgressDetails details)>(callbackId);
    func = [ lambda = CJLambda::Create(cFunc)](const DistributedRdb::Details &details) ->
        void { lambda(ToCProgressDetails(details)); };
}

RdbStoreObserverImpl::RdbStoreObserverImpl(int64_t callback,
    const std::function<void()>& callbackRef)
{
    m_callback = callback;
    m_callbackRef = callbackRef;
}

int64_t RdbStoreObserverImpl::GetCallBack()
{
    return m_callback;
}

bool isSameFunction(int64_t f1, int64_t f2)
{
    return f1 == f2;
}

bool RdbStoreImpl::HasRegisteredObserver(
    int64_t callback,
    std::list<std::shared_ptr<RdbStoreObserverImpl>> &observers)
{
    for (auto &it : observers) {
        if (isSameFunction(callback, it->GetCallBack())) {
            return true;
        }
    }
    return false;
}

int32_t RdbStoreImpl::RegisteredObserver(
    DistributedRdb::SubscribeOption option,
    std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers,
    int64_t callback, const std::function<void()>& callbackRef)
{
    std::lock_guard<std::mutex> lock(observerMutex_);
    observers.try_emplace(option.event);
    if (!HasRegisteredObserver(callback, observers[option.event])) {
        auto localObserver = std::make_shared<RdbStoreObserverImpl>(callback, callbackRef);
        int32_t errCode = rdbStore_->Subscribe(option, localObserver);
        if (errCode != NativeRdb::E_OK) {
            return errCode;
        }
        observers[option.event].push_back(localObserver);
        LOGI("subscribe success event: %{public}s", option.event.c_str());
    } else {
        LOGI("duplicate subscribe event: %{public}s", option.event.c_str());
    }
    return RelationalStoreJsKit::OK;
}

int32_t RdbStoreImpl::RegisterObserver(const char *event, bool interProcess, int64_t callback,
    const std::function<void()>& callbackRef)
{
    DistributedRdb::SubscribeOption option;
    option.event = event;
    interProcess ? option.mode = DistributedRdb::SubscribeMode::LOCAL_SHARED : option.mode =
        DistributedRdb::SubscribeMode::LOCAL;
    if (option.mode == DistributedRdb::SubscribeMode::LOCAL) {
        return RegisteredObserver(option, localObservers_, callback, callbackRef);
    }
    return RegisteredObserver(option, localSharedObservers_, callback, callbackRef);
}

int32_t RdbStoreImpl::RegisterObserverArrStr(int32_t subscribeType, int64_t callbackId)
{
    int32_t mode = subscribeType;
    DistributedRdb::SubscribeOption option;
    option.mode = static_cast<DistributedRdb::SubscribeMode>(mode);
    option.event = "dataChange";
    std::lock_guard<std::mutex> lock(observerMutex_);
    auto observer = std::make_shared<RdbStoreObserverImpl>(callbackId, RdbStoreObserverImpl::ParamArrStr, mode);
    int32_t errCode = NativeRdb::E_OK;
    if (option.mode == DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
        errCode = rdbStore_->SubscribeObserver(option, observer);
    } else {
        errCode = rdbStore_->Subscribe(option, observer);
    }
    if (errCode == NativeRdb::E_OK) {
        observers_[mode].push_back(observer);
        LOGI("subscribe success");
    }
    return errCode;
}

int32_t RdbStoreImpl::RegisterObserverChangeInfo(int32_t subscribeType, int64_t callbackId)
{
    int32_t mode = subscribeType;
    DistributedRdb::SubscribeOption option;
    option.mode = static_cast<DistributedRdb::SubscribeMode>(mode);
    option.event = "dataChange";
    std::lock_guard<std::mutex> lock(observerMutex_);
    auto observer = std::make_shared<RdbStoreObserverImpl>(callbackId, RdbStoreObserverImpl::ParamChangeInfo, mode);
    int32_t errCode = NativeRdb::E_OK;
    if (option.mode == DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
        errCode = rdbStore_->SubscribeObserver(option, observer);
    } else {
        errCode = rdbStore_->Subscribe(option, observer);
    }
    if (errCode == NativeRdb::E_OK) {
        observers_[mode].push_back(observer);
        LOGI("subscribe success");
    }
    return errCode;
}

int32_t RdbStoreImpl::RegisterObserverProgressDetails(int64_t callbackId)
{
    std::lock_guard<std::mutex> lock(observerMutex_);
    auto observer = std::make_shared<SyncObserverImpl>(callbackId);
    int errCode = rdbStore_->RegisterAutoSyncCallback(observer);
    if (errCode == NativeRdb::E_OK) {
        syncObservers_.push_back(observer);
        LOGI("progress subscribe success");
    }
    return errCode;
}

int32_t RdbStoreImpl::UnRegisterObserver(const char *event, bool interProcess, int64_t callback)
{
    DistributedRdb::SubscribeOption option;
    option.event = event;
    interProcess ? option.mode = DistributedRdb::SubscribeMode::LOCAL_SHARED : option.mode =
        DistributedRdb::SubscribeMode::LOCAL;
    if (option.mode == DistributedRdb::SubscribeMode::LOCAL) {
        return UnRegisteredObserver(option, localObservers_, callback);
    }
    return UnRegisteredObserver(option, localSharedObservers_, callback);
}

int32_t RdbStoreImpl::UnRegisteredObserver(DistributedRdb::SubscribeOption option,
    std::map<std::string, std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers,
    int64_t callback)
{
    std::lock_guard<std::mutex> lock(observerMutex_);
    auto obs = observers.find(option.event);
    if (obs == observers.end()) {
        LOGI("observer not found, event: %{public}s", option.event.c_str());
        return RelationalStoreJsKit::OK;
    }

    auto &list = obs->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if (isSameFunction(callback, (*it)->GetCallBack())) {
            int errCode = rdbStore_->UnSubscribe(option, *it);
            if (errCode != RelationalStoreJsKit::OK) {
                return errCode;
            }
            list.erase(it);
            break;
        }
    }
    if (list.empty()) {
        observers.erase(option.event);
    }
    LOGI("unsubscribe success, event: %{public}s", option.event.c_str());
    return RelationalStoreJsKit::OK;
}

int32_t RdbStoreImpl::UnRegisterAllObserver(const char *event, bool interProcess)
{
    DistributedRdb::SubscribeOption option;
    option.event = event;
    interProcess ? option.mode = DistributedRdb::SubscribeMode::LOCAL_SHARED : option.mode =
        DistributedRdb::SubscribeMode::LOCAL;
    if (option.mode == DistributedRdb::SubscribeMode::LOCAL) {
        return UnRegisteredAllObserver(option, localObservers_);
    }
    return UnRegisteredAllObserver(option, localSharedObservers_);
}

int32_t RdbStoreImpl::UnRegisteredAllObserver(DistributedRdb::SubscribeOption option, std::map<std::string,
    std::list<std::shared_ptr<RdbStoreObserverImpl>>> &observers)
{
    std::lock_guard<std::mutex> lock(observerMutex_);
    auto obs = observers.find(option.event);
    if (obs == observers.end()) {
        LOGI("observer not found, event: %{public}s", option.event.c_str());
        return RelationalStoreJsKit::OK;
    }

    int errCode = rdbStore_->UnSubscribe(option, nullptr);
    if (errCode != RelationalStoreJsKit::OK) {
        return errCode;
    }
    observers.erase(option.event);
    LOGI("unsubscribe success, event: %{public}s", option.event.c_str());
    return RelationalStoreJsKit::OK;
}

int32_t RdbStoreImpl::UnRegisterObserverArrStrChangeInfo(int32_t subscribeType, int64_t callbackId)
{
    int32_t mode = subscribeType;
    DistributedRdb::SubscribeOption option;
    option.mode = static_cast<DistributedRdb::SubscribeMode>(mode);
    option.event = "dataChange";
    std::lock_guard<std::mutex> lock(observerMutex_);
    for (auto it = observers_[mode].begin(); it != observers_[mode].end();) {
        if (*it == nullptr) {
            it = observers_[mode].erase(it);
            continue;
        }
        if (((**it).GetCallBackId() != callbackId)) {
            ++it;
            continue;
        }
        int errCode = NativeRdb::E_OK;
        if (option.mode == DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
            errCode = rdbStore_->UnsubscribeObserver(option, *it);
        } else {
            errCode = rdbStore_->UnSubscribe(option, *it);
        }
        if (errCode != NativeRdb::E_OK) {
            return errCode;
        }
        it = observers_[mode].erase(it);
    }
    return NativeRdb::E_OK;
}

int32_t RdbStoreImpl::UnRegisterObserverArrStrChangeInfoAll(int32_t subscribeType)
{
    int32_t mode = subscribeType;
    DistributedRdb::SubscribeOption option;
    option.mode = static_cast<DistributedRdb::SubscribeMode>(mode);
    option.event = "dataChange";
    std::lock_guard<std::mutex> lock(observerMutex_);
    for (auto it = observers_[mode].begin(); it != observers_[mode].end();) {
        if (*it == nullptr) {
            it = observers_[mode].erase(it);
            continue;
        }
        int errCode = NativeRdb::E_OK;
        if (option.mode == DistributedRdb::SubscribeMode::LOCAL_DETAIL) {
            errCode = rdbStore_->UnsubscribeObserver(option, *it);
        } else {
            errCode = rdbStore_->UnSubscribe(option, *it);
        }
        if (errCode != NativeRdb::E_OK) {
            return errCode;
        }
        it = observers_[mode].erase(it);
    }
    return NativeRdb::E_OK;
}

int32_t RdbStoreImpl::UnRegisterObserverProgressDetails(int64_t callbackId)
{
    std::lock_guard<std::mutex> lock(observerMutex_);
    for (auto it = syncObservers_.begin(); it != syncObservers_.end();) {
        if (*it == nullptr) {
            it = syncObservers_.erase(it);
            continue;
        }
        if (((**it).GetCallBackId() != callbackId)) {
            ++it;
            continue;
        }

        int32_t errCode = rdbStore_->UnregisterAutoSyncCallback(*it);
        if (errCode != NativeRdb::E_OK) {
            return errCode;
        }
        it = syncObservers_.erase(it);
    }
    return NativeRdb::E_OK;
}

int32_t RdbStoreImpl::UnRegisterObserverProgressDetailsAll()
{
    std::lock_guard<std::mutex> lock(observerMutex_);
    for (auto it = syncObservers_.begin(); it != syncObservers_.end();) {
        if (*it == nullptr) {
            it = syncObservers_.erase(it);
            continue;
        }
        int32_t errCode = rdbStore_->UnregisterAutoSyncCallback(*it);
        if (errCode != NativeRdb::E_OK) {
            return errCode;
        }
        it = syncObservers_.erase(it);
    }
    return NativeRdb::E_OK;
}
}
}