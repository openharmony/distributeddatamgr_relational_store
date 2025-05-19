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

#define LOG_TAG "ObsMgrAdapter"
#include "obs_mgr_adapter.h"

#include <chrono>
#include <list>
#include <thread>

#include "concurrent_map.h"
#include "data_ability_observer_stub.h"
#include "dataobs_mgr_client.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_visibility.h"
#include "rdb_types.h"

using namespace OHOS::DistributedRdb;
API_EXPORT int32_t Register(const std::string &uri, std::shared_ptr<RdbStoreObserver> observer) asm("Register");
API_EXPORT int32_t Unregister(const std::string &uri, std::shared_ptr<RdbStoreObserver> observer) asm("Unregister");
API_EXPORT int32_t NotifyChange(const std::string &uri) asm("NotifyChange");
API_EXPORT void Destroy() asm("Destroy");
namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;
class RdbStoreLocalSharedObserver : public AAFwk::DataAbilityObserverStub {
public:
    explicit RdbStoreLocalSharedObserver(std::shared_ptr<RdbStoreObserver> observer) : observer_(observer){};
    virtual ~RdbStoreLocalSharedObserver(){};
    void OnChange() override
    {
        if (observer_ == nullptr) {
            LOG_ERROR("observer_ is null.");
            return;
        }
        observer_->OnChange();
    }

    bool operator==(std::shared_ptr<RdbStoreObserver> observer)
    {
        return observer_ == observer;
    }

private:
    std::shared_ptr<RdbStoreObserver> observer_ = nullptr;
};

static std::string Anonymous(const std::string &uri)
{
    return std::string(uri).substr(uri.rfind("/") + 1, uri.size());
}

static void Wait(wptr<RdbStoreLocalSharedObserver> obs)
{
    static constexpr int32_t MEX_RETRY = 100;
    int32_t retry = 0;
    while (obs->GetSptrRefCount() && ++retry < MEX_RETRY) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (obs->GetSptrRefCount()) {
        LOG_WARN("Failed to release observer, which may cause a crash");
    }
}

class ObsMgrAdapterImpl {
public:
    ObsMgrAdapterImpl() = default;
    static int32_t RegisterObserver(const std::string &uri, std::shared_ptr<RdbStoreObserver> observer);
    static int32_t UnregisterObserver(const std::string &uri, std::shared_ptr<RdbStoreObserver> observer);
    static int32_t NotifyChange(const std::string &uri);
    static void Clean();

private:
    static void RemoveObserver(const std::string &uri, sptr<RdbStoreLocalSharedObserver> observer);
    static void AddObserver(const std::string &uri, const std::list<sptr<RdbStoreLocalSharedObserver>> &observers);
    static ConcurrentMap<std::string, std::list<sptr<RdbStoreLocalSharedObserver>>> obs_;
};

ConcurrentMap<std::string, std::list<sptr<RdbStoreLocalSharedObserver>>> ObsMgrAdapterImpl::obs_;
int32_t ObsMgrAdapterImpl::RegisterObserver(const std::string &uri, std::shared_ptr<RdbStoreObserver> observer)
{
    sptr<RdbStoreLocalSharedObserver> localSharedObserver;
    int32_t code = E_OK;
    obs_.Compute(uri, [&localSharedObserver, &observer, &uri, &code](const auto &key, auto &obs) {
        for (auto it = obs.begin(); it != obs.end();) {
            if (*it == nullptr) {
                it = obs.erase(it);
                continue;
            }
            if ((**it) == observer) {
                LOG_WARN("Duplicate subscribe, uri:%{public}s", Anonymous(uri).c_str());
                return !obs.empty();
            }
            ++it;
        }
        localSharedObserver = new (std::nothrow) RdbStoreLocalSharedObserver(observer);
        if (localSharedObserver == nullptr) {
            LOG_ERROR("no memory! uri:%{public}s", Anonymous(uri).c_str());
            code = E_ERROR;
            return !obs.empty();
        }
        obs.push_back(localSharedObserver);
        return !obs.empty();
    });
    if (localSharedObserver == nullptr) {
        return code;
    }
    auto client = OHOS::AAFwk::DataObsMgrClient::GetInstance();
    if (client == nullptr) {
        RemoveObserver(uri, localSharedObserver);
        LOG_ERROR("Failed to get DataObsMgrClient, uri:%{public}s", Anonymous(uri).c_str());
        return E_GET_DATAOBSMGRCLIENT_FAIL;
    }
    code = client->RegisterObserver(Uri(uri), localSharedObserver);
    if (code != 0) {
        RemoveObserver(uri, localSharedObserver);
        LOG_ERROR("Subscribe failed. code:%{public}d, uri:%{public}.3s", code, Anonymous(uri).c_str());
        return E_ERROR;
    }
    return E_OK;
}

int32_t ObsMgrAdapterImpl::UnregisterObserver(const std::string &uri, std::shared_ptr<RdbStoreObserver> observer)
{
    std::list<sptr<RdbStoreLocalSharedObserver>> localSharedObservers;
    obs_.Compute(uri, [&localSharedObservers, &observer](const auto &key, auto &obs) {
        for (auto it = obs.begin(); it != obs.end();) {
            if (*it == nullptr) {
                it = obs.erase(it);
                continue;
            }
            if ((**it) == observer || observer == nullptr) {
                localSharedObservers.push_back(std::move(*it));
                it = obs.erase(it);
                break;
            }
            ++it;
        }
        return !obs.empty();
    });
    if (localSharedObservers.empty()) {
        return E_OK;
    }
    auto client = OHOS::AAFwk::DataObsMgrClient::GetInstance();
    if (client == nullptr) {
        AddObserver(uri, localSharedObservers);
        LOG_ERROR("Failed to get DataObsMgrClient, uri:%{public}s", Anonymous(uri).c_str());
        return E_GET_DATAOBSMGRCLIENT_FAIL;
    }
    for (auto it = localSharedObservers.begin(); it != localSharedObservers.end();) {
        if (*it == nullptr) {
            it = localSharedObservers.erase(it);
            continue;
        }
        int32_t err = client->UnregisterObserver(Uri(uri), *it);
        if (err != 0) {
            AddObserver(uri, localSharedObservers);
            LOG_ERROR("UnregisterObserver failed. code:%{public}d, uri:%{public}s", err, Anonymous(uri).c_str());
            return err;
        }
        wptr<RdbStoreLocalSharedObserver> obs(*it);
        it = localSharedObservers.erase(it);
        Wait(obs);
    }
    return E_OK;
}

int32_t ObsMgrAdapterImpl::NotifyChange(const std::string &uri)
{
    auto client = OHOS::AAFwk::DataObsMgrClient::GetInstance();
    if (client == nullptr) {
        LOG_ERROR("Failed to get DataObsMgrClient, uri:%{public}s", Anonymous(uri).c_str());
        return E_GET_DATAOBSMGRCLIENT_FAIL;
    }
    auto err = client->NotifyChange(Uri(uri));
    if (err != 0) {
        LOG_ERROR("Notify failed, uri:%{public}s", Anonymous(uri).c_str());
        return E_ERROR;
    }
    return E_OK;
}

void ObsMgrAdapterImpl::Clean()
{
    auto client = OHOS::AAFwk::DataObsMgrClient::GetInstance();
    if (client == nullptr) {
        LOG_ERROR("Failed to get DataObsMgrClient");
        return;
    }
    std::list<wptr<RdbStoreLocalSharedObserver>> released;
    obs_.EraseIf([client, &released](const auto &key, auto &observer) {
        for (auto it = observer.begin(); it != observer.end();) {
            if (*it == nullptr) {
                it = observer.erase(it);
                continue;
            }
            client->UnregisterObserver(Uri(key), *it);
            released.push_back(*it);
            it = observer.erase(it);
        }
        return true;
    });
    for (auto &obs : released) {
        Wait(obs);
    }
}

void ObsMgrAdapterImpl::RemoveObserver(const std::string &uri, sptr<RdbStoreLocalSharedObserver> observer)
{
    obs_.ComputeIfPresent(uri, [&observer](const auto &key, auto &obs) {
        for (auto it = obs.begin(); it != obs.end();) {
            if (*it == nullptr) {
                it = obs.erase(it);
                continue;
            }
            if (observer == nullptr || (*it) == observer) {
                it = obs.erase(it);
                continue;
            }
            ++it;
        }
        return !obs.empty();
    });
}

void ObsMgrAdapterImpl::AddObserver(
    const std::string &uri, const std::list<sptr<RdbStoreLocalSharedObserver>> &observers)
{
    obs_.Compute(uri, [&observers](const auto &key, auto &obs) {
        obs.insert(obs.end(), observers.begin(), observers.end());
        return !obs.empty();
    });
}
} // namespace OHOS::NativeRdb

int32_t Register(const std::string &uri, std::shared_ptr<RdbStoreObserver> observer)
{
    return OHOS::NativeRdb::ObsMgrAdapterImpl::RegisterObserver(uri, observer);
}

int32_t Unregister(const std::string &uri, std::shared_ptr<RdbStoreObserver> observer)
{
    return OHOS::NativeRdb::ObsMgrAdapterImpl::UnregisterObserver(uri, observer);
}

int32_t NotifyChange(const std::string &uri)
{
    return OHOS::NativeRdb::ObsMgrAdapterImpl::NotifyChange(uri);
}

void Destroy()
{
}