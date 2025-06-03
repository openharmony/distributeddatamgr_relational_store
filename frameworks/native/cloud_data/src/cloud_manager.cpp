/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#define LOG_TAG "CloudManager"
#include "cloud_manager.h"

#include "app_mgr_client.h"
#include "cloud_service_proxy.h"
#include "data_mgr_service.h"
#include "icloud_client_death_observer.h"
#include "icloud_service.h"
#include "iservice_registry.h"
#include "itypes_util.h"
#include "logger.h"
#include "singleton.h"
#include "system_ability_definition.h"

namespace OHOS::CloudData {
using namespace OHOS::Rdb;

class CloudDeath : public IRemoteObject::DeathRecipient {
public:
    explicit CloudDeath(std::function<void()> action) : action_(std::move(action)) {};
    void OnRemoteDied(const wptr<IRemoteObject> &object) override
    {
        if (action_) {
            action_();
        }
    }

private:
    std::function<void()> action_;
};

CloudManager &CloudManager::GetInstance()
{
    static CloudManager instance;
    return instance;
}

std::string CloudManager::GetProcessName()
{
    AppExecFwk::RunningProcessInfo info;
    auto appMgrClient = DelayedSingleton<AppExecFwk::AppMgrClient>::GetInstance();
    if (appMgrClient != nullptr && appMgrClient->GetProcessRunningInformation(info) == 0) {
        return info.processName_;
    }
    return "";
}

std::pair<int32_t, std::shared_ptr<CloudService>> CloudManager::GetCloudService()
{
    std::lock_guard<decltype(mutex_)> lg(mutex_);
    if (cloudService_ != nullptr) {
        return std::make_pair(CloudService::Status::SUCCESS, cloudService_);
    }

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        LOG_ERROR("Get system ability manager failed.");
        return std::make_pair(CloudService::Status::SERVER_UNAVAILABLE, nullptr);
    }
    auto dataMgrObject = saMgr->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (dataMgrObject == nullptr) {
        LOG_ERROR("Get distributed data manager failed.");
        return std::make_pair(CloudService::Status::SERVER_UNAVAILABLE, nullptr);
    }

    sptr<DataMgrService> dataMgr = new (std::nothrow) DataMgrService(dataMgrObject);
    if (dataMgr == nullptr) {
        LOG_ERROR("New CloudDataServiceProxy failed.");
        return std::make_pair(CloudService::Status::SERVER_UNAVAILABLE, nullptr);
    }
    sptr<IRemoteObject> clientDeathObserver = new (std::nothrow) CloudClientDeathObserverStub();
    dataMgr->RegisterClientDeathObserver(GetProcessName(), clientDeathObserver);

    auto cloudObject = dataMgr->GetFeatureInterface(CloudService::SERVICE_NAME);
    if (cloudObject == nullptr) {
        LOG_ERROR("Get cloud service failed.");
        return std::make_pair(CloudService::Status::FEATURE_UNAVAILABLE, nullptr);
    }

    cloudObject->AddDeathRecipient(new CloudDeath([this]() {
        std::lock_guard<decltype(mutex_)> lg(mutex_);
        cloudService_ = nullptr;
    }));

    sptr<CloudServiceProxy> proxy = new (std::nothrow) CloudServiceProxy(cloudObject);
    if (proxy == nullptr) {
        return std::make_pair(CloudService::Status::FEATURE_UNAVAILABLE, nullptr);
    }

    cloudService_ = std::shared_ptr<CloudService>(proxy.GetRefPtr(), [holder = proxy](const auto *) {});
    if (cloudService_ == nullptr) {
        return std::make_pair(CloudService::Status::FEATURE_UNAVAILABLE, nullptr);
    }
    return std::make_pair(CloudService::Status::SUCCESS, cloudService_);
}
} // namespace OHOS::CloudData