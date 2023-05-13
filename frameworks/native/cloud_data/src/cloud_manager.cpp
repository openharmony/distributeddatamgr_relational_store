/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define LOG_TAG "CloudManagerImpl"

#include "cloud_manager.h"

#include "cloud_service_proxy.h"
#include "icloud_service.h"
#include "iservice_registry.h"
#include "itypes_util.h"
#include "log_print.h"
#include "system_ability_definition.h"
namespace OHOS::CloudData {
class DataMgrService : public IRemoteProxy<CloudData::IKvStoreDataService> {
public:
    explicit DataMgrService(const sptr<IRemoteObject> &impl);
    ~DataMgrService() = default;
    sptr<IRemoteObject> GetFeatureInterface(const std::string &name) override;
};

class CloudDeath : public IRemoteObject::DeathRecipient {
public:
    explicit CloudDeath(std::function<void()> action) : action_(std::move(action)){};
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

std::pair<int32_t, std::shared_ptr<CloudService>> CloudManager::GetCloudService()
{
    std::lock_guard<decltype(mutex_)> lg(mutex_);
    if (cloudService_ != nullptr) {
        return std::make_pair(CloudService::Status::SUCCESS, cloudService_);
    }

    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        ZLOGE("get system ability manager failed");
        return std::make_pair(CloudService::Status::SERVER_UNAVAILABLE, nullptr);
    }
    auto dataMgrObject = saMgr->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (dataMgrObject == nullptr) {
        ZLOGE("get distributed data manager failed");
        return std::make_pair(CloudService::Status::SERVER_UNAVAILABLE, nullptr);
    }

    sptr<DataMgrService> dataMgr = new (std::nothrow) DataMgrService(dataMgrObject);
    if (dataMgr == nullptr) {
        ZLOGE("new CloudDataServiceProxy failed");
        return std::make_pair(CloudService::Status::SERVER_UNAVAILABLE, nullptr);
    }

    auto cloudObject = dataMgr->GetFeatureInterface(CloudService::SERVICE_NAME);
    if (cloudObject == nullptr) {
        ZLOGE("get cloud service failed");
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
    return std::make_pair(CloudService::Status::SUCCESS, nullptr);
}

DataMgrService::DataMgrService(const sptr<IRemoteObject> &impl) : IRemoteProxy<CloudData::IKvStoreDataService>(impl)
{
    ZLOGI("init proxy");
}

sptr<IRemoteObject> DataMgrService::GetFeatureInterface(const std::string &name)
{
    ZLOGI("%s", name.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataMgrService::GetDescriptor())) {
        ZLOGE("write descriptor failed");
        return nullptr;
    }

    if (!ITypesUtil::Marshal(data, name)) {
        ZLOGE("write descriptor failed");
        return nullptr;
    }

    MessageParcel reply;
    MessageOption mo{ MessageOption::TF_SYNC };
    int32_t error = Remote()->SendRequest(GET_FEATURE_INTERFACE, data, reply, mo);
    if (error != 0) {
        ZLOGE("SendRequest returned %{public}d", error);
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject;
    if (!ITypesUtil::Unmarshal(reply, remoteObject)) {
        ZLOGE("remote object is nullptr");
        return nullptr;
    }
    return remoteObject;
}
} // namespace OHOS::CloudData