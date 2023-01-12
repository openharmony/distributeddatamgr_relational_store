/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define LOG_TAG "RdbManagerImpl"

#include "rdb_manager_impl.h"

#include <thread>
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "system_ability_definition.h"

#include "log_print.h"
#include "irdb_service.h"
#include "itypes_util.h"
#include "rdb_service_proxy.h"

namespace OHOS::DistributedRdb {
std::shared_ptr<RdbStoreDataServiceProxy> RdbManagerImpl::GetDistributedDataManager()
{
    int retry = 0;
    while (++retry <= GET_SA_RETRY_TIMES) {
        auto manager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (manager == nullptr) {
            ZLOGE("get system ability manager failed");
            return nullptr;
        }
        ZLOGI("get distributed data manager %{public}d", retry);
        auto remoteObject = manager->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
        if (remoteObject == nullptr) {
            std::this_thread::sleep_for(std::chrono::seconds(RETRY_INTERVAL));
            continue;
        }
        ZLOGI("get distributed data manager success");
        sptr<RdbStoreDataServiceProxy> rdbStoreDataServiceProxy = new RdbStoreDataServiceProxy(remoteObject);
        return std::shared_ptr<RdbStoreDataServiceProxy>(rdbStoreDataServiceProxy.GetRefPtr(),
            [holder = rdbStoreDataServiceProxy](const auto *) {});
    }

    ZLOGE("get distributed data manager failed");
    return nullptr;
}

static void LinkToDeath(const sptr<IRemoteObject>& remote)
{
    auto& manager = RdbManagerImpl::GetInstance();
    sptr<RdbManagerImpl::ServiceDeathRecipient> deathRecipient =
        new(std::nothrow) RdbManagerImpl::ServiceDeathRecipient(&manager);
    if (!remote->AddDeathRecipient(deathRecipient)) {
        ZLOGE("add death recipient failed");
    }
    ZLOGE("success");
}

RdbManagerImpl::RdbManagerImpl()
{
    ZLOGI("construct");
}

RdbManagerImpl::~RdbManagerImpl()
{
    ZLOGI("destroy");
}

RdbManagerImpl& RdbManagerImpl::GetInstance()
{
    static RdbManagerImpl manager;
    return manager;
}

sptr<RdbServiceProxy> RdbManagerImpl::GetRdbService()
{
    if (distributedDataMgr_ == nullptr) {
        distributedDataMgr_ = GetDistributedDataManager();
    }
    if (distributedDataMgr_ == nullptr) {
        ZLOGE("get distributed data manager failed");
        return nullptr;
    }

    auto remote = distributedDataMgr_->GetFeatureInterface("relational_store");
    if (remote == nullptr) {
        ZLOGE("get rdb service failed");
        return nullptr;
    }
    return iface_cast<DistributedRdb::RdbServiceProxy>(remote);
}

std::shared_ptr<RdbService> RdbManagerImpl::GetRdbService(const RdbSyncerParam& param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (rdbService_ != nullptr) {
        return rdbService_;
    }
    auto service = GetRdbService();
    if (service == nullptr) {
        return nullptr;
    }
    if (service->InitNotifier(param) != RDB_OK) {
        ZLOGE("init notifier failed");
        return nullptr;
    }
    sptr<IRdbService> serviceBase = service;
    LinkToDeath(serviceBase->AsObject().GetRefPtr());
    rdbService_ = std::shared_ptr<RdbService>(service.GetRefPtr(), [holder = service] (const auto*) {});
    bundleName_ = param.bundleName_;
    return rdbService_;
}

void RdbManagerImpl::OnRemoteDied()
{
    ZLOGI("rdb service has dead!!");
    auto proxy = std::static_pointer_cast<RdbServiceProxy>(rdbService_);
    auto observers = proxy->ExportObservers();
    ResetServiceHandle();

    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    RdbSyncerParam param;
    param.bundleName_ = bundleName_;
    auto service = GetRdbService(param);
    if (service == nullptr) {
        return;
    }
    proxy = std::static_pointer_cast<RdbServiceProxy>(service);
    if (proxy == nullptr) {
        return;
    }
    ZLOGI("restore observer");
    proxy->ImportObservers(observers);
}

void RdbManagerImpl::ResetServiceHandle()
{
    ZLOGI("enter");
    std::lock_guard<std::mutex> lock(mutex_);
    distributedDataMgr_ = nullptr;
    rdbService_ = nullptr;
}

RdbStoreDataServiceProxy::RdbStoreDataServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<DistributedRdb::IKvStoreDataService>(impl)
{
    ZLOGI("init data service proxy.");
}

sptr<IRemoteObject> RdbStoreDataServiceProxy::GetFeatureInterface(const std::string &name)
{
    ZLOGI("%s", name.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(RdbStoreDataServiceProxy::GetDescriptor())) {
        ZLOGE("write descriptor failed");
        return nullptr;
    }

    if (!ITypesUtil::Marshal(data, name)) {
        ZLOGE("write descriptor failed");
        return nullptr;
    }

    MessageParcel reply;
    MessageOption mo { MessageOption::TF_SYNC };
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
} // namespace OHOS::DistributedRdb
