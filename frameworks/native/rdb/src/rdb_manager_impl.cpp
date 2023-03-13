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
#include "rdb_errno.h"

namespace OHOS::DistributedRdb {
using namespace OHOS::NativeRdb;
std::shared_ptr<RdbStoreDataServiceProxy> RdbManagerImpl::GetDistributedDataManager()
{
    auto manager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (manager == nullptr) {
        ZLOGE("get system ability manager failed");
        return nullptr;
    }
    auto remoteObject = manager->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (remoteObject == nullptr) {
        ZLOGE("get distributed data manager failed");
        return nullptr;
    }
    sptr<RdbStoreDataServiceProxy> rdbStoreDataServiceProxy = new(std::nothrow) RdbStoreDataServiceProxy(remoteObject);
    if (rdbStoreDataServiceProxy == nullptr) {
        ZLOGE("new RdbStoreDataServiceProxy failed");
        return nullptr;
    }
    return std::shared_ptr<RdbStoreDataServiceProxy>(rdbStoreDataServiceProxy.GetRefPtr(),
        [holder = rdbStoreDataServiceProxy](const auto *) {});
}

static void LinkToDeath(const sptr<IRemoteObject>& remote)
{
    auto& manager = RdbManagerImpl::GetInstance();
    sptr<RdbManagerImpl::ServiceDeathRecipient> deathRecipient =
        new(std::nothrow) RdbManagerImpl::ServiceDeathRecipient(&manager);
    if (deathRecipient == nullptr) {
        ZLOGE("new ServiceDeathRecipient failed");
    }
    if (!remote->AddDeathRecipient(deathRecipient)) {
        ZLOGE("add death recipient failed");
    }
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

int RdbManagerImpl::GetRdbService(const RdbSyncerParam& param, std::shared_ptr<RdbService> service)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (rdbService_ != nullptr) {
        service = rdbService_;
        return E_OK;
    }
    if (distributedDataMgr_ == nullptr) {
        distributedDataMgr_ = GetDistributedDataManager();
    }
    if (distributedDataMgr_ == nullptr) {
        ZLOGE("get distributed data manager failed");
        return E_ERROR;
    }

    auto remote = distributedDataMgr_->GetFeatureInterface("relational_store");
    if (remote == nullptr) {
        ZLOGE("get rdb service failed");
        return E_NOT_SUPPORTED;
    }
    sptr<RdbServiceProxy> serviceProxy = iface_cast<DistributedRdb::RdbServiceProxy>(remote);
    if (serviceProxy->InitNotifier(param) != RDB_OK) {
        ZLOGE("init notifier failed");
        return E_ERROR;
    }
    sptr<IRdbService> serviceBase = serviceProxy;
    LinkToDeath(serviceBase->AsObject().GetRefPtr());
    rdbService_ = std::shared_ptr<RdbService>(serviceProxy.GetRefPtr(), [holder = serviceProxy] (const auto*) {});
    if (rdbService_ == nullptr) {
        return E_ERROR;
    }
    bundleName_ = param.bundleName_;
    service = rdbService_;
    return E_OK;
}

void RdbManagerImpl::OnRemoteDied()
{
    ZLOGI("rdb service has dead!!");
    if (rdbService_ == nullptr) {
        ResetServiceHandle();
        return;
    }
    auto proxy = std::static_pointer_cast<RdbServiceProxy>(rdbService_);
    auto observers = proxy->ExportObservers();
    ResetServiceHandle();

    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    RdbSyncerParam param;
    param.bundleName_ = bundleName_;
    std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
    int errCode = GetRdbService(param, service);
    if (errCode != E_OK) {
        return;
    }
    proxy = std::static_pointer_cast<RdbServiceProxy>(service);
    if (proxy == nullptr) {
        return;
    }
    proxy->ImportObservers(observers);
}

void RdbManagerImpl::ResetServiceHandle()
{
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
