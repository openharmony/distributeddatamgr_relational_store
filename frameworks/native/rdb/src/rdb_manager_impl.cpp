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

#include "rdb_manager_impl.h"

#include <thread>

#include "ipc_skeleton.h"
#include "irdb_service.h"
#include "iservice_registry.h"
#include "itypes_util.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_service_proxy.h"
#include "system_ability_definition.h"

namespace OHOS::DistributedRdb {
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;

std::shared_ptr<RdbStoreDataServiceProxy> RdbManagerImpl::GetDistributedDataManager()
{
    auto manager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (manager == nullptr) {
        LOG_ERROR("get system ability manager failed");
        return nullptr;
    }
    auto remoteObject = manager->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (remoteObject == nullptr) {
        LOG_ERROR("get distributed data manager failed");
        return nullptr;
    }
    sptr<RdbStoreDataServiceProxy> rdbStoreDataServiceProxy = new(std::nothrow) RdbStoreDataServiceProxy(remoteObject);
    if (rdbStoreDataServiceProxy == nullptr) {
        LOG_ERROR("new RdbStoreDataServiceProxy failed");
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
        LOG_ERROR("new ServiceDeathRecipient failed");
    }
    if (!remote->AddDeathRecipient(deathRecipient)) {
        LOG_ERROR("add death recipient failed");
    }
}

RdbManagerImpl::RdbManagerImpl()
{
    LOG_INFO("construct");
}

RdbManagerImpl::~RdbManagerImpl()
{
    LOG_INFO("destroy");
}

RdbManagerImpl& RdbManagerImpl::GetInstance()
{
    static RdbManagerImpl manager;
    return manager;
}

int RdbManagerImpl::GetRdbService(const RdbSyncerParam &param, std::shared_ptr<RdbService> &service)
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
        LOG_ERROR("get distributed data manager failed");
        return E_ERROR;
    }

    auto remote = distributedDataMgr_->GetFeatureInterface(DistributedRdb::RdbService::SERVICE_NAME);
    if (remote == nullptr) {
        LOG_ERROR("get rdb service failed");
        return E_NOT_SUPPORTED;
    }
    sptr<DistributedRdb::RdbServiceProxy> serviceProxy = nullptr;
    if (remote->IsProxyObject()) {
        serviceProxy = iface_cast<DistributedRdb::RdbServiceProxy>(remote);
    }

    if (serviceProxy == nullptr) {
        serviceProxy = new (std::nothrow) RdbServiceProxy(remote);
    }

    if (serviceProxy == nullptr) {
        return E_ERROR;
    }
    if (serviceProxy->InitNotifier(param) != RDB_OK) {
        LOG_ERROR("init notifier failed");
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
    LOG_INFO("rdb service has dead!!");
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
    LOG_INFO("init data service proxy.");
}

sptr<IRemoteObject> RdbStoreDataServiceProxy::GetFeatureInterface(const std::string &name)
{
    LOG_INFO("%s", name.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(RdbStoreDataServiceProxy::GetDescriptor())) {
        LOG_ERROR("write descriptor failed");
        return nullptr;
    }

    if (!ITypesUtil::Marshal(data, name)) {
        LOG_ERROR("write descriptor failed");
        return nullptr;
    }

    MessageParcel reply;
    MessageOption mo { MessageOption::TF_SYNC };
    int32_t error = Remote()->SendRequest(GET_FEATURE_INTERFACE, data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest returned %{public}d", error);
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject;
    if (!ITypesUtil::Unmarshal(reply, remoteObject)) {
        LOG_ERROR("remote object is nullptr");
        return nullptr;
    }
    return remoteObject;
}
} // namespace OHOS::DistributedRdb
