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

#include "global_resource.h"
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
using RdbServiceProxy = DistributedRdb::RdbServiceProxy;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedRdb::RelationalStore;
constexpr int32_t MAX_RETRY = 100;
constexpr int32_t LOAD_SA_TIMEOUT_SECONDS = 1;
class DeathStub : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedRdb.DeathStub");
};
class DeathStubImpl : public IRemoteStub<DeathStub> {};
std::shared_ptr<RdbStoreDataServiceProxy> RdbManagerImpl::GetDistributedDataManager(const std::string &bundleName)
{
    auto manager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (manager == nullptr) {
        LOG_ERROR("Get system ability manager failed.");
        return nullptr;
    }
    auto dataMgr = manager->CheckSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID);
    if (dataMgr == nullptr) {
        LOG_WARN("Get distributed data manager CheckSystemAbility failed.");
        dataMgr = manager->LoadSystemAbility(DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID, LOAD_SA_TIMEOUT_SECONDS);
        if (dataMgr == nullptr) {
            LOG_ERROR("Get distributed data manager LoadSystemAbility failed.");
            return nullptr;
        }
    }
    sptr<RdbStoreDataServiceProxy> dataService = new (std::nothrow) RdbStoreDataServiceProxy(dataMgr);
    if (dataService == nullptr) {
        LOG_ERROR("New RdbStoreDataServiceProxy failed.");
        return nullptr;
    }

    sptr<IRemoteObject> observer = new (std::nothrow) DeathStubImpl();
    dataService->RegisterDeathObserver(bundleName, observer);
    return std::shared_ptr<RdbStoreDataServiceProxy>(dataService.GetRefPtr(), [dataService](const auto *) {});
}

sptr<IRemoteObject::DeathRecipient> RdbManagerImpl::LinkToDeath(const sptr<IRemoteObject> &remote)
{
    auto &manager = RdbManagerImpl::GetInstance();
    sptr<RdbManagerImpl::ServiceDeathRecipient> deathRecipient = new (std::nothrow)
        RdbManagerImpl::ServiceDeathRecipient(&manager);
    if (deathRecipient == nullptr) {
        LOG_ERROR("New ServiceDeathRecipient failed.");
        return nullptr;
    }
    if (!remote->AddDeathRecipient(deathRecipient)) {
        LOG_ERROR("Add death recipient failed.");
    }
    return deathRecipient;
}

RdbManagerImpl::RdbManagerImpl()
{
}

RdbManagerImpl::~RdbManagerImpl()
{
    LOG_INFO("Destroy.");
}

RdbManagerImpl &RdbManagerImpl::GetInstance()
{
    static RdbManagerImpl manager;
    return manager;
}

std::pair<int32_t, std::shared_ptr<RdbService>> RdbManagerImpl::GetRdbService(const RdbSyncerParam &param)
{
    if (param.bundleName_.empty()) {
        return { E_INVALID_ARGS, nullptr };
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (rdbService_ != nullptr) {
        return { E_OK, rdbService_ };
    }

    if (distributedDataMgr_ == nullptr) {
        distributedDataMgr_ = GetDistributedDataManager(param.bundleName_);
    }
    if (distributedDataMgr_ == nullptr) {
        LOG_ERROR("Get distributed data manager failed.");
        return { E_SERVICE_NOT_FOUND, nullptr };
    }

    auto remote = distributedDataMgr_->GetFeatureInterface(DistributedRdb::RdbService::SERVICE_NAME);
    if (remote == nullptr) {
        LOG_ERROR("Get rdb service failed.");
        return { E_NOT_SUPPORT, nullptr };
    }

    if (!remote->IsProxyObject()) {
        return { E_NOT_SUPPORT, nullptr };
    }

    sptr<RdbServiceProxy> rdbService = iface_cast<RdbServiceProxy>(remote);
    if (rdbService == nullptr) {
        rdbService = new (std::nothrow) RdbServiceProxy(remote);
    }

    if (rdbService == nullptr || rdbService->InitNotifier(param) != RDB_OK) {
        LOG_ERROR("Init notifier failed.");
        return { E_ERROR, nullptr };
    }

    sptr<IRdbService> serviceBase = rdbService;
    auto deathRecipient = LinkToDeath(serviceBase->AsObject());
    // the rdbService is not null, so rdbService.GetRefPtr() is not null;
    rdbService_ = std::shared_ptr<RdbService>(rdbService.GetRefPtr(), [rdbService, deathRecipient](const auto *) {
        sptr<IRdbService> serviceBase = rdbService;
        serviceBase->AsObject()->RemoveDeathRecipient(deathRecipient);
    });
    param_ = param;
    GlobalResource::RegisterClean(GlobalResource::IPC, []() {
        return RdbManagerImpl::GetInstance().CleanUp();
    });
    return { E_OK, rdbService_ };
}

std::string RdbManagerImpl::GetSelfBundleName()
{
    std::shared_ptr<RdbStoreDataServiceProxy> distributedDataMgr = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!bundleName_.empty()) {
            return bundleName_;
        }
        distributedDataMgr = distributedDataMgr_;
    }
    if (distributedDataMgr == nullptr) {
        distributedDataMgr = GetDistributedDataManager("");
    }
    if (distributedDataMgr == nullptr) {
        LOG_ERROR("Get distributed data manager failed.");
        return "";
    }
    auto [code, bundle] = distributedDataMgr->GetSelfBundleName();
    if (code != E_OK || bundle.empty()) {
        return "";
    }
    std::lock_guard<std::mutex> lock(mutex_);
    bundleName_ = bundle;
    return bundle;
}

void RdbManagerImpl::OnRemoteDied()
{
    LOG_INFO("Rdb service has dead!");
    if (rdbService_ == nullptr) {
        ResetServiceHandle();
        return;
    }
    auto proxy = std::static_pointer_cast<RdbServiceProxy>(rdbService_);
    if (proxy == nullptr) {
        return;
    }
    auto observers = proxy->ExportObservers();
    auto syncObservers = proxy->ExportSyncObservers();
    proxy->OnRemoteDeadSyncComplete();
    ResetServiceHandle();

    std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    auto [errCode, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param_);
    if (errCode != E_OK) {
        return;
    }
    proxy = std::static_pointer_cast<RdbServiceProxy>(service);
    if (proxy == nullptr) {
        return;
    }
    proxy->ImportObservers(observers);
    proxy->ImportSyncObservers(syncObservers);
}

void RdbManagerImpl::ResetServiceHandle()
{
    std::lock_guard<std::mutex> lock(mutex_);
    distributedDataMgr_ = nullptr;
    rdbService_ = nullptr;
}

int32_t RdbManagerImpl::CleanUp()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (distributedDataMgr_ != nullptr) {
        auto code = distributedDataMgr_->Exit();
        if (code != E_OK) {
            LOG_ERROR("Exit failed.code:%{public}d!", code);
            return code;
        }
    }
    distributedDataMgr_ = nullptr;
    if (rdbService_.use_count() > 1) {
        LOG_WARN("RdbService has other in use:%{public}ld!", rdbService_.use_count());
        return E_ERROR;
    }
    rdbService_ = nullptr;
    return E_OK;
}

RdbStoreDataServiceProxy::RdbStoreDataServiceProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<DistributedRdb::IKvStoreDataService>(impl)
{
}

sptr<IRemoteObject> RdbStoreDataServiceProxy::GetFeatureInterface(const std::string &name)
{
    LOG_DEBUG("%{public}s", name.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(RdbStoreDataServiceProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed.");
        return nullptr;
    }

    if (!ITypesUtil::Marshal(data, name)) {
        LOG_ERROR("Write descriptor failed.");
        return nullptr;
    }

    MessageParcel reply;
    MessageOption mo{ MessageOption::TF_SYNC };
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(KvStoreInterfaceCode::GET_FEATURE_INTERFACE), data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest returned %{public}d", error);
        return nullptr;
    }

    sptr<IRemoteObject> remoteObject;
    if (!ITypesUtil::Unmarshal(reply, remoteObject)) {
        LOG_ERROR("Remote object is nullptr.");
        return nullptr;
    }
    return remoteObject;
}

int32_t RdbStoreDataServiceProxy::RegisterDeathObserver(
    const std::string &bundleName, sptr<IRemoteObject> observer, const std::string &featureName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(RdbStoreDataServiceProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed.");
        return E_ERROR;
    }

    if (!ITypesUtil::Marshal(data, bundleName, observer, featureName)) {
        LOG_ERROR("Write descriptor failed.");
        return E_ERROR;
    }

    MessageParcel reply;
    MessageOption mo{ MessageOption::TF_SYNC };
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(KvStoreInterfaceCode::REGISTER_DEATH_OBSERVER), data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest returned %{public}d", error);
        return E_ERROR;
    }

    int32_t status = E_ERROR;
    ITypesUtil::Unmarshal(reply, status);
    if (status == E_OK) {
        clientDeathObserver_ = observer;
    }
    return status;
}

int32_t RdbStoreDataServiceProxy::Exit(const std::string &featureName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(RdbStoreDataServiceProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed.");
        return E_ERROR;
    }

    if (!ITypesUtil::Marshal(data, featureName)) {
        LOG_ERROR("Write descriptor failed.");
        return E_ERROR;
    }

    MessageParcel reply;
    MessageOption mo{ MessageOption::TF_SYNC };
    int32_t error = Remote()->SendRequest(static_cast<uint32_t>(KvStoreInterfaceCode::FEATURE_EXIT), data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest returned %{public}d", error);
        return E_ERROR;
    }

    int32_t status = E_ERROR;
    ITypesUtil::Unmarshal(reply, status);
    if (status == E_OK) {
        int32_t retry = 0;
        while (clientDeathObserver_ != nullptr && clientDeathObserver_->GetSptrRefCount() > 1 && retry < MAX_RETRY) {
            retry++;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (clientDeathObserver_ != nullptr && clientDeathObserver_->GetSptrRefCount() > 1) {
            LOG_WARN("observer still in use! count:%{public}d", clientDeathObserver_->GetSptrRefCount());
            return E_ERROR;
        }
    }
    return status;
}

std::pair<int32_t, std::string> RdbStoreDataServiceProxy::GetSelfBundleName()
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(RdbStoreDataServiceProxy::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed.");
        return {E_ERROR, ""};
    }

    MessageParcel reply;
    MessageOption mo{ MessageOption::TF_SYNC };
    int32_t error =
        Remote()->SendRequest(static_cast<uint32_t>(KvStoreInterfaceCode::GET_SELF_BUNDLENAME), data, reply, mo);
    if (error != 0) {
        LOG_ERROR("SendRequest returned %{public}d", error);
        return {E_ERROR, ""};
    }

    std::string bundleName = "";
    int32_t code = E_OK;
    if (!ITypesUtil::Unmarshal(reply, bundleName, code)) {
        LOG_ERROR("Unmarshal failed");
        return {E_ERROR, ""};
    }
    return {code, bundleName};
}
} // namespace OHOS::DistributedRdb
