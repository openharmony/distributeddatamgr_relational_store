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
#define LOG_TAG "DataMgrService"
#include "data_mgr_service.h"

#include "distributeddata_relational_store_ipc_interface_code.h"
#include "itypes_util.h"
#include "logger.h"

namespace OHOS::CloudData {
using namespace OHOS::Rdb;
using namespace OHOS::DistributedRdb::RelationalStore;
DataMgrService::DataMgrService(const sptr<IRemoteObject> &impl) : IRemoteProxy<CloudData::IKvStoreDataService>(impl)
{
}

sptr<IRemoteObject> DataMgrService::GetFeatureInterface(const std::string &name)
{
    LOG_INFO("%{public}s", name.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataMgrService::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed.");
        return nullptr;
    }

    if (!ITypesUtil::Marshal(data, name)) {
        LOG_ERROR("Write descriptor failed.");
        return nullptr;
    }

    MessageParcel reply;
    MessageOption mo{ MessageOption::TF_SYNC };
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        LOG_ERROR("remote is nullptr");
        return nullptr;
    }
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(CloudKvStoreInterfaceCode::GET_FEATURE_INTERFACE), data, reply, mo);
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

int32_t DataMgrService::RegisterClientDeathObserver(const std::string &bundleName, sptr<IRemoteObject> observer)
{
    LOG_INFO("%{public}s", bundleName.c_str());
    if (bundleName.empty() || observer == nullptr) {
        LOG_ERROR("bundleName is empty or observer is nullptr.");
        return CloudService::ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DataMgrService::GetDescriptor())) {
        LOG_ERROR("Write descriptor failed.");
        return CloudService::IPC_ERROR;
    }

    if (!ITypesUtil::Marshal(data, bundleName, observer)) {
        LOG_ERROR("Write descriptor failed.");
        return CloudService::IPC_PARCEL_ERROR;
    }

    MessageParcel reply;
    MessageOption mo{ MessageOption::TF_SYNC };
    sptr<IRemoteObject> remoteObject = Remote();
    if (remoteObject == nullptr) {
        LOG_ERROR("remoteObject is nullptr");
        return CloudService::IPC_ERROR;
    }
    int32_t status = remoteObject->SendRequest(
        static_cast<uint32_t>(CloudKvStoreInterfaceCode::REGISTER_CLIENT_DEATH_OBSERVER), data, reply, mo);
    if (status != CloudService::SUCCESS) {
        LOG_ERROR("SendRequest returned %{public}d", status);
        return status;
    }

    if (!ITypesUtil::Unmarshal(reply, status)) {
        LOG_ERROR("Read status failed.");
        return CloudService::IPC_PARCEL_ERROR;
    }
    return status;
}
} // namespace OHOS::CloudData
