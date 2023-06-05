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

#include "rdb_notifier_stub.h"

#include <ipc_skeleton.h>

#include "itypes_util.h"
#include "logger.h"

namespace OHOS::DistributedRdb {
using namespace OHOS::Rdb;

RdbNotifierStub::RdbNotifierStub(const SyncCompleteHandler &completeNotifier, const DataChangeHandler &changeNotifier)
    : IRemoteStub<RdbNotifierStubBroker>(), completeNotifier_(completeNotifier), changeNotifier_(changeNotifier)
{
    LOG_INFO("construct");
}

RdbNotifierStub::~RdbNotifierStub() noexcept
{
    LOG_INFO("destroy");
}

bool RdbNotifierStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        LOG_ERROR("interface token is not equal");
        return false;
    }
    return true;
}

int RdbNotifierStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                     MessageOption &option)
{
    LOG_DEBUG("code:%{public}u, callingPid:%{public}d", code, IPCSkeleton::GetCallingPid());
    if (!CheckInterfaceToken(data)) {
        return RDB_ERROR;
    }

    if (code >= 0 && code < RDB_NOTIFIER_CMD_MAX) {
        return (this->*HANDLES[code])(data, reply);
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t RdbNotifierStub::OnCompleteInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t seqNum;
    if (!data.ReadUint32(seqNum)) {
        LOG_INFO("read seq num failed");
        return RDB_ERROR;
    }
    SyncResult result;
    if (!ITypesUtil::Unmarshal(data, result)) {
        LOG_ERROR("read sync result failed");
        return RDB_ERROR;
    }
    return OnComplete(seqNum, result);
}

int32_t RdbNotifierStub::OnComplete(uint32_t seqNum, const SyncResult &result)
{
    if (completeNotifier_) {
        completeNotifier_(seqNum, result);
    }
    return RDB_OK;
}

int32_t RdbNotifierStub::OnChangeInner(MessageParcel &data, MessageParcel &reply)
{
    std::string storeName;
    if (!data.ReadString(storeName)) {
        LOG_ERROR("read store name failed");
        return RDB_ERROR;
    }
    std::vector<std::string> devices;
    if (!data.ReadStringVector(&devices)) {
        LOG_ERROR("read devices failed");
        return RDB_ERROR;
    }
    return OnChange(storeName, devices);
}

int32_t RdbNotifierStub::OnChange(const std::string& storeName, const std::vector<std::string> &devices)
{
    if (changeNotifier_) {
        changeNotifier_(storeName, devices);
    }
    return RDB_OK;
}
} // namespace OHOS::DistributedRdb
