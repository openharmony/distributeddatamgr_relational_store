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
#define LOG_TAG "RdbNotifierStub"
#include "rdb_notifier_stub.h"
#include <ipc_skeleton.h>
#include "itypes_util.h"
#include "log_print.h"
namespace OHOS::DistributedRdb {
RdbNotifierStub::RdbNotifierStub(const SyncCompleteHandler &completeNotifier, const DataChangeHandler &changeNotifier)
    : IRemoteStub<RdbNotifierStubBroker>(), completeNotifier_(completeNotifier), changeNotifier_(changeNotifier)
{
    ZLOGI("construct");
}

RdbNotifierStub::~RdbNotifierStub() noexcept
{
    ZLOGI("destroy");
}

bool RdbNotifierStub::CheckInterfaceToken(MessageParcel& data)
{
    auto localDescriptor = GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        ZLOGE("interface token is not equal");
        return false;
    }
    return true;
}

int RdbNotifierStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
                                     MessageOption &option)
{
    ZLOGD("code:%{public}u, callingPid:%{public}d", code, IPCSkeleton::GetCallingPid());
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
    uint32_t seqNum = 0;
    Details result;
    if (!ITypesUtil::Unmarshal(data, seqNum, result)) {
        ZLOGE("read sync result failed");
        return RDB_ERROR;
    }
    return OnComplete(seqNum, std::move(result));
}

int32_t RdbNotifierStub::OnComplete(uint32_t seqNum, Details &&result)
{
    if (completeNotifier_) {
        completeNotifier_(seqNum, std::move(result));
    }
    return RDB_OK;
}

int32_t RdbNotifierStub::OnChangeInner(MessageParcel &data, MessageParcel &reply)
{
    std::string storeName;
    std::vector<std::string> devices;
    if (!ITypesUtil::Unmarshal(data, storeName, devices)) {
        ZLOGE("read sync result failed");
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
