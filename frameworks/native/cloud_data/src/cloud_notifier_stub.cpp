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
#define LOG_TAG "CloudNotifierStub"

#include "cloud_notifier_stub.h"

#include <ipc_skeleton.h>

#include "cloud_service.h"
#include "itypes_util.h"
#include "logger.h"

namespace OHOS::CloudData {
using namespace Rdb;
CloudNotifierStub::CloudNotifierStub(const SyncCompleteHandler &completeNotifier)
    : IRemoteStub<CloudNotifierStubBroker>(), completeNotifier_(completeNotifier)
{
}

CloudNotifierStub::~CloudNotifierStub() noexcept
{
}

bool CloudNotifierStub::CheckInterfaceToken(MessageParcel &data)
{
    auto localDescriptor = GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        LOG_ERROR("interface token is not equal.");
        return false;
    }
    return true;
}

int CloudNotifierStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    LOG_DEBUG("code:%{public}u, callingPid:%{public}d", code, IPCSkeleton::GetCallingPid());
    if (!CheckInterfaceToken(data)) {
        return CloudService::ERROR;
    }

    if (code < static_cast<uint32_t>(NotifierCode::CLOUD_NOTIFIER_CMD_MAX)) {
        return (this->*HANDLES[code])(data, reply);
    }

    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t CloudNotifierStub::OnCompleteInner(MessageParcel &data, MessageParcel &reply)
{
    uint32_t seqNum = 0;
    Details result;
    if (!ITypesUtil::Unmarshal(data, seqNum, result)) {
        LOG_ERROR("read sync result failed.");
        return CloudService::ERROR;
    }
    return OnComplete(seqNum, std::move(result));
}

int32_t CloudNotifierStub::OnComplete(uint32_t seqNum, Details &&result)
{
    if (completeNotifier_) {
        completeNotifier_(seqNum, std::move(result));
    }
    return CloudService::SUCCESS;
}
} // namespace OHOS::CloudData
