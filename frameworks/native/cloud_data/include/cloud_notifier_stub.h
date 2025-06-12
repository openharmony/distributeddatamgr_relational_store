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

#ifndef OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_NOTIFIER_STUB_H
#define OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_NOTIFIER_STUB_H

#include "cloud_notifier.h"
#include "iremote_broker.h"
#include "iremote_stub.h"

namespace OHOS::CloudData {
using namespace DistributedRdb;
using NotifierCode = DistributedRdb::RelationalStore::ICloudNotifierInterfaceCode;

class CloudNotifierStubBroker : public ICloudNotifier, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.CloudData.ICloudNotifier");
};

class CloudNotifierStub : public IRemoteStub<CloudNotifierStubBroker> {
public:
    using SyncCompleteHandler = std::function<void(uint32_t, Details &&)>;
    explicit CloudNotifierStub(const SyncCompleteHandler &syncComplete);
    virtual ~CloudNotifierStub() noexcept;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
    int32_t OnComplete(uint32_t seqNum, Details &&result) override;

private:
    int32_t OnCompleteInner(MessageParcel& data, MessageParcel& reply);
    bool CheckInterfaceToken(MessageParcel& data);

    using RequestHandle = int32_t (CloudNotifierStub::*)(MessageParcel&, MessageParcel&);
    static constexpr RequestHandle HANDLES[static_cast<uint32_t>(NotifierCode::CLOUD_NOTIFIER_CMD_MAX)] = {
        [static_cast<uint32_t>(NotifierCode::CLOUD_NOTIFIER_CMD_SYNC_COMPLETE)] = &CloudNotifierStub::OnCompleteInner,
    };

    SyncCompleteHandler completeNotifier_;
};
} // namespace OHOS::CloudData
#endif // OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_NOTIFIER_STUB_H
