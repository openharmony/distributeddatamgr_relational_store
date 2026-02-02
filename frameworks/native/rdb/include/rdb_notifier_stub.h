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

#ifndef DISTRIBUTED_RDB_RDB_NOTIFIER_STUB_H
#define DISTRIBUTED_RDB_RDB_NOTIFIER_STUB_H
#include "rdb_notifier.h"
#include <iremote_broker.h>
#include <iremote_stub.h>
namespace OHOS::DistributedRdb {
using NotifierIFCode = RelationalStore::IRdbNotifierInterfaceCode;

class RdbNotifierStubBroker : public IRdbNotifier, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedRdb.IRdbNotifier");
};

class RdbNotifierStub : public IRemoteStub<RdbNotifierStubBroker> {
public:
    using SyncCompleteHandler = std::function<void(uint32_t, Details &&)>;
    using AutoSyncCompleteHandler = std::function<void(std::string, Details &&)>;
    using DataChangeHandler = std::function<void(const Origin &origin, const PrimaryFields &primaries,
        ChangeInfo &&changeInfo)>;
    RdbNotifierStub(const SyncCompleteHandler&, const AutoSyncCompleteHandler&, const DataChangeHandler&);
    virtual ~RdbNotifierStub() noexcept;

    int OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override;
    int32_t OnComplete(uint32_t seqNum, Details &&result) override;
    int32_t OnComplete(const std::string& storeName, Details &&result) override;
    int32_t OnChange(const Origin &origin, const PrimaryFields &primaries, ChangeInfo &&changeInfo) override;

private:
    int32_t OnCompleteInner(MessageParcel& data, MessageParcel& reply);
    int32_t OnAutoSyncCompleteInner(MessageParcel& data, MessageParcel& reply);
    int32_t OnChangeInner(MessageParcel& data, MessageParcel& reply);
    bool CheckInterfaceToken(MessageParcel& data);

    using RequestHandle = int32_t (RdbNotifierStub::*)(MessageParcel&, MessageParcel&);
    static constexpr RequestHandle HANDLES[static_cast<uint32_t>(NotifierIFCode::RDB_NOTIFIER_CMD_MAX)] = {
        [static_cast<uint32_t>(NotifierIFCode::RDB_NOTIFIER_CMD_SYNC_COMPLETE)] = &RdbNotifierStub::OnCompleteInner,
        [static_cast<uint32_t>(NotifierIFCode::RDB_NOTIFIER_CMD_AUTO_SYNC_COMPLETE)] =
            &RdbNotifierStub::OnAutoSyncCompleteInner,
        [static_cast<uint32_t>(NotifierIFCode::RDB_NOTIFIER_CMD_DATA_CHANGE)] = &RdbNotifierStub::OnChangeInner,
    };

    SyncCompleteHandler completeNotifier_;
    AutoSyncCompleteHandler autoSyncCompleteHandler_;
    DataChangeHandler changeNotifier_;
};
} // namespace OHOS::DistributedRdb
#endif // DISTRIBUTED_RDB_RDB_NOTIFIER_STUB_H
