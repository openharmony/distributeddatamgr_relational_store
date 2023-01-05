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

#ifndef OHOS_DISTRIBUTED_DATA_KV_STORE_FRAMEWORKS_INNERKITSIMPL_RDB_RDB_NOTIFIER_STUB_H
#define OHOS_DISTRIBUTED_DATA_KV_STORE_FRAMEWORKS_INNERKITSIMPL_RDB_RDB_NOTIFIER_STUB_H
#include "rdb_notifier.h"
namespace OHOS::DistributedRdb {
class RdbNotifierStubBroker : public IRdbNotifier, public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DistributedRdb.IRdbNotifier");
};

class RdbNotifierStub : public IRemoteStub<RdbNotifierStubBroker> {
public:
    using SyncCompleteHandler = std::function<void(uint32_t, const SyncResult&)>;
    using DataChangeHandler = std::function<void(const std::string&, const std::vector<std::string>&)>;
    RdbNotifierStub(const SyncCompleteHandler&, const DataChangeHandler&);
    virtual ~RdbNotifierStub() noexcept;

    int32_t OnComplete(uint32_t seqNum, const SyncResult& result) override;
    int32_t OnChange(const std::string& storeName, const std::vector<std::string>& devices) override;

private:

    SyncCompleteHandler completeNotifier_;
    DataChangeHandler changeNotifier_;
};
} // namespace OHOS::DistributedRdb
#endif // OHOS_DISTRIBUTED_DATA_KV_STORE_FRAMEWORKS_INNERKITSIMPL_RDB_RDB_NOTIFIER_STUB_H
