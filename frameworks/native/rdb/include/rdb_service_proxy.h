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

#ifndef DISTRIBUTED_RDB_RDB_SERVICE_PROXY_H
#define DISTRIBUTED_RDB_RDB_SERVICE_PROXY_H

#include <atomic>
#include <list>
#include <iremote_proxy.h>
#include "irdb_service.h"
#include "rdb_notifier_stub.h"
#include "concurrent_map.h"

namespace OHOS::DistributedRdb {
class RdbServiceProxy : public IRemoteProxy<IRdbService> {
public:
    using ObserverMapValue = std::pair<std::list<RdbStoreObserver*>, RdbSyncerParam>;
    using ObserverMap = ConcurrentMap<std::string, ObserverMapValue>;

    explicit RdbServiceProxy(const sptr<IRemoteObject>& object);

    std::string ObtainDistributedTableName(const std::string& device, const std::string& table) override;

    int32_t InitNotifier(const RdbSyncerParam &param);

    int32_t InitNotifier(const RdbSyncerParam &param, sptr<IRemoteObject> notifier) override;

    int32_t SetDistributedTables(const RdbSyncerParam &param, const std::vector<std::string> &tables,
        int32_t type = DISTRIBUTED_DEVICE) override;

    int32_t Sync(const RdbSyncerParam& param, const Option& option,
                 const PredicatesMemo& predicates, const AsyncDetail &async) override;

    int32_t Subscribe(const RdbSyncerParam& param, const SubscribeOption& option,
                      RdbStoreObserver *observer) override;

    int32_t UnSubscribe(const RdbSyncerParam& param, const SubscribeOption& option,
                        RdbStoreObserver *observer) override;
    int32_t RemoteQuery(const RdbSyncerParam& param, const std::string& device, const std::string& sql,
                        const std::vector<std::string>& selectionArgs, sptr<IRemoteObject>& resultSet) override;

    ObserverMap ExportObservers();

    void ImportObservers(ObserverMap& observers);

    int32_t GetSchema(const RdbSyncerParam &param) override;
private:
    using ChangeInfo = RdbStoreObserver::ChangeInfo;
    using PrimaryFields = RdbStoreObserver::PrimaryFields;
    std::pair<int32_t, Details> DoSync(const RdbSyncerParam &param, const Option &option,
        const PredicatesMemo &predicates);

    int32_t DoAsync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates);

    int32_t DoSync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates,
        const AsyncDetail &async);

    int32_t DoAsync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates,
        const AsyncDetail &async);

    int32_t DoSubscribe(const RdbSyncerParam& param, const SubscribeOption &option);

    int32_t DoUnSubscribe(const RdbSyncerParam& param);

    uint32_t GetSeqNum();

    void OnSyncComplete(uint32_t seqNum, Details &&result);

    void OnDataChange(const Origin &origin, const PrimaryFields &primaries, ChangeInfo &&changeInfo);

    std::string RemoveSuffix(const std::string& name);

    std::atomic<uint32_t> seqNum_ {};

    ConcurrentMap<uint32_t, AsyncDetail> syncCallbacks_;
    ObserverMap observers_;
    sptr<RdbNotifierStub> notifier_;

    sptr<IRemoteObject> remote_;
    static inline BrokerDelegator<RdbServiceProxy> delegator_;
};
} // namespace OHOS::DistributedRdb
#endif
