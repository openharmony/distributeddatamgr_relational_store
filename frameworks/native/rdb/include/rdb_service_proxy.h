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

#include <iremote_proxy.h>

#include <atomic>
#include <list>
#include <memory>

#include "concurrent_map.h"
#include "irdb_service.h"
#include "rdb_notifier_stub.h"

namespace OHOS::DistributedRdb {
class RdbServiceProxy : public IRemoteProxy<IRdbService> {
public:
    struct ObserverParam {
        std::weak_ptr<RdbStoreObserver> observer;
        std::string bundleName;
        SubscribeOption subscribeOption{ SubscribeMode::REMOTE };
    };
    using Observers = ConcurrentMap<std::string, std::list<ObserverParam>>;
    struct SyncObserverParam {
        std::shared_ptr<DetailProgressObserver> syncObserver = nullptr;
        std::string bundleName;
    };
    using SyncObservers = ConcurrentMap<std::string, std::list<SyncObserverParam>>;
    explicit RdbServiceProxy(const sptr<IRemoteObject> &object);
    ~RdbServiceProxy();

    std::string ObtainDistributedTableName(
        const RdbSyncerParam &param, const std::string &device, const std::string &table) override;

    int32_t InitNotifier(const RdbSyncerParam &param);

    int32_t InitNotifier(const RdbSyncerParam &param, sptr<IRemoteObject> notifier) override;

    int32_t SetDistributedTables(const RdbSyncerParam &param, const std::vector<std::string> &tables,
        const std::vector<Reference> &references, bool isRebuild, int32_t type = DISTRIBUTED_DEVICE) override;

    int32_t Sync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates,
        const AsyncDetail &async) override;

    int32_t Subscribe(const RdbSyncerParam &param, const SubscribeOption &option,
        std::shared_ptr<RdbStoreObserver> observer) override;

    int32_t UnSubscribe(const RdbSyncerParam &param, const SubscribeOption &option,
        std::shared_ptr<RdbStoreObserver> observer) override;

    int32_t RegisterAutoSyncCallback(
        const RdbSyncerParam &param, std::shared_ptr<DetailProgressObserver> observer) override;

    int32_t UnregisterAutoSyncCallback(
        const RdbSyncerParam &param, std::shared_ptr<DetailProgressObserver> observer) override;

    std::pair<int32_t, std::shared_ptr<ResultSet>> RemoteQuery(const RdbSyncerParam &param, const std::string &device,
        const std::string &sql, const std::vector<std::string> &selectionArgs) override;

    Observers ExportObservers();

    void ImportObservers(Observers &observers);

    int32_t BeforeOpen(RdbSyncerParam &param) override;
    
    std::pair<int32_t, bool> IsSupportSilent(const RdbSyncerParam &param) override;

    int32_t AfterOpen(const RdbSyncerParam &param) override;

    int32_t ReportStatistic(const RdbSyncerParam &param, const RdbStatEvent &statEvent) override;

    int32_t Delete(const RdbSyncerParam &param) override;

    int32_t NotifyDataChange(const RdbSyncerParam &param, const RdbChangedData &clientChangedData,
        const RdbNotifyConfig &rdbNotifyConfig) override;

    int32_t SetSearchable(const RdbSyncerParam &param, bool isSearchable) override;

    std::pair<int32_t, std::shared_ptr<ResultSet>> QuerySharingResource(const RdbSyncerParam &param,
        const PredicatesMemo &predicates, const std::vector<std::string> &columns) override;
    int32_t Disable(const RdbSyncerParam &param) override;
    int32_t Enable(const RdbSyncerParam &param) override;
    int32_t GetPassword(const RdbSyncerParam &param, std::vector<std::vector<uint8_t>> &key) override;

    std::pair<int32_t, uint32_t> LockCloudContainer(const RdbSyncerParam &param) override;

    int32_t UnlockCloudContainer(const RdbSyncerParam &param) override;

    int32_t GetDebugInfo(const RdbSyncerParam &param, std::map<std::string, RdbDebugInfo> &debugInfo) override;

    int32_t GetDfxInfo(const RdbSyncerParam &param, DistributedRdb::RdbDfxInfo &dfxInfo) override;

    int32_t VerifyPromiseInfo(const RdbSyncerParam &param) override;
    SyncObservers ExportSyncObservers();
    void ImportSyncObservers(SyncObservers &SyncObservers);
    void OnRemoteDeadSyncComplete();
    int32_t StopCloudSync(const RdbSyncerParam &param) override;

private:
    using ChangeInfo = RdbStoreObserver::ChangeInfo;
    using PrimaryFields = RdbStoreObserver::PrimaryFields;
    using SyncCallbacks = ConcurrentMap<uint32_t, AsyncDetail>;
    std::pair<int32_t, Details> DoSync(
        const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates);

    int32_t DoAsync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates);

    int32_t DoSync(
        const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates, const AsyncDetail &async);

    int32_t DoAsync(
        const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates, const AsyncDetail &async);

    int32_t DoSubscribe(const RdbSyncerParam &param, const SubscribeOption &option);

    int32_t DoUnSubscribe(const RdbSyncerParam &param, const SubscribeOption &option);

    int32_t DoRegister(const RdbSyncerParam &param);

    int32_t DoUnRegister(const RdbSyncerParam &param);

    uint32_t GetSeqNum();

    void OnSyncComplete(uint32_t seqNum, Details &&result);

    void OnSyncComplete(const std::string &storeName, Details &&result);

    void OnDataChange(const Origin &origin, const PrimaryFields &primaries, ChangeInfo &&changeInfo);

    void OnSyncTrigger(const std::string &storeId, const int32_t triggerMode);

    std::atomic<uint32_t> seqNum_{};
    Observers observers_;
    SyncCallbacks syncCallbacks_;
    SyncObservers syncObservers_;
    sptr<RdbNotifierStub> notifier_;

    sptr<IRemoteObject> remote_;
    static inline BrokerDelegator<RdbServiceProxy> delegator_;
};
} // namespace OHOS::DistributedRdb
#endif