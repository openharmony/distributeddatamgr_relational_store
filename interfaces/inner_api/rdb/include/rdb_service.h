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

#ifndef DISTRIBUTED_RDB_RDB_SERVICE_H
#define DISTRIBUTED_RDB_RDB_SERVICE_H

#include <memory>
#include <string>

#include "distributeddata_relational_store_ipc_interface_code.h"
#include "iremote_object.h"
#include "rdb_notifier.h"
#include "rdb_types.h"
#include "result_set.h"

namespace OHOS {
namespace DistributedRdb {
class RdbService {
public:
    struct Option {
        int32_t mode;
        uint32_t seqNum = 0;
        bool isAsync = false;
        bool isAutoSync = false;
        bool isCompensation = false;
    };
    using ResultSet = NativeRdb::ResultSet;
    inline static constexpr const char *SERVICE_NAME = "relational_store";

    virtual std::string ObtainDistributedTableName(
        const RdbSyncerParam &param, const std::string &device, const std::string &table) = 0;

    virtual int32_t SetDistributedTables(const RdbSyncerParam &param, const std::vector<std::string> &tables,
        const std::vector<Reference> &references, bool isRebuild, int32_t type = DISTRIBUTED_DEVICE) = 0;

    virtual int32_t Sync(const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates,
        const AsyncDetail &async) = 0;

    virtual int32_t Subscribe(
        const RdbSyncerParam &param, const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer) = 0;

    virtual int32_t UnSubscribe(
        const RdbSyncerParam &param, const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer) = 0;

    virtual int32_t RegisterAutoSyncCallback(
        const RdbSyncerParam &param, std::shared_ptr<DetailProgressObserver> observer) = 0;

    virtual int32_t UnregisterAutoSyncCallback(
        const RdbSyncerParam &param, std::shared_ptr<DetailProgressObserver> observer) = 0;

    virtual std::pair<int32_t, std::shared_ptr<ResultSet>> RemoteQuery(const RdbSyncerParam &param,
        const std::string &device, const std::string &sql, const std::vector<std::string> &selectionArgs) = 0;

    virtual int32_t InitNotifier(const RdbSyncerParam &param, sptr<IRemoteObject> notifier) = 0;

    virtual int32_t BeforeOpen(RdbSyncerParam &param) = 0;

    virtual int32_t AfterOpen(const RdbSyncerParam &param) = 0;

    // only use param.storeName_
    virtual int32_t Delete(const RdbSyncerParam &param) = 0;

    virtual std::pair<int32_t, std::shared_ptr<ResultSet>> QuerySharingResource(
        const RdbSyncerParam &param, const PredicatesMemo &predicates, const std::vector<std::string> &columns) = 0;

    virtual int32_t NotifyDataChange(
        const RdbSyncerParam &param, const RdbChangedData &rdbChangedData, const RdbNotifyConfig &rdbNotifyConfig) = 0;

    virtual int32_t SetSearchable(const RdbSyncerParam &param, bool isSearchable) = 0;

    virtual int32_t Disable(const RdbSyncerParam &param) = 0;

    virtual int32_t Enable(const RdbSyncerParam &param) = 0;

    virtual int32_t GetPassword(const RdbSyncerParam &param, std::vector<std::vector<uint8_t>> &password) = 0;

    virtual std::pair<int32_t, uint32_t> LockCloudContainer(const RdbSyncerParam &param) = 0;

    virtual int32_t UnlockCloudContainer(const RdbSyncerParam &param) = 0;

    virtual int32_t GetDebugInfo(const RdbSyncerParam &param, std::map<std::string, RdbDebugInfo> &debugInfo) = 0;

    virtual int32_t GetDfxInfo(const RdbSyncerParam &param, DistributedRdb::RdbDfxInfo &dfxInfo) = 0;

    virtual int32_t VerifyPromiseInfo(const RdbSyncerParam &param) = 0;

    virtual int32_t ReportStatistic(const RdbSyncerParam &param, const RdbStatEvent &statEvent) = 0;

    virtual ~RdbService() = default;
};
} // namespace DistributedRdb
} // namespace OHOS
#endif