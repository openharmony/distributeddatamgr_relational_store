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

#ifndef DISTRIBUTED_RDB_RDB_SERVICE_MOCK_H
#define DISTRIBUTED_RDB_RDB_SERVICE_MOCK_H

#include <gmock/gmock.h>

#include "iremote_object.h"
#include "rdb_service.h"

namespace OHOS {
namespace DistributedRdb {
class MockRdbService : public RdbService {
public:
    MOCK_METHOD(
        std::string, ObtainDistributedTableName, (const std::string &device, const std::string &table), (override));
    MOCK_METHOD(int32_t, SetDistributedTables,
        (const RdbSyncerParam &param, const std::vector<std::string> &tables, const std::vector<Reference> &references,
            bool isRebuild, int32_t type),
        (override));
    MOCK_METHOD(int32_t, Sync,
        (const RdbSyncerParam &param, const Option &option, const PredicatesMemo &predicates, const AsyncDetail &async),
        (override));
    MOCK_METHOD(int32_t, Subscribe,
        (const RdbSyncerParam &param, const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer),
        (override));
    MOCK_METHOD(int32_t, UnSubscribe,
        (const RdbSyncerParam &param, const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer),
        (override));
    MOCK_METHOD(int32_t, RegisterAutoSyncCallback,
        (const RdbSyncerParam &param, std::shared_ptr<DetailProgressObserver> observer), (override));
    MOCK_METHOD(int32_t, UnregisterAutoSyncCallback,
        (const RdbSyncerParam &param, std::shared_ptr<DetailProgressObserver> observer), (override));
    MOCK_METHOD((std::pair<int32_t, std::shared_ptr<ResultSet>>), RemoteQuery,
        (const RdbSyncerParam &param, const std::string &device, const std::string &sql,
            const std::vector<std::string> &selectionArgs),
        (override));
    MOCK_METHOD(int32_t, InitNotifier, (const RdbSyncerParam &param, sptr<IRemoteObject> notifier), (override));

    MOCK_METHOD(int32_t, BeforeOpen, (RdbSyncerParam & param), (override));

    MOCK_METHOD(int32_t, AfterOpen, (const RdbSyncerParam &param), (override));

    MOCK_METHOD(int32_t, Delete, (const RdbSyncerParam &param), (override));

    MOCK_METHOD((std::pair<int32_t, std::shared_ptr<ResultSet>>), QuerySharingResource,
        (const RdbSyncerParam &param, const PredicatesMemo &predicates, const std::vector<std::string> &columns),
        (override));

    MOCK_METHOD(int32_t, NotifyDataChange,
        (const RdbSyncerParam &param, const RdbChangedData &rdbChangedData, const RdbNotifyConfig &rdbNotifyConfig),
        (override));

    MOCK_METHOD(int32_t, SetSearchable, (const RdbSyncerParam &param, bool isSearchable), (override));

    MOCK_METHOD(int32_t, Disable, (const RdbSyncerParam &param), (override));

    MOCK_METHOD(int32_t, Enable, (const RdbSyncerParam &param), (override));

    MOCK_METHOD(
        int32_t, GetPassword, (const RdbSyncerParam &param, std::vector<std::vector<uint8_t>> &password), (override));

    MOCK_METHOD((std::pair<int32_t, uint32_t>), LockCloudContainer, (const RdbSyncerParam &param), (override));

    MOCK_METHOD(int32_t, UnlockCloudContainer, (const RdbSyncerParam &param), (override));

    MOCK_METHOD(int32_t, GetDebugInfo,
        (const RdbSyncerParam &param, (std::map<std::string, RdbDebugInfo> & debugInfo)), (override));

    MOCK_METHOD(int32_t, GetDfxInfo, (const RdbSyncerParam &param, RdbDfxInfo &dfxInfo), (override));

    MOCK_METHOD(int32_t, VerifyPromiseInfo, (const RdbSyncerParam &param), (override));

    MOCK_METHOD(int32_t, ReportStatistic, (const RdbSyncerParam &param, const RdbStatEvent &statEvent), (override));
};
} // namespace DistributedRdb
} // namespace OHOS
#endif