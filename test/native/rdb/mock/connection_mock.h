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

#ifndef OHOS_CONNECTION_MOCK_H
#define OHOS_CONNECTION_MOCK_H

#include "connection.h"

namespace DistributedDB {
class StoreObserver;
}
namespace OHOS::NativeRdb {
class RdbStoreConfig;
class Statement;
class MockConnection : public Connection {
public:
    MOCK_METHOD(int32_t, VerifyAndRegisterHook, (const RdbStoreConfig &config), (override));
    MOCK_METHOD((std::pair<int32_t, Stmt>), CreateStatement, (const std::string &sql, SConn conn), (override));
    MOCK_METHOD(int32_t, GetDBType, (), (const, override));
    MOCK_METHOD(bool, IsWriter, (), (const, override));
    MOCK_METHOD(int32_t, ReSetKey, (const RdbStoreConfig &config), (override));
    MOCK_METHOD(int32_t, TryCheckPoint, (bool timeout), (override));
    MOCK_METHOD(int32_t, LimitWalSize, (), (override));
    MOCK_METHOD(int32_t, ConfigLocale, (const std::string &localeStr), (override));
    MOCK_METHOD(int32_t, CleanDirtyData, (const std::string &table, uint64_t cursor), (override));
    MOCK_METHOD(int32_t, SubscribeTableChanges, (const Notifier &notifier), (override));
    MOCK_METHOD(int32_t, GetMaxVariable, (), (const, override));
    MOCK_METHOD(int32_t, GetJournalMode, (), (override));
    MOCK_METHOD(int32_t, ClearCache, (), (override));
    MOCK_METHOD(int32_t, Subscribe, (const std::shared_ptr<DistributedDB::StoreObserver> &observer), (override));
    MOCK_METHOD(int32_t, Unsubscribe, (const std::shared_ptr<DistributedDB::StoreObserver> &observer), (override));
    MOCK_METHOD(int32_t, Backup,
        (const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, bool isAsync,
            SlaveStatus &slaveStatus),
        (override));
    MOCK_METHOD(int32_t, Restore,
        (const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, SlaveStatus &slaveStatus),
        (override));
    MOCK_METHOD(ExchangeStrategy, GenerateExchangeStrategy, (const SlaveStatus &status), (override));
    MOCK_METHOD(int, SetKnowledgeSchema, (const DistributedRdb::RdbKnowledgeSchema &schema), (override));
    MOCK_METHOD(int, CleanDirtyLog, (const std::string &table, uint64_t cursor), (override));
};
} // namespace OHOS::NativeRdb
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_CONNECTION_H
