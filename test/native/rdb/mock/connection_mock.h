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
    using Info = DistributedRdb::RdbDebugInfo;
    using SConn = std::shared_ptr<Connection>;
    using Stmt = std::shared_ptr<Statement>;
    using Notifier = std::function<void(const DistributedRdb::RdbChangedData &rdbChangedData)>;
    using Creator = std::pair<int32_t, SConn> (*)(const RdbStoreConfig &config, bool isWriter);
    using Repairer = int32_t (*)(const RdbStoreConfig &config);
    using Deleter = int32_t (*)(const RdbStoreConfig &config);
    using Collector = std::map<std::string, Info> (*)(const RdbStoreConfig &config);
    using Restorer = int32_t (*)(const RdbStoreConfig &config, const std::string &srcPath, const std::string &destPath);
    using ReplicaChecker = int32_t (*)(const RdbStoreConfig &config);
    using ReplayCallBack = std::function<void(void)>;

    MOCK_METHOD(int32_t, VerifyAndRegisterHook, (const RdbStoreConfig &config), (override));
    MOCK_METHOD((std::pair<int32_t, Stmt>), CreateStatement, (const std::string &sql, SConn conn), (override));
    MOCK_METHOD((std::pair<int32_t, Stmt>), CreateReplicaStatement,
        (const std::string &sql, SConn conn), (override));
    MOCK_METHOD(int, CheckReplicaForRestore, (), (override));
    MOCK_METHOD(int32_t, Rekey, (const RdbStoreConfig::CryptoParam &cryptoParam), (override));
    MOCK_METHOD(int32_t, GetDBType, (), (const, override));
    MOCK_METHOD(bool, IsWriter, (), (const, override));
    MOCK_METHOD(int32_t, ResetKey, (const RdbStoreConfig &config), (override));
    MOCK_METHOD(int32_t, TryCheckPoint, (bool timeout), (override));
    MOCK_METHOD(int32_t, LimitWalSize, (), (override));
    MOCK_METHOD(int32_t, ConfigLocale, (const std::string &localeStr), (override));
    MOCK_METHOD(int32_t, SetTokenizer, (Tokenizer tokenizer), (override));
    MOCK_METHOD(int32_t, CleanDirtyData, (const std::string &table, uint64_t cursor), (override));
    MOCK_METHOD(int32_t, SubscribeTableChanges, (const Notifier &notifier), (override));
    MOCK_METHOD(int32_t, GetMaxVariable, (), (const, override));
    MOCK_METHOD(int32_t, GetJournalMode, (), (override));
    MOCK_METHOD(int32_t, ClearCache, (bool isForceClear), (override));
    MOCK_METHOD(int32_t, Subscribe, (const std::shared_ptr<DistributedDB::StoreObserver> &observer), (override));
    MOCK_METHOD(int32_t, Unsubscribe, (const std::shared_ptr<DistributedDB::StoreObserver> &observer), (override));
    MOCK_METHOD(int32_t, Backup,
        (const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, bool isAsync,
            std::shared_ptr<SlaveStatus> slaveStatus, bool verifyDb),
        (override));
    MOCK_METHOD(void, Interrupt, (), (override));
    MOCK_METHOD(int32_t, Restore,
        (const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
            std::shared_ptr<SlaveStatus> slaveStatus),
        (override));
    MOCK_METHOD(ExchangeStrategy, GenerateExchangeStrategy, (std::shared_ptr<SlaveStatus> status,
        bool isReplay), (override));
    MOCK_METHOD(int, SetKnowledgeSchema, (const DistributedRdb::RdbKnowledgeSchema &schema), (override));
    MOCK_METHOD(int, CleanDirtyLog, (const std::string &table, uint64_t cursor), (override));
    MOCK_METHOD(int, RegisterAlgo, (const std::string &clstAlgoName, ClusterAlgoFunc func), (override));
    MOCK_METHOD(int32_t, RegisterReplayCallback, (const RdbStoreConfig &config,
        const ReplayCallBack &replayCallback), (override));
    MOCK_METHOD(void, ReplayBinlog, (const RdbStoreConfig &config, bool chkBinlogCount), (override));
};
} // namespace OHOS::NativeRdb
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_CONNECTION_H
