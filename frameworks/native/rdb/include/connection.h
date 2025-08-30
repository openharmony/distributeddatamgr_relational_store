/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_CONNECTION_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_CONNECTION_H
#include <cstdint>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include "knowledge_types.h"
#include "rdb_common.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "statement.h"

namespace DistributedDB {
class StoreObserver;
}
namespace OHOS::NativeRdb {
class RdbStoreConfig;
class Statement;
class Connection {
public:
    using Info = DistributedRdb::RdbDebugInfo;
    using SConn = std::shared_ptr<Connection>;
    using Stmt = std::shared_ptr<Statement>;
    using Notifier = std::function<void(const DistributedRdb::RdbChangedData &rdbChangedData)>;
    using Creator = std::pair<int32_t, SConn> (*)(const RdbStoreConfig &config, bool isWriter);
    using Repairer = int32_t (*)(const RdbStoreConfig &config);
    using Deleter = int32_t (*)(const RdbStoreConfig &config);
    using Collector = std::map<std::string, Info> (*)(const RdbStoreConfig &config);
    using GetDbFileser = std::vector<std::string> (*)(const RdbStoreConfig &config);
    using ReplicaChecker = int32_t (*)(const RdbStoreConfig &config);
    static std::pair<int32_t, SConn> Create(const RdbStoreConfig &config, bool isWriter);
    static int32_t Repair(const RdbStoreConfig &config);
    static int32_t Delete(const RdbStoreConfig &config);
    static std::map<std::string, Info> Collect(const RdbStoreConfig &config);
    static std::vector<std::string> GetDbFiles(const RdbStoreConfig &config);
    static int32_t CheckReplicaIntegrity(const RdbStoreConfig &config);
    static int32_t RegisterCreator(int32_t dbType, Creator creator);
    static int32_t RegisterRepairer(int32_t dbType, Repairer repairer);
    static int32_t RegisterDeleter(int32_t dbType, Deleter deleter);
    static int32_t RegisterCollector(int32_t dbType, Collector collector);
    static int32_t RegisterGetDbFileser(int32_t dbType, GetDbFileser getDbFileser);
    static int32_t RegisterReplicaChecker(int32_t dbType, ReplicaChecker replicaChecker);

    int32_t SetId(int32_t id);
    int32_t GetId() const;
    void SetIsRecyclable(bool recyclable);
    bool IsRecyclable() const;
    virtual ~Connection() = default;
    virtual int32_t VerifyAndRegisterHook(const RdbStoreConfig &config) = 0;
    virtual std::pair<int32_t, Stmt> CreateStatement(const std::string &sql, SConn conn) = 0;
    virtual std::pair<int32_t, Stmt> CreateReplicaStatement(const std::string &sql, SConn conn) = 0;
    virtual int CheckReplicaForRestore() = 0;
    virtual int32_t Rekey(const RdbStoreConfig::CryptoParam &cryptoParam) = 0;
    virtual int32_t GetDBType() const = 0;
    virtual bool IsWriter() const = 0;
    virtual int32_t ResetKey(const RdbStoreConfig &config) = 0;
    virtual int32_t TryCheckPoint(bool timeout) = 0;
    virtual int32_t LimitWalSize() = 0;
    virtual int32_t ConfigLocale(const std::string &localeStr) = 0;
    virtual int32_t CleanDirtyData(const std::string &table, uint64_t cursor) = 0;
    virtual int32_t SubscribeTableChanges(const Notifier &notifier) = 0;
    virtual int32_t GetMaxVariable() const = 0;
    virtual int32_t GetJournalMode() = 0;
    virtual int32_t ClearCache(bool isForceClear = false) = 0;
    virtual int32_t Subscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer) = 0;
    virtual int32_t Unsubscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer) = 0;
    virtual int32_t Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, bool isAsync,
        std::shared_ptr<SlaveStatus> slaveStatus, bool verifyDb = true) = 0;
    virtual int32_t Restore(
        const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
        std::shared_ptr<SlaveStatus> slaveStatus) = 0;
    virtual ExchangeStrategy GenerateExchangeStrategy(std::shared_ptr<SlaveStatus> status, bool isRelpay = true) = 0;
    virtual int SetKnowledgeSchema(const DistributedRdb::RdbKnowledgeSchema &schema) = 0;
    virtual int CleanDirtyLog(const std::string &table, uint64_t cursor) = 0;
    virtual int RegisterAlgo(const std::string &clstAlgoName, ClusterAlgoFunc func) = 0;

private:
    int32_t id_ = 0;
    bool isRecyclable_ = true;
};
} // namespace OHOS::NativeRdb
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_INCLUDE_CONNECTION_H
