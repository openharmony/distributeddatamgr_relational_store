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

#ifndef NATIVE_RDB_SQLITE_CONNECTION_H
#define NATIVE_RDB_SQLITE_CONNECTION_H

#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <vector>

#include "connection.h"
#include "rdb_common.h"
#include "rdb_local_db_observer.h"
#include "rdb_store_config.h"
#include "sqlite3sym.h"
#include "sqlite_statement.h"
#include "value_object.h"

typedef struct ClientChangedData ClientChangedData;
namespace OHOS {
namespace NativeRdb {
/**
 * @brief Use DataChangeCallback replace std::function<void(ClientChangedData &clientChangedData)>.
 */
using DataChangeCallback = std::function<void(ClientChangedData &clientChangedData)>;

class SqliteConnection : public Connection {
public:
    static std::pair<int32_t, std::shared_ptr<Connection>> Create(const RdbStoreConfig &config, bool isWrite);
    static int32_t Delete(const RdbStoreConfig &config);
    static int32_t Repair(const RdbStoreConfig &config);
    SqliteConnection(const RdbStoreConfig &config, bool isWriteConnection);
    ~SqliteConnection();
    int32_t OnInitialize() override;
    int TryCheckPoint() override;
    int LimitWalSize() override;
    int ConfigLocale(const std::string &localeStr) override;
    int CleanDirtyData(const std::string &table, uint64_t cursor) override;
    int ReSetKey(const RdbStoreConfig &config) override;
    int32_t GetJournalMode() override;
    std::pair<int32_t, Stmt> CreateStatement(const std::string &sql, SConn conn) override;
    bool IsWriter() const override;
    int SubscribeTableChanges(const Notifier &notifier) override;
    int GetMaxVariable() const override;
    int32_t GetDBType() const override;
    int32_t ClearCache() override;
    int32_t Subscribe(const std::string &event,
        const std::shared_ptr<DistributedRdb::RdbStoreObserver> &observer) override;
    int32_t Unsubscribe(const std::string &event,
        const std::shared_ptr<DistributedRdb::RdbStoreObserver> &observer) override;
    int32_t Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
        bool isAsync = false) override;
    int32_t Restore(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey) override;
    int32_t InterruptBackup() override;
    int32_t GetBackupStatus() const override;
    std::pair<bool, bool> IsExchange(const RdbStoreConfig &config) override;

protected:
    std::pair<int32_t, ValueObject> ExecuteForValue(const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());

private:
    static constexpr const char *MERGE_ASSETS_FUNC = "merge_assets";
    static constexpr const char *MERGE_ASSET_FUNC = "merge_asset";
    int InnerOpen(const RdbStoreConfig &config);
    int Configure(const RdbStoreConfig &config, std::string &dbPath);
    int SetPageSize(const RdbStoreConfig &config);
    int SetEncrypt(const RdbStoreConfig &config);
    int SetEncryptKey(const std::vector<uint8_t> &key, int32_t iter);
    int SetServiceKey(const RdbStoreConfig &config, int32_t errCode);
    int SetEncryptAgo(int32_t iter);
    int SetJournalMode(const RdbStoreConfig &config);
    int SetJournalSizeLimit(const RdbStoreConfig &config);
    int SetAutoCheckpoint(const RdbStoreConfig &config);
    int SetWalSyncMode(const std::string &syncMode);
    void LimitPermission(const std::string &dbPath) const;

    int SetPersistWal();
    int SetBusyTimeout(int timeout);

    int RegDefaultFunctions(sqlite3 *dbHandle);
    static void MergeAssets(sqlite3_context *ctx, int argc, sqlite3_value **argv);
    static void MergeAsset(sqlite3_context *ctx, int argc, sqlite3_value **argv);
    static void CompAssets(std::map<std::string, ValueObject::Asset> &oldAssets,
        std::map<std::string, ValueObject::Asset> &newAssets);
    static void MergeAsset(ValueObject::Asset &oldAsset, ValueObject::Asset &newAsset);

    int SetCustomFunctions(const RdbStoreConfig &config);
    int SetCustomScalarFunction(const std::string &functionName, int argc, ScalarFunction *function);
    int32_t UnsubscribeLocalDetail(const std::string &event,
        const std::shared_ptr<DistributedRdb::RdbStoreObserver> &observer);
    int32_t UnsubscribeLocalDetailAll(const std::string &event);
    int32_t OpenDatabase(const std::string &dbPath, int openFileFlags);
    void ReadFile2Buffer();
    int LoadExtension(const RdbStoreConfig &config, sqlite3 *dbHandle);
    RdbStoreConfig GetSlaveRdbStoreConfig(const RdbStoreConfig rdbConfig);
    void ReportDbCorruptedEvent(int errCode, const std::string &checkResultInfo);
    int CreateSlaveConnection(const RdbStoreConfig &config, bool isWrite, bool checkSlaveExist = false);
    int MasterSlaveExchange(bool isRestore = false);
    bool IsRepairable();
    std::pair<bool, int> ExchangeVerify(bool isRestore);

    static constexpr int DEFAULT_BUSY_TIMEOUT_MS = 2000;
    static constexpr int BACKUP_PAGES_PRE_STEP = 12800; // 1024 * 4 * 12800 == 50m
    static constexpr uint32_t NO_ITER = 0;
    static const int32_t regCreator_;
    static const int32_t regRepairer_;
    static const int32_t regDeleter_;

    sqlite3 *dbHandle_;
    bool isWriter_;
    bool isReadOnly_;
    bool isConfigured_ = false;
    bool hasClientObserver_ = false;
    JournalMode mode_ = JournalMode::MODE_WAL;
    int maxVariableNumber_;
    std::mutex mutex_;
    std::string filePath;
    std::shared_ptr<SqliteConnection> slaveConnection_;
    std::map<std::string, ScalarFunctionInfo> customScalarFunctions_;
    std::map<std::string, std::list<std::shared_ptr<RdbStoreLocalDbObserver>>> observers_;
    const RdbStoreConfig config_;
    std::atomic<SlaveStatus> slaveStatus_ = SlaveStatus::UNDEFINED;
};
} // namespace NativeRdb
} // namespace OHOS
#endif
