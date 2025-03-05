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
    static int32_t Delete(const std::string &path);
    static int32_t Repair(const RdbStoreConfig &config);
    static int32_t Restore(const RdbStoreConfig &config, const std::string &srcPath, const std::string &destPath);
    static std::map<std::string, Info> Collect(const RdbStoreConfig &config);
    SqliteConnection(const RdbStoreConfig &config, bool isWriteConnection);
    ~SqliteConnection();
    int32_t VerifyAndRegisterHook(const RdbStoreConfig &config) override;
    int TryCheckPoint(bool timeout) override;
    int LimitWalSize() override;
    int ConfigLocale(const std::string &localeStr) override;
    int CleanDirtyData(const std::string &table, uint64_t cursor) override;
    int ReSetKey(const RdbStoreConfig &config) override;
    int32_t GetJournalMode() override;
    std::pair<int32_t, Stmt> CreateStatement(const std::string &sql, SConn conn) override;
    bool IsWriter() const override;
    bool IsInTrans() const override;
    int SubscribeTableChanges(const Notifier &notifier) override;
    int GetMaxVariable() const override;
    int32_t GetDBType() const override;
    int32_t ClearCache() override;
    int32_t Subscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer) override;
    int32_t Unsubscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer) override;
    int32_t Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, bool isAsync,
        SlaveStatus &slaveStatus) override;
    int32_t Restore(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
        SlaveStatus &slaveStatus) override;
    ExchangeStrategy GenerateExchangeStrategy(const SlaveStatus &status) override;

protected:
    std::pair<int32_t, ValueObject> ExecuteForValue(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());

private:
    struct Suffix {
        const char *suffix_ = nullptr;
        const char *debug_ = nullptr;
    };

    enum SlaveOpenPolicy : int32_t {
        FORCE_OPEN = 0,
        OPEN_IF_DB_VALID // DB exists and there are no -slaveFailure and -syncInterrupt files
    };

    int InnerOpen(const RdbStoreConfig &config);
    int Configure(const RdbStoreConfig &config, std::string &dbPath);
    int SetPageSize(const RdbStoreConfig &config);
    int SetEncrypt(const RdbStoreConfig &config);
    int SetEncryptKey(const std::vector<uint8_t> &key, const RdbStoreConfig &config);
    int SetServiceKey(const RdbStoreConfig &config, int32_t errCode);
    int SetEncryptAgo(const RdbStoreConfig &config);
    int SetJournalMode(const RdbStoreConfig &config);
    int SetJournalSizeLimit(const RdbStoreConfig &config);
    int SetAutoCheckpoint(const RdbStoreConfig &config);
    int SetWalFile(const RdbStoreConfig &config);
    int SetWalSyncMode(const std::string &syncMode);
    int SetTokenizer(const RdbStoreConfig &config);
    void LimitPermission(const RdbStoreConfig &config, const std::string &dbPath) const;

    int SetPersistWal(const RdbStoreConfig &config);
    int SetBusyTimeout(int timeout);
    int SetCrcCheck(const RdbStoreConfig &config);
    void SetDwrEnable(const RdbStoreConfig &config);

    int RegDefaultFunctions(sqlite3 *dbHandle);
    int SetCustomFunctions(const RdbStoreConfig &config);
    int SetCustomScalarFunction(const std::string &functionName, int argc, ScalarFunction *function);
    int32_t UnsubscribeLocalDetail(
        const std::string &event, const std::shared_ptr<DistributedRdb::RdbStoreObserver> &observer);
    int32_t UnsubscribeLocalDetailAll(const std::string &event);
    int32_t OpenDatabase(const std::string &dbPath, int openFileFlags);
    int LoadExtension(const RdbStoreConfig &config, sqlite3 *dbHandle);
    RdbStoreConfig GetSlaveRdbStoreConfig(const RdbStoreConfig &rdbConfig);
    std::pair<int32_t, std::shared_ptr<SqliteConnection>> CreateSlaveConnection(
        const RdbStoreConfig &config, SlaveOpenPolicy slaveOpenPolicy);
    int ExchangeSlaverToMaster(bool isRestore, bool verifyDb, SlaveStatus &status);
    int ExchangeVerify(bool isRestore);
    int SqliteNativeBackup(bool isRestore, SlaveStatus &curStatus);
    int VeritySlaveIntegrity();
    bool IsDbVersionBelowSlave();
    int RegisterStoreObs();
    int RegisterClientObs();
    int RegisterHookIfNecessary();
    static std::pair<int32_t, std::shared_ptr<SqliteConnection>> InnerCreate(
        const RdbStoreConfig &config, bool isWrite);
    static int CopyDb(const RdbStoreConfig &config, const std::string &srcPath, const std::string &destPath);
    static constexpr SqliteConnection::Suffix FILE_SUFFIXES[] = { { "", "DB" }, { "-shm", "SHM" }, { "-wal", "WAL" },
        { "-dwr", "DWR" }, { "-journal", "JOURNAL" }, { "-slaveFailure", nullptr }, { "-syncInterrupt", nullptr },
        { ".corruptedflg", nullptr }, { "-compare", nullptr } };
    static constexpr int CHECKPOINT_TIME = 500;
    static constexpr int DEFAULT_BUSY_TIMEOUT_MS = 2000;
    static constexpr int BACKUP_PAGES_PRE_STEP = 12800; // 1024 * 4 * 12800 == 50m
    static constexpr int BACKUP_PRE_WAIT_TIME = 10;
    static constexpr ssize_t SLAVE_WAL_SIZE_LIMIT = 2147483647;       // 2147483647 = 2g - 1
    static constexpr ssize_t SLAVE_INTEGRITY_CHECK_LIMIT = 524288000; // 524288000 == 1024 * 1024 * 500
    static constexpr uint32_t NO_ITER = 0;
    static constexpr uint32_t DB_INDEX = 0;
    static constexpr uint32_t WAL_INDEX = 2;
    static constexpr uint32_t ITER_V1 = 5000;
    static constexpr uint32_t SQLITE_CKSUMVFS_RESERVE_BYTES = 8;
    static const int32_t regCreator_;
    static const int32_t regRepairer_;
    static const int32_t regDeleter_;
    static const int32_t regCollector_;
    static const int32_t regRestorer_;
    using EventHandle = int (SqliteConnection::*)();
    struct HandleInfo {
        RegisterType Type;
        EventHandle handle;
    };
    static constexpr HandleInfo onEventHandlers_[RegisterType::OBSERVER_END] = {
        { RegisterType::STORE_OBSERVER, &SqliteConnection::RegisterStoreObs },
        { RegisterType::CLIENT_OBSERVER, &SqliteConnection::RegisterClientObs },
    };

    std::atomic<uint64_t> backupId_;
    sqlite3 *dbHandle_;
    bool isWriter_;
    bool isReadOnly_;
    bool isConfigured_ = false;
    JournalMode mode_ = JournalMode::MODE_WAL;
    int maxVariableNumber_;
    std::shared_ptr<SqliteConnection> slaveConnection_;
    std::map<std::string, ScalarFunctionInfo> customScalarFunctions_;
    const RdbStoreConfig config_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif