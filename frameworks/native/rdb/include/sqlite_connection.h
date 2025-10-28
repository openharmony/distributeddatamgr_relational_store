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

#include "concurrent_map.h"
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
    static std::map<std::string, Info> Collect(const RdbStoreConfig &config);
    static std::vector<std::string> GetDbFiles(const RdbStoreConfig &config);
    static int32_t CheckReplicaIntegrity(const RdbStoreConfig &config);
    static int32_t ClientCleanUp();
    static int32_t OpenSSLCleanUp();
    static int32_t RekeyEx(const RdbStoreConfig &config, const RdbStoreConfig::CryptoParam &cryptoParam);
    SqliteConnection(const RdbStoreConfig &config, bool isWriteConnection, bool isSlave = false);
    ~SqliteConnection();
    int32_t VerifyAndRegisterHook(const RdbStoreConfig &config) override;
    int TryCheckPoint(bool timeout) override;
    int LimitWalSize() override;
    int ConfigLocale(const std::string &localeStr) override;
    int32_t SetTokenizer(Tokenizer tokenizer) override;
    int CleanDirtyData(const std::string &table, uint64_t cursor) override;
    int ResetKey(const RdbStoreConfig &config) override;
    int32_t Rekey(const RdbStoreConfig::CryptoParam &cryptoParam) override;
    int32_t GetJournalMode() override;
    std::pair<int32_t, Stmt> CreateStatement(const std::string &sql, SConn conn) override;
    std::pair<int32_t, Stmt> CreateReplicaStatement(const std::string &sql, SConn conn) override;
    int CheckReplicaForRestore() override;
    bool IsWriter() const override;
    int SubscribeTableChanges(const Notifier &notifier) override;
    int GetMaxVariable() const override;
    int32_t GetDBType() const override;
    int32_t ClearCache(bool isForceClear = false) override;
    int32_t Subscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer) override;
    int32_t Unsubscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer) override;
    int32_t Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, bool isAsync,
        std::shared_ptr<SlaveStatus> slaveStatus, bool verifyDb = true) override;
    int32_t Restore(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
        std::shared_ptr<SlaveStatus> slaveStatus) override;
    ExchangeStrategy GenerateExchangeStrategy(std::shared_ptr<SlaveStatus> status, bool isRelpay) override;
    int SetKnowledgeSchema(const DistributedRdb::RdbKnowledgeSchema &schema) override;
    int CleanDirtyLog(const std::string &table, uint64_t cursor) override;
    static bool IsSupportBinlog(const RdbStoreConfig &config);
protected:
    std::pair<int32_t, ValueObject> ExecuteForValue(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int RegisterAlgo(const std::string &clstAlgoName, ClusterAlgoFunc func) override;

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
    int SetEncryptAgo(const RdbStoreConfig::CryptoParam &cryptoParam);
    int SetAutoCheckpoint(const RdbStoreConfig &config);
    int SetWalFile(const RdbStoreConfig &config);
    int SetWalSyncMode(const std::string &syncMode);
    int SetTokenizer(const RdbStoreConfig &config);
    int SetBinlog();
    void LimitPermission(const RdbStoreConfig &config, const std::string &dbPath) const;

    int SetPersistWal(const RdbStoreConfig &config);
    int SetBusyTimeout(int timeout);
    void SetDwrEnable(const RdbStoreConfig &config);
    void SetIsSupportBinlog(bool isSupport);

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
    int ExchangeSlaverToMaster(bool isRestore, bool verifyDb, std::shared_ptr<SlaveStatus> curStatus);
    int ExchangeVerify(bool isRestore);
    int SqliteBackupStep(bool isRestore, sqlite3_backup *pBackup, std::shared_ptr<SlaveStatus> curStatus);
    int SqliteNativeBackup(bool isRestore, std::shared_ptr<SlaveStatus> curStatus, bool isNeedSetAcl = false);
    int VerifySlaveIntegrity();
    bool IsDbVersionBelowSlave();
    int RegisterStoreObs();
    int RegisterClientObs();
    int RegisterHookIfNecessary();
    std::pair<int32_t, Stmt> CreateStatementInner(const std::string &sql, SConn conn,
        sqlite3 *db, bool isFromReplica);
    void ReplayBinlog(const RdbStoreConfig &config);
    ExchangeStrategy CompareWithSlave(int64_t mCount, int64_t mIdxCount);
    void DeleteCorruptSlave(const std::string &path);
    static std::pair<int32_t, std::shared_ptr<SqliteConnection>> InnerCreate(
        const RdbStoreConfig &config, bool isWrite, bool isReusableReplica = false);
    static void BinlogOnErrFunc(void *pCtx, int errNo, char *errMsg, const char *dbPath);
    static void BinlogCloseHandle(sqlite3 *dbHandle);
    static int CheckPathExist(const std::string &dbPath);
    static int BinlogOpenHandle(const std::string &dbPath, sqlite3 *&dbHandle, bool isMemoryRdb);
    static void BinlogSetConfig(sqlite3 *dbHandle);
    static void BinlogOnFullFunc(void *pCtx, unsigned short currentCount, const char *dbPath);
    static int ReplayBinlogSqlite(sqlite3 *dbFrom, sqlite3 *slaveDb, const RdbStoreConfig &config);
    static void ReplayBinlog(const std::string &dbPath,
        std::shared_ptr<SqliteConnection> slaveConn, bool isNeedClean);
    static std::string GetBinlogFolderPath(const std::string &dbPath);
    static void InsertReusableReplica(const std::string &dbPath, std::weak_ptr<SqliteConnection> slaveConn);
    static std::shared_ptr<SqliteConnection> GetReusableReplica(const std::string &dbPath);
    /**
     * @brief The lifecycle of config must be shorter than that of param..
     */
    static CodecConfig ConvertCryptoParamToCodecConfig(const RdbStoreConfig::CryptoParam &param);
    static CodecConfig CreateCodecConfig();
    static constexpr const char *BINLOG_LOCK_FILE_SUFFIX = "_binlog/binlog_default.readIndex";
    static constexpr const char *BINLOG_FOLDER_SUFFIX = "_binlog";
    static constexpr SqliteConnection::Suffix FILE_SUFFIXES[] = { { "", "DB" }, { "-shm", "SHM" }, { "-wal", "WAL" },
        { "-dwr", "DWR" }, { "-journal", "JOURNAL" }, { "-slaveFailure", nullptr }, { "-syncInterrupt", nullptr },
        { ".corruptedflg", nullptr }, { "-compare", nullptr }, { "-walcompress", nullptr },
        { "-journalcompress", nullptr }, { "-shmcompress", nullptr }, { "-lockcompress", nullptr } };
    static constexpr int CHECKPOINT_TIME = 500;
    static constexpr int DEFAULT_BUSY_TIMEOUT_MS = 2000;
    static constexpr int BACKUP_PAGES_PRE_STEP = 12800; // 1024 * 4 * 12800 == 50m
    static constexpr int BACKUP_PRE_WAIT_TIME = 10;
    static constexpr int RESTORE_PRE_WAIT_TIME = 120;
    static constexpr int DEFAULT_ITER_NUM = 10000;
    static constexpr ssize_t SLAVE_WAL_SIZE_LIMIT = 2147483647;       // 2147483647 = 2g - 1
    static constexpr ssize_t SLAVE_INTEGRITY_CHECK_LIMIT = 524288000; // 524288000 == 1024 * 1024 * 500
    static constexpr unsigned short BINLOG_FILE_NUMS_LIMIT = 2;
    static constexpr uint32_t BINLOG_FILE_SIZE_LIMIT = 1024 * 1024 * 4; // 4194304 == 1024 * 1024 * 4
    static constexpr uint32_t NO_ITER = 0;
    static constexpr uint32_t DB_INDEX = 0;
    static constexpr uint32_t WAL_INDEX = 2;
    static const int32_t regCreator_;
    static const int32_t regRepairer_;
    static const int32_t regDeleter_;
    static const int32_t regCollector_;
    static const int32_t regGetDbFileser_;
    static const int32_t regReplicaChecker_;
    static const int32_t regDbClientCleaner_;
    static const int32_t regOpenSSLCleaner_;
    static const int32_t regRekeyExcuter_;
    static ConcurrentMap<std::string, std::weak_ptr<SqliteConnection>> reusableReplicas_;
    using EventHandle = int (SqliteConnection::*)();
    struct HandleInfo {
        RegisterType Type;
        EventHandle handle;
    };
    static constexpr HandleInfo onEventHandlers_[RegisterType::OBSERVER_END] = {
        { RegisterType::STORE_OBSERVER, &SqliteConnection::RegisterStoreObs },
        { RegisterType::CLIENT_OBSERVER, &SqliteConnection::RegisterClientObs },
    };
    static constexpr const char *ENCRYPT_ALGOS[EncryptAlgo::PLAIN_TEXT] = { "aes-256-gcm", "aes-256-cbc" };
    static constexpr const char *HMAC_ALGOS[static_cast<int>(HmacAlgo::HMAC_BUTT)] = { "SHA1", "SHA256", "SHA512" };
    static constexpr const char *KDF_ALGOS[static_cast<int>(KdfAlgo::KDF_BUTT)] = { "KDF_SHA1", "KDF_SHA256",
        "KDF_SHA512" };

    std::atomic<uint64_t> backupId_;
    sqlite3 *dbHandle_;
    bool isWriter_;
    bool isReadOnly_;
    bool isConfigured_ = false;
    bool isSupportBinlog_ = false;
    bool isSlave_ = false;
    bool isReplay_ = false;
    JournalMode mode_ = JournalMode::MODE_WAL;
    int maxVariableNumber_;
    std::shared_ptr<SqliteConnection> slaveConnection_;
    std::map<std::string, ScalarFunctionInfo> customScalarFunctions_;
    const RdbStoreConfig config_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif