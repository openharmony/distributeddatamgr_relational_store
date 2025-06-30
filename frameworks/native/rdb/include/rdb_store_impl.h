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

#ifndef NATIVE_RDB_RDB_STORE_IMPL_H
#define NATIVE_RDB_RDB_STORE_IMPL_H

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "concurrent_map.h"
#include "connection_pool.h"
#include "knowledge_schema_helper.h"
#include "rdb_errno.h"
#include "rdb_obs_manager.h"
#include "rdb_open_callback.h"
#include "rdb_service.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "refbase.h"
#include "sqlite_statement.h"
#include "value_object.h"

namespace OHOS {
class ExecutorPool;
}

namespace OHOS::NativeRdb {
class DelayNotify;
class RdbStoreLocalDbObserver;
using RdbStoreObserver = DistributedRdb::RdbStoreObserver;
class RdbStoreLocalObserver {
public:
    explicit RdbStoreLocalObserver(std::shared_ptr<RdbStoreObserver> observer) : observer_(observer) {};
    virtual ~RdbStoreLocalObserver() {};
    void OnChange()
    {
        auto obs = observer_.lock();
        if (obs != nullptr) {
            obs->OnChange();
        }
    }
    std::shared_ptr<RdbStoreObserver> getObserver()
    {
        return observer_.lock();
    }

private:
    std::weak_ptr<RdbStoreObserver> observer_;
};

class RdbStoreImpl : public RdbStore {
public:
    RdbStoreImpl(const RdbStoreConfig &config);
    ~RdbStoreImpl() override;
    int32_t Init(int version, RdbOpenCallback &openCallback);
    std::pair<int, int64_t> Insert(const std::string &table, const Row &row, Resolution resolution) override;
    std::pair<int, int64_t> BatchInsert(const std::string &table, const ValuesBuckets &rows) override;
    std::pair<int32_t, Results> BatchInsert(const std::string &table, const RefRows &rows,
        const std::vector<std::string> &returningFields, Resolution resolution) override;
    std::pair<int32_t, Results> Update(const Row &row, const AbsRdbPredicates &predicates,
        const std::vector<std::string> &returningFields, Resolution resolution) override;
    std::pair<int32_t, Results> Delete(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &returningFields) override;
    std::shared_ptr<AbsSharedResultSet> QuerySql(const std::string &sql, const Values &args) override;
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const Values &args, bool preCount) override;
    std::shared_ptr<ResultSet> RemoteQuery(
        const std::string &device, const AbsRdbPredicates &predicates, const Fields &columns, int &errCode) override;
    std::pair<int32_t, std::shared_ptr<ResultSet>> QuerySharingResource(
        const AbsRdbPredicates &predicates, const Fields &columns) override;
    int ExecuteSql(const std::string &sql, const Values &args) override;
    std::pair<int32_t, ValueObject> Execute(const std::string &sql, const Values &args, int64_t trxId) override;
    std::pair<int32_t, Results> ExecuteExt(const std::string &sql, const Values &args) override;
    int ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const Values &args) override;
    int ExecuteAndGetString(std::string &outValue, const std::string &sql, const Values &args) override;
    int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql, const Values &args) override;
    int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql, const Values &args) override;
    int GetVersion(int &version) override;
    int SetVersion(int version) override;
    int BeginTransaction() override;
    std::pair<int, int64_t> BeginTrans() override;
    int RollBack() override;
    int RollBack(int64_t trxId) override;
    int Commit() override;
    int Commit(int64_t trxId) override;
    bool IsInTransaction() override;
    bool IsOpen() const override;
    std::string GetPath() override;
    bool IsReadOnly() const override;
    bool IsMemoryRdb() const override;
    bool IsHoldingConnection() override;
    bool IsSlaveDiffFromMaster() const override;
    int Backup(const std::string &databasePath, const std::vector<uint8_t> &encryptKey) override;
    int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey) override;
    int Count(int64_t &outValue, const AbsRdbPredicates &predicates) override;
    int SetDistributedTables(const std::vector<std::string> &tables, int32_t type,
        const DistributedRdb::DistributedConfig &distributedConfig) override;
    int32_t Rekey(const RdbStoreConfig::CryptoParam &cryptoParam) override;
    std::string ObtainDistributedTableName(const std::string &device, const std::string &table, int &errCode) override;
    int Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncBrief &async) override;
    int Sync(const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async) override;
    int Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncDetail &async) override;
    int Subscribe(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer) override;
    int UnSubscribe(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer) override;
    int SubscribeObserver(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer) override;
    int UnsubscribeObserver(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer) override;
    int RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) override;
    int UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) override;
    int Notify(const std::string &event) override;
    int SetSearchable(bool isSearchable) override;
    ModifyTime GetModifyTime(
        const std::string &table, const std::string &columnName, std::vector<PRIKey> &keys) override;
    int GetRebuilt(RebuiltType &rebuilt) override;
    int CleanDirtyData(const std::string &table, uint64_t cursor) override;
    std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime) override;
    std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime) override;
    int ModifyLockStatus(const AbsRdbPredicates &predicates, bool isLock) override;
    int32_t GetDbType() const override;
    std::pair<int32_t, uint32_t> LockCloudContainer() override;
    int32_t UnlockCloudContainer() override;
    int InterruptBackup() override;
    int32_t GetBackupStatus() const override;
    std::pair<int32_t, std::shared_ptr<Transaction>> CreateTransaction(int32_t type) override;
    int CleanDirtyLog(const std::string &table, uint64_t cursor) override;
    int InitKnowledgeSchema(const DistributedRdb::RdbKnowledgeSchema &schema) override;
    int RegisterAlgo(const std::string &clstAlgoName, ClusterAlgoFunc func) override;

    // not virtual functions /
    const RdbStoreConfig &GetConfig();
    int ConfigLocale(const std::string &localeStr) override;
    std::string GetName();
    std::string GetFileType();
    int32_t ExchangeSlaverToMaster();
    void Close();

protected:
    std::string GetLogTableName(const std::string &tableName) override;

private:
    using Stmt = std::shared_ptr<Statement>;
    using RdbParam = DistributedRdb::RdbSyncerParam;
    using Options = DistributedRdb::RdbService::Option;
    using Memo = DistributedRdb::PredicatesMemo;
    using ReportFunc = std::function<void(const DistributedRdb::RdbStatEvent&)>;
    class CloudTables {
    public:
        int32_t AddTables(const std::vector<std::string> &tables);
        int32_t RmvTables(const std::vector<std::string> &tables);
        bool Change(const std::string &table);
        std::set<std::string> Steal();

    private:
        std::mutex mutex_;
        std::set<std::string> tables_;
        std::set<std::string> changes_;
    };

    static void AfterOpen(const RdbParam &param, int32_t retry = 0);
    int32_t ProcessOpenCallback(int version, RdbOpenCallback &openCallback);
    int32_t CreatePool(bool &created);
    static void RegisterDataChangeCallback(
        std::shared_ptr<DelayNotify> delayNotifier, std::weak_ptr<ConnectionPool> connPool, int retry);
    int InnerOpen();
    void InitReportFunc(const RdbParam &param);
    void InitSyncerParam(const RdbStoreConfig &config, bool created);
    int32_t SetSecurityLabel(const RdbStoreConfig &config);
    int ExecuteByTrxId(const std::string &sql, int64_t trxId, bool closeConnAfterExecute = false,
        const std::vector<ValueObject> &bindArgs = {});
    std::pair<int32_t, Results> HandleResults(
        std::shared_ptr<Statement> statement, const std::string &sql, int32_t code, int sqlType);
    std::pair<int32_t, ValueObject> HandleDifferentSqlTypes(
        std::shared_ptr<Statement> statement, const std::string &sql, int32_t code, int sqlType);
    int CheckAttach(const std::string &sql);
    std::pair<int32_t, Stmt> BeginExecuteSql(const std::string &sql);
    int GetDataBasePath(const std::string &databasePath, std::string &backupFilePath);
    void DoCloudSync(const std::string &table);
    static int InnerSync(const RdbParam &param, const Options &option, const Memo &predicates,
        const AsyncDetail &async);
    int InnerBackup(const std::string &databasePath,
        const std::vector<uint8_t> &destEncryptKey = std::vector<uint8_t>());
    ModifyTime GetModifyTimeByRowId(const std::string &logTable, std::vector<PRIKey> &keys);
    std::string GetUri(const std::string &event);
    int SubscribeLocal(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer);
    int SubscribeLocalShared(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer);
    int32_t SubscribeLocalDetail(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer);
    int SubscribeRemote(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer);
    int UnSubscribeLocal(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer);
    int UnSubscribeLocalShared(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer);
    int32_t UnsubscribeLocalDetail(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer);
    int UnSubscribeRemote(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer);
    int RegisterDataChangeCallback();
    void InitDelayNotifier();
    void TryDump(int32_t code, const char *dumpHeader);
    std::pair<int32_t, std::shared_ptr<Connection>> CreateWritableConn();
    std::vector<ValueObject> CreateBackupBindArgs(
        const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey);
    std::pair<int32_t, Stmt> GetStatement(const std::string &sql, std::shared_ptr<Connection> conn) const;
    std::pair<int32_t, Stmt> GetStatement(const std::string &sql, bool read = false) const;
    int AttachInner(const RdbStoreConfig &config, const std::string &attachName, const std::string &dbPath,
        const std::vector<uint8_t> &key, int32_t waitTime);
    int SetDefaultEncryptSql(
        const std::shared_ptr<Statement> &statement, std::string sql, const RdbStoreConfig &config);
    int SetDefaultEncryptAlgo(const ConnectionPool::SharedConn &conn, const RdbStoreConfig &config);
    int GetHashKeyForLockRow(const AbsRdbPredicates &predicates, std::vector<std::vector<uint8_t>> &hashKeys);
    int GetSlaveName(const std::string &dbName, std::string &backupFilePath);
    bool TryGetMasterSlaveBackupPath(const std::string &srcPath, std::string &destPath, bool isRestore = false);
    void NotifyDataChange();
    int GetDestPath(const std::string &backupPath, std::string &destPath);
    std::shared_ptr<ConnectionPool> GetPool() const;
    int HandleCloudSyncAfterSetDistributedTables(
        const std::vector<std::string> &tables, const DistributedRdb::DistributedConfig &distributedConfig);
    std::pair<int32_t, std::shared_ptr<Connection>> GetConn(bool isRead);
    std::pair<int32_t, Results> ExecuteForRow(const std::string &sql, const Values &args);
    static Results GenerateResult(int32_t code, std::shared_ptr<Statement> statement, bool isDML = true);
    static std::shared_ptr<ResultSet> GetValues(std::shared_ptr<Statement> statement);
    int32_t HandleSchemaDDL(std::shared_ptr<Statement> statement, const std::string &sql);
    void BatchInsertArgsDfx(int argsSize);
    void SetKnowledgeSchema();
    std::shared_ptr<NativeRdb::KnowledgeSchemaHelper> GetKnowledgeSchemaHelper();
    static bool IsKnowledgeDataChange(const DistributedRdb::RdbChangedData &rdbChangedData);
    static bool IsNotifyService(const DistributedRdb::RdbChangedData &rdbChangedData);

    static constexpr char SCHEME_RDB[] = "rdb://";
    static constexpr uint32_t EXPANSION = 2;
    static inline constexpr uint32_t INTERVAL = 10;
    static inline constexpr uint32_t MAX_RETURNING_ROWS = 1024;
    static inline constexpr uint32_t RETRY_INTERVAL = 5; // s
    static inline constexpr int32_t MAX_RETRY_TIMES = 5;
    static constexpr const char *ROW_ID = "ROWID";

    bool isOpen_ = false;
    bool isReadOnly_ = false;
    bool isMemoryRdb_ = false;
    uint32_t rebuild_ = RebuiltType::NONE;
    int32_t initStatus_ = -1;
    const std::shared_ptr<SlaveStatus> slaveStatus_ = std::make_shared<SlaveStatus>(SlaveStatus::UNDEFINED);
    int64_t vSchema_ = 0;
    std::atomic<int64_t> newTrxId_ = 1;
    const RdbStoreConfig config_;
    // Can only be modified within the constructor
    DistributedRdb::RdbSyncerParam syncerParam_;
    DistributedRdb::RdbStatEvent statEvent_;
    std::shared_ptr<ReportFunc> reportFunc_ = nullptr;
    std::string path_;
    std::string name_;
    std::string fileType_;
    mutable std::shared_mutex rwMutex_;
    mutable std::shared_mutex poolMutex_;
    std::mutex mutex_;
    std::mutex initMutex_;
    std::shared_ptr<ConnectionPool> connectionPool_ = nullptr;
    std::shared_ptr<DelayNotify> delayNotifier_ = nullptr;
    std::shared_ptr<CloudTables> cloudInfo_ = std::make_shared<CloudTables>();
    RdbObsManager obsManger_;
    std::map<std::string, std::list<std::shared_ptr<RdbStoreLocalObserver>>> localObservers_;
    std::list<std::shared_ptr<RdbStoreLocalDbObserver>> localDetailObservers_;
    ConcurrentMap<std::string, std::string> attachedInfo_;
    ConcurrentMap<int64_t, std::shared_ptr<Connection>> trxConnMap_ = {};
    std::list<std::weak_ptr<Transaction>> transactions_;
    std::mutex helperMutex_;
    std::shared_ptr<NativeRdb::KnowledgeSchemaHelper> knowledgeSchemaHelper_;
};
} // namespace OHOS::NativeRdb
#endif
