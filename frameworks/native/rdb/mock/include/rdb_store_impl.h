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

#include <atomic>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "abs_shared_result_set.h"
#include "concurrent_map.h"
#include "connection_pool.h"
#include "knowledge_schema_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "sqlite_statement.h"

namespace OHOS::NativeRdb {
class DelayNotify;
class RdbStoreImpl : public RdbStore {
public:
    RdbStoreImpl(const RdbStoreConfig &config);
    ~RdbStoreImpl() override;
    int32_t Init(int version, RdbOpenCallback &openCallback, bool isNeedSetAcl = false);
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
    int32_t SetTokenizer(Tokenizer tokenizer) override;
    bool IsOpen() const override;
    std::string GetPath() override;
    bool IsReadOnly() const override;
    bool IsMemoryRdb() const override;
    bool IsHoldingConnection() override;
    bool IsSlaveDiffFromMaster() const override;
    int Backup(const std::string &databasePath, const std::vector<uint8_t> &encryptKey, bool verifyDb) override;
    int Backup() override;
    int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey) override;
    int Count(int64_t &outValue, const AbsRdbPredicates &predicates) override;
    int GetRebuilt(RebuiltType &rebuilt) override;
    std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime) override;
    std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime) override;
    int InterruptBackup() override;
    int32_t GetBackupStatus() const override;
    int32_t GetInitStatus() const;
    int32_t GetDbType() const override;
    std::pair<int32_t, std::shared_ptr<Transaction>> CreateTransaction(int32_t type) override;
    int CleanDirtyLog(const std::string &table, uint64_t cursor) override;
    int InitKnowledgeSchema(const DistributedRdb::RdbKnowledgeSchema &schema) override;
    int RegisterAlgo(const std::string &clstAlgoName, ClusterAlgoFunc func) override;
    int ConfigLocale(const std::string &localeStr) override;

    const RdbStoreConfig &GetConfig();
    std::string GetName();
    int32_t ExchangeSlaverToMaster();
    void Close();

private:
    using Stmt = std::shared_ptr<Statement>;
    using RdbParam = DistributedRdb::RdbSyncerParam;
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

    int InnerOpen();
    static bool SetFileGid(const RdbStoreConfig &config, int32_t gid);
    int32_t ProcessOpenCallback(int version, RdbOpenCallback &openCallback);
    int32_t CreatePool(bool &created);
    void InitReportFunc(const RdbParam &param);
    void InitSyncerParam(const RdbStoreConfig &config, bool created);
    int32_t SetSecurityLabel(const RdbStoreConfig &config);
    int ExecuteByTrxId(const std::string &sql, int64_t trxId, bool closeConnAfterExecute = false,
        const std::vector<ValueObject> &bindArgs = {});
    std::pair<int32_t, Results> HandleResults(
        std::shared_ptr<Statement> &&statement, const std::string &sql, int32_t code, int sqlType);
    std::pair<int32_t, ValueObject> HandleDifferentSqlTypes(
        std::shared_ptr<Statement> &&statement, const std::string &sql, int32_t code, int sqlType);
    int CheckAttach(const std::string &sql);
    std::pair<int32_t, Stmt> BeginExecuteSql(const std::string &sql);
    int GetDataBasePath(const std::string &databasePath, std::string &backupFilePath);
    void DoCloudSync(const std::string &table);
    int InnerBackup(const std::string& databasePath,
        const std::vector<uint8_t> &destEncryptKey = std::vector<uint8_t>(), bool verifyDb = true);
    static std::pair<int32_t, std::shared_ptr<Connection>> CreateWritableConn(const RdbStoreConfig &config);
    std::vector<ValueObject> CreateBackupBindArgs(
        const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey);
    std::pair<int32_t, Stmt> GetStatement(const std::string &sql, std::shared_ptr<Connection> conn) const;
    std::pair<int32_t, Stmt> GetStatement(const std::string &sql, bool read = false) const;
    int AttachInner(const RdbStoreConfig &config, const std::string &attachName, const std::string &dbPath,
        const std::vector<uint8_t> &key, int32_t waitTime);
    int SetDefaultEncryptSql(
        const std::shared_ptr<Statement> &statement, std::string sql, const RdbStoreConfig &config);
    int SetDefaultEncryptAlgo(const ConnectionPool::SharedConn &conn, const RdbStoreConfig &config);
    std::string GetSlaveName(const std::string &dbName);
    bool TryGetMasterSlaveBackupPath(const std::string &srcPath, std::string &destPath, bool isRestore = false);
    void NotifyDataChange();
    void TryDump(int32_t code, const char *dumpHeader);
    int GetDestPath(const std::string &backupPath, std::string &destPath);
    std::shared_ptr<ConnectionPool> GetPool() const;
    int HandleCloudSyncAfterSetDistributedTables(
        const std::vector<std::string> &tables, const DistributedRdb::DistributedConfig &distributedConfig);
    std::pair<int32_t, std::shared_ptr<Connection>> GetConn(bool isRead);
    std::pair<int32_t, Results> ExecuteForRow(const std::string &sql, const Values &args);
    static Results GenerateResult(int32_t code, std::shared_ptr<Statement> statement, bool isDML = true);
    static std::shared_ptr<ResultSet> GetValues(std::shared_ptr<Statement> statement);
    int32_t HandleSchemaDDL(std::shared_ptr<Statement> &&statement, const std::string &sql);
    void BatchInsertArgsDfx(int argsSize);
    void SetKnowledgeSchema();
    std::shared_ptr<NativeRdb::KnowledgeSchemaHelper> GetKnowledgeSchemaHelper();
    void SwitchOver(bool isUseReplicaDb);
    bool TryAsyncRepair();
    bool IsInAsyncRestore(const std::string &dbPath);
    int StartAsyncRestore(std::shared_ptr<ConnectionPool> pool) const;
    int StartAsyncBackupIfNeed(std::shared_ptr<SlaveStatus> slaveStatus);
    int RestoreInner(const std::string &destPath, const std::vector<uint8_t> &newKey,
        std::shared_ptr<ConnectionPool> pool);
    static int32_t RestoreWithPool(std::shared_ptr<ConnectionPool> pool, const std::string &path);
    static bool IsKnowledgeDataChange(const DistributedRdb::RdbChangedData &rdbChangedData);
    static bool IsNotifyService(const DistributedRdb::RdbChangedData &rdbChangedData);
    static void ReplayCallbackImpl(const RdbStoreConfig &config);

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
    bool isUseReplicaDb_ = false;
    bool isNeedSetAcl_ = false;
    uint32_t rebuild_ = RebuiltType::NONE;
    int32_t initStatus_ = -1;
    const std::shared_ptr<SlaveStatus> slaveStatus_ = std::make_shared<SlaveStatus>(SlaveStatus::UNDEFINED);
    int64_t vSchema_ = 0;
    std::atomic<int64_t> newTrxId_ = 1;
    std::shared_ptr<RdbStoreConfig> configHolder_;
    const RdbStoreConfig &config_;
    DistributedRdb::RdbSyncerParam syncerParam_;
    DistributedRdb::RdbStatEvent statEvent_;
    std::shared_ptr<ReportFunc> reportFunc_ = nullptr;
    std::string path_;
    std::string name_;
    mutable std::shared_mutex poolMutex_;
    std::mutex mutex_;
    std::mutex initMutex_;
    std::shared_ptr<ConnectionPool> connectionPool_ = nullptr;
    std::shared_ptr<DelayNotify> delayNotifier_ = nullptr;
    std::shared_ptr<CloudTables> cloudInfo_ = std::make_shared<CloudTables>();
    ConcurrentMap<std::string, std::string> attachedInfo_;
    ConcurrentMap<int64_t, std::shared_ptr<Connection>> trxConnMap_ = {};
    std::list<std::weak_ptr<Transaction>> transactions_;
    std::list<std::weak_ptr<Connection>> conns_;
    mutable std::mutex schemaMutex_;
    std::shared_ptr<DistributedRdb::RdbKnowledgeSchema> knowledgeSchema_;
    std::mutex helperMutex_;
    std::shared_ptr<NativeRdb::KnowledgeSchemaHelper> knowledgeSchemaHelper_;
    std::atomic<bool> isKnowledgeSchemaReady_{false};
};
} // namespace OHOS::NativeRdb
#endif
