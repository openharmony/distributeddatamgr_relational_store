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
#include "data_ability_observer_stub.h"
#include "dataobs_mgr_client.h"
#include "rdb_errno.h"
#include "rdb_service.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "refbase.h"
#include "sqlite_connection_pool.h"
#include "sqlite_statement.h"
#include "value_object.h"

namespace OHOS {
class ExecutorPool;
}

namespace OHOS::NativeRdb {
class DelayNotify;
class RdbStoreLocalObserver {
public:
    explicit RdbStoreLocalObserver(DistributedRdb::RdbStoreObserver *observer) : observer_(observer) {};
    virtual ~RdbStoreLocalObserver() {};
    void OnChange()
    {
        observer_->OnChange();
    }
    DistributedRdb::RdbStoreObserver *getObserver()
    {
        return observer_;
    }
private:
    DistributedRdb::RdbStoreObserver *observer_ = nullptr;
};

class RdbStoreLocalSharedObserver : public AAFwk::DataAbilityObserverStub {
public:
    explicit RdbStoreLocalSharedObserver(DistributedRdb::RdbStoreObserver *observer) : observer_(observer) {};
    virtual ~RdbStoreLocalSharedObserver() {};
    void OnChange() override
    {
        observer_->OnChange();
    }
    DistributedRdb::RdbStoreObserver *getObserver()
    {
        return observer_;
    }
private:
    DistributedRdb::RdbStoreObserver *observer_ = nullptr;
};

class RdbStoreImpl : public RdbStore {
public:
    RdbStoreImpl(const RdbStoreConfig &config);
    RdbStoreImpl(const RdbStoreConfig &config, int &errCode);
    ~RdbStoreImpl() override;
    const RdbStoreConfig &GetConfig();
    int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &values) override;
    int BatchInsert(int64_t& outInsertNum, const std::string& table, const std::vector<ValuesBucket>& values) override;
    int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) override;
    int InsertWithConflictResolution(int64_t &outRowId, const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution) override;
    int Update(int &changedRows, const std::string &table, const ValuesBucket &values, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) override;
    int Update(int &changedRows, const std::string &table, const ValuesBucket &values, const std::string &whereClause,
        const std::vector<ValueObject> &bindArgs) override;
    int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs,
        ConflictResolution conflictResolution) override;
    int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs,
        ConflictResolution conflictResolution) override;
    int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) override;
    int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<ValueObject> &bindArgs) override;
    std::shared_ptr<AbsSharedResultSet> Query(int &errCode, bool distinct,
        const std::string &table, const std::vector<std::string> &columns,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs, const std::string &groupBy,
        const std::string &indexName, const std::string &orderBy, const int &limit, const int &offset) override;
    std::shared_ptr<AbsSharedResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &sqlArgs) override;
    std::shared_ptr<AbsSharedResultSet> QuerySql(const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteSql(const std::string& sql, const std::vector<ValueObject>& bindArgs) override;
    std::pair<int32_t, ValueObject> Execute(const std::string& sql, const std::vector<ValueObject>& bindArgs,
        int64_t trxId) override;
    int ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs) override;
    int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey) override;
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
    int ConfigLocale(const std::string &localeStr);
    int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey) override;
    std::string GetName();
    std::string GetFileType();
    std::shared_ptr<ResultSet> QueryByStep(const std::string& sql, const std::vector<std::string>& sqlArgs) override;
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const std::vector<ValueObject> &args) override;
    std::shared_ptr<ResultSet> QueryByStep(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override;
    std::shared_ptr<AbsSharedResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override;
    std::pair<int32_t, std::shared_ptr<ResultSet>> QuerySharingResource(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override;
    int Count(int64_t &outValue, const AbsRdbPredicates &predicates) override;
    int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) override;
    int Delete(int &deletedRows, const AbsRdbPredicates &predicates) override;

    std::shared_ptr<ResultSet> RemoteQuery(const std::string &device, const AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns, int &errCode) override;

    int SetDistributedTables(const std::vector<std::string> &tables, int32_t type,
        const DistributedRdb::DistributedConfig &distributedConfig) override;

    std::string ObtainDistributedTableName(const std::string& device, const std::string& table, int &errCode) override;

    int Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncBrief &async) override;

    int Sync(const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async) override;

    int Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncDetail &async) override;

    int Subscribe(const SubscribeOption& option, RdbStoreObserver *observer) override;

    int UnSubscribe(const SubscribeOption& option, RdbStoreObserver *observer) override;

    int SubscribeObserver(const SubscribeOption& option, const std::shared_ptr<RdbStoreObserver> &observer) override;

    int UnsubscribeObserver(const SubscribeOption& option, const std::shared_ptr<RdbStoreObserver> &observer) override;

    int RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) override;

    int UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) override;

    int Notify(const std::string &event) override;

    ModifyTime GetModifyTime(const std::string& table, const std::string& columnName,
        std::vector<PRIKey>& keys) override;

    int GetRebuilt(RebuiltType &rebuilt) override;
    int CleanDirtyData(const std::string &table, uint64_t cursor) override;
    std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime = 2) override;
    std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime = 2) override;
    int ModifyLockStatus(const AbsRdbPredicates &predicates, bool isLock) override;
    void AfterOpen(const RdbStoreConfig &config);

protected:
    int InnerOpen();
    const RdbStoreConfig config_;
    bool isOpen_ = false;
    bool isReadOnly_;
    bool isMemoryRdb_;
    bool isEncrypt_;
    int64_t vSchema_ = 0;
    std::string path_;
    std::string orgPath_;
    std::string name_;
    std::string fileType_;

private:
    using ExecuteSqls = std::vector<std::pair<std::string, std::vector<std::vector<ValueObject>>>>;
    using Stmt = std::shared_ptr<Statement>;
    int CheckAttach(const std::string &sql);
    std::pair<int32_t, Stmt> BeginExecuteSql(const std::string &sql);
    ExecuteSqls GenerateSql(const std::string& table, const std::vector<ValuesBucket>& buckets, int limit);
    int GetDataBasePath(const std::string &databasePath, std::string &backupFilePath);
    int ExecuteSqlInner(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    void SetAssetStatus(const ValueObject &val, int32_t status);
    void DoCloudSync(const std::string &table);
    int InnerSync(const DistributedRdb::RdbService::Option &option, const DistributedRdb::PredicatesMemo &predicates,
        const AsyncDetail &async);
    int InnerBackup(const std::string& databasePath,
        const std::vector<uint8_t>& destEncryptKey = std::vector<uint8_t>());
    ModifyTime GetModifyTimeByRowId(const std::string& logTable, std::vector<PRIKey>& keys);
    Uri GetUri(const std::string &event);
    int SubscribeLocal(const SubscribeOption& option, RdbStoreObserver *observer);
    int SubscribeLocalShared(const SubscribeOption& option, RdbStoreObserver *observer);
    int32_t SubscribeLocalDetail(const SubscribeOption& option, const std::shared_ptr<RdbStoreObserver> &observer);
    int SubscribeRemote(const SubscribeOption& option, RdbStoreObserver *observer);

    int UnSubscribeLocal(const SubscribeOption& option, RdbStoreObserver *observer);
    int UnSubscribeLocalAll(const SubscribeOption& option);
    int UnSubscribeLocalShared(const SubscribeOption& option, RdbStoreObserver *observer);
    int UnSubscribeLocalSharedAll(const SubscribeOption& option);
    int32_t UnsubscribeLocalDetail(const SubscribeOption& option, const std::shared_ptr<RdbStoreObserver> &observer);
    int UnSubscribeRemote(const SubscribeOption& option, RdbStoreObserver *observer);
    int RegisterDataChangeCallback();
    void InitDelayNotifier();
    bool ColHasSpecificField(const std::vector<std::string> &columns);
    std::pair<int32_t, Stmt> GetStatement(const std::string& sql, std::shared_ptr<Connection> conn) const;
    std::pair<int32_t, Stmt> GetStatement(const std::string& sql, bool read = false) const;
    int AttachInner(const std::string &attachName,
        const std::string &dbPath, const std::vector<uint8_t> &key, int32_t waitTime);
    std::string GetSecManagerName(const RdbStoreConfig &config);
    void RemoveDbFiles(std::string &path);
    int GetHashKeyForLockRow(const AbsRdbPredicates &predicates, std::vector<std::vector<uint8_t>> &hashKeys);
    int InsertWithConflictResolutionEntry(int64_t &outRowId, const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution);
    int UpdateWithConflictResolutionEntry(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs,
        ConflictResolution conflictResolution);
    int BatchInsertEntry(int64_t& outInsertNum, const std::string& table, const std::vector<ValuesBucket>& values);
    int ExecuteSqlEntry(const std::string& sql, const std::vector<ValueObject>& bindArgs);
    std::pair<int32_t, ValueObject> ExecuteEntry(const std::string& sql, const std::vector<ValueObject>& bindArgs,
        int64_t trxId);
    static void UploadSchema(const DistributedRdb::RdbSyncerParam &param, uint32_t retry);

    static constexpr char SCHEME_RDB[] = "rdb://";
    static constexpr uint32_t EXPANSION = 2;
    static inline constexpr uint32_t INTERVAL = 10;
    static inline constexpr uint32_t RETRY_INTERVAL = 5; // s
    static inline constexpr uint32_t MAX_RETRY_TIMES = 5;
    static constexpr const char *ROW_ID = "ROWID";

    std::shared_ptr<SqliteConnectionPool> connectionPool_ = nullptr;
    DistributedRdb::RdbSyncerParam syncerParam_;

    std::shared_ptr<ExecutorPool> pool_;
    std::shared_ptr<DelayNotify> delayNotifier_ = nullptr;

    mutable std::shared_mutex rwMutex_;

    std::set<std::string> cloudTables_;

    std::mutex mutex_;
    std::shared_ptr<std::set<std::string>> syncTables_;
    std::map<std::string, std::list<std::shared_ptr<RdbStoreLocalObserver>>> localObservers_;
    std::map<std::string, std::list<sptr<RdbStoreLocalSharedObserver>>> localSharedObservers_;
    ConcurrentMap<std::string, std::string> attachedInfo_;
    uint32_t rebuild_;
};
} // namespace OHOS::NativeRdb
#endif
