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
#include <thread>
#include <shared_mutex>

#include "dataobs_mgr_client.h"
#include "data_ability_observer_stub.h"
#include "rdb_service.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "refbase.h"
#include "sqlite_connection_pool.h"
#include "sqlite_statement.h"

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

class RdbStoreImpl : public RdbStore, public std::enable_shared_from_this<RdbStoreImpl> {
public:
    RdbStoreImpl(const RdbStoreConfig &config, int &errCode);
    ~RdbStoreImpl() override;
    const RdbStoreConfig &GetConfig();
    int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) override;
    int BatchInsert(int64_t &outInsertNum, const std::string &table,
        const std::vector<ValuesBucket> &initialBatchValues) override;
    int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) override;
    int InsertWithConflictResolution(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues,
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
    int ExecuteSql(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>()) override;
    int ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs) override;
    int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int Backup(const std::string databasePath,
        const std::vector<uint8_t> destEncryptKey = std::vector<uint8_t>()) override;
    int Attach(const std::string &alias, const std::string &pathName,
        const std::vector<uint8_t> destEncryptKey) override;
    int GetVersion(int &version) override;
    int SetVersion(int version) override;
    int BeginTransaction() override;
    int RollBack() override;
    int Commit() override;
    bool IsInTransaction() override;
    bool IsOpen() const override;
    std::string GetPath() override;
    bool IsReadOnly() const override;
    bool IsMemoryRdb() const override;
    bool IsHoldingConnection() override;
#ifdef RDB_SUPPORT_ICU
    int ConfigLocale(const std::string localeStr);
#endif
    int Restore(const std::string backupPath, const std::vector<uint8_t> &newKey = std::vector<uint8_t>()) override;
    void GetSchema(const RdbStoreConfig &config);
    std::string GetName();
    std::string GetOrgPath();
    std::string GetFileType();
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<std::string> &sqlArgs) override;
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

    int RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) override;

    int UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) override;

    int Notify(const std::string &event) override;

    ModifyTime GetModifyTime(const std::string& table, const std::string& columnName,
        std::vector<PRIKey>& keys) override;

    int CleanDirtyData(const std::string &table, uint64_t cursor = UINT64_MAX) override;

private:
    int InnerOpen();
    int CheckAttach(const std::string &sql);
    int BeginExecuteSql(const std::string &sql, std::shared_ptr<SqliteConnection> &connection);
    int FreeTransaction(std::shared_ptr<SqliteConnection> connection, const std::string &sql);
    std::pair<std::string, std::vector<ValueObject>> GetInsertParams(
        std::map<std::string, ValueObject> &valuesMap, const std::string &table);
    int GetDataBasePath(const std::string &databasePath, std::string &backupFilePath);
    int ExecuteSqlInner(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    int ExecuteGetLongInner(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    void SetAssetStatus(const ValueObject &val, int32_t status);
    void DoCloudSync(const std::string &table);
    int InnerSync(const DistributedRdb::RdbService::Option &option, const DistributedRdb::PredicatesMemo &predicates,
        const AsyncDetail &async);
    int InnerBackup(const std::string databasePath,
        const std::vector<uint8_t> destEncryptKey = std::vector<uint8_t>());
    ModifyTime GetModifyTimeByRowId(const std::string& logTable, std::vector<PRIKey>& keys);
    inline std::string GetSqlArgs(size_t size);
    Uri GetUri(const std::string &event);
    int SubscribeLocal(const SubscribeOption& option, RdbStoreObserver *observer);
    int SubscribeLocalShared(const SubscribeOption& option, RdbStoreObserver *observer);
    int SubscribeRemote(const SubscribeOption& option, RdbStoreObserver *observer);

    int UnSubscribeLocal(const SubscribeOption& option, RdbStoreObserver *observer);
    int UnSubscribeLocalAll(const SubscribeOption& option);
    int UnSubscribeLocalShared(const SubscribeOption& option, RdbStoreObserver *observer);
    int UnSubscribeLocalSharedAll(const SubscribeOption& option);
    int UnSubscribeRemote(const SubscribeOption& option, RdbStoreObserver *observer);
    int RegisterDataChangeCallback();
    void InitDelayNotifier();
    bool ColHasSpecificField(const std::vector<std::string> &columns);

    const RdbStoreConfig rdbStoreConfig;
    SqliteConnectionPool *connectionPool;
    bool isOpen;
    std::string path;
    std::string orgPath;
    bool isReadOnly;
    bool isMemoryRdb;
    std::string name;
    std::string fileType;
    DistributedRdb::RdbSyncerParam syncerParam_;
    bool isEncrypt_;
    std::shared_ptr<ExecutorPool> pool_;
    std::shared_ptr<DelayNotify> delayNotifier_ = nullptr;

    mutable std::shared_mutex rwMutex_;
    static inline constexpr uint32_t INTERVAL = 200;
    static constexpr const char *ROW_ID = "ROWID";
    std::set<std::string> cloudTables_;

    std::mutex mutex_;
    std::shared_ptr<std::set<std::string>> syncTables_;
    static constexpr char SCHEME_RDB[] = "rdb://";
    std::map<std::string, std::list<std::shared_ptr<RdbStoreLocalObserver>>> localObservers_;
    std::map<std::string, std::list<sptr<RdbStoreLocalSharedObserver>>> localSharedObservers_;
};
} // namespace OHOS::NativeRdb
#endif
