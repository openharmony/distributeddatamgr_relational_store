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

#include "rdb_store.h"
#include "rdb_store_config.h"
#include "sqlite_connection_pool.h"
#include "sqlite_statement.h"

namespace OHOS {
class ExecutorPool;
}
namespace OHOS::NativeRdb {
class RdbStoreImpl : public RdbStore, public std::enable_shared_from_this<RdbStoreImpl> {
public:
    static std::shared_ptr<RdbStoreImpl> Open(const RdbStoreConfig &config, int &errCode);
    RdbStoreImpl(const RdbStoreConfig &config);
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
    int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs,
        ConflictResolution conflictResolution) override;
    int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) override;
    std::shared_ptr<AbsSharedResultSet> Query(int &errCode, bool distinct,
        const std::string &table, const std::vector<std::string> &columns,
        const std::string &selection, const std::vector<std::string> &selectionArgs, const std::string &groupBy,
        const std::string &having, const std::string &orderBy, const std::string &limit) override;
    std::shared_ptr<AbsSharedResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &selectionArgs) override;
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
    int GiveConnectionTemporarily(int64_t milliseconds);
#ifdef RDB_SUPPORT_ICU
    int ConfigLocale(const std::string localeStr);
#endif
    int Restore(const std::string backupPath, const std::vector<uint8_t> &newKey = std::vector<uint8_t>()) override;
    void GetSchema(const RdbStoreConfig &config);
    std::string GetName();
    std::string GetOrgPath();
    std::string GetFileType();
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<std::string> &selectionArgs) override;
    std::shared_ptr<ResultSet> QueryByStep(
        const AbsRdbPredicates &predicates, const std::vector<std::string> columns) override;
    std::shared_ptr<AbsSharedResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> columns) override;
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

    int Subscribe(const SubscribeOption& option, RdbStoreObserver *observer) override;

    int UnSubscribe(const SubscribeOption& option, RdbStoreObserver *observer) override;

    // user must use UDID
    bool DropDeviceData(const std::vector<std::string>& devices, const DropOption& option) override;

private:
    int InnerOpen(const RdbStoreConfig &config);
    int InnerInsert(int64_t &outRowId, const std::string &table, ValuesBucket values,
        ConflictResolution conflictResolution);
    int CheckAttach(const std::string &sql);
    int BeginExecuteSql(const std::string &sql, SqliteConnection **connection);
    int FreeTransaction(SqliteConnection *connection, const std::string &sql);
    std::pair<std::string, std::vector<ValueObject>> GetInsertParams(
        std::map<std::string, ValueObject> &valuesMap, const std::string &table);
    int GetDataBasePath(const std::string &databasePath, std::string &backupFilePath);
    int ExecuteSqlInner(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    int ExecuteGetLongInner(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    void SetAssetStatusWhileInsert(ValueObject &val);
    void DoCloudSync(const std::string &table);
    int InnerBackup(const std::string databasePath,
        const std::vector<uint8_t> destEncryptKey = std::vector<uint8_t>());

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

    mutable std::shared_mutex rwMutex_;
    static inline constexpr uint32_t INTERVAL = 500;
    std::set<std::string> cloudTables_;

    std::mutex mutex_;
    std::shared_ptr<std::set<std::string>> syncTables_;
};
} // namespace OHOS::NativeRdb
#endif
