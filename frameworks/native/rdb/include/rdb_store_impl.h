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

#include "rdb_store.h"
#include "rdb_store_config.h"
#include "sqlite_connection_pool.h"
#include "sqlite_statement.h"
#include "store_session.h"
#include "transaction_observer.h"

namespace OHOS::NativeRdb {
class API_EXPORT RdbStoreImpl : public RdbStore, public std::enable_shared_from_this<RdbStoreImpl> {
public:
    API_EXPORT static std::shared_ptr<RdbStore> Open(const RdbStoreConfig &config, int &errCode);
    API_EXPORT RdbStoreImpl();
    API_EXPORT ~RdbStoreImpl() override;

    API_EXPORT int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) override;
    API_EXPORT int BatchInsert(int64_t &outInsertNum, const std::string &table,
        const std::vector<ValuesBucket> &initialBatchValues) override;
    API_EXPORT int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) override;
    API_EXPORT int InsertWithConflictResolution(int64_t &outRowId, const std::string &table,
        const ValuesBucket &initialValues, ConflictResolution conflictResolution) override;
    API_EXPORT int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs) override;
    API_EXPORT int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs,
        ConflictResolution conflictResolution) override;
    API_EXPORT int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) override;
    API_EXPORT std::unique_ptr<AbsSharedResultSet> Query(int &errCode, bool distinct,
        const std::string &table, const std::vector<std::string> &columns,
        const std::string &selection, const std::vector<std::string> &selectionArgs, const std::string &groupBy,
        const std::string &having, const std::string &orderBy, const std::string &limit) override;
    API_EXPORT std::unique_ptr<AbsSharedResultSet> QuerySql(const std::string &sql,
        const std::vector<std::string> &selectionArgs) override;
    API_EXPORT int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs) override;
    API_EXPORT int ExecuteAndGetLong(
        int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs) override;
    API_EXPORT int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    API_EXPORT int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    API_EXPORT int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    API_EXPORT int Backup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey) override;
    API_EXPORT int Attach(const std::string &alias, const std::string &pathName,
        const std::vector<uint8_t> destEncryptKey) override;
    API_EXPORT int GetVersion(int &version) override;
    API_EXPORT int SetVersion(int version) override;
    API_EXPORT int BeginTransaction() override;
    API_EXPORT int RollBack() override;
    API_EXPORT int Commit() override;
    API_EXPORT bool IsInTransaction() override;
    API_EXPORT bool IsOpen() const override;
    API_EXPORT std::string GetPath() override;
    API_EXPORT bool IsReadOnly() const override;
    API_EXPORT bool IsMemoryRdb() const override;
    API_EXPORT bool IsHoldingConnection() override;
    API_EXPORT int GiveConnectionTemporarily(int64_t milliseconds);
#ifdef RDB_SUPPORT_ICU
    API_EXPORT int ConfigLocale(const std::string localeStr);
#endif
    API_EXPORT int Restore(const std::string backupPath, const std::vector<uint8_t> &newKey) override;
    API_EXPORT int ChangeDbFileForRestore(const std::string newPath, const std::string backupPath,
        const std::vector<uint8_t> &newKey) override;
    API_EXPORT std::string GetName();
    API_EXPORT std::string GetOrgPath();
    API_EXPORT std::string GetFileType();
    API_EXPORT std::unique_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<std::string> &selectionArgs) override;
    API_EXPORT std::unique_ptr<ResultSet> QueryByStep(
        const AbsRdbPredicates &predicates, const std::vector<std::string> columns) override;
    API_EXPORT std::unique_ptr<AbsSharedResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> columns) override;
    API_EXPORT int Count(int64_t &outValue, const AbsRdbPredicates &predicates) override;
    API_EXPORT int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) override;
    API_EXPORT int Delete(int &deletedRows, const AbsRdbPredicates &predicates) override;

    API_EXPORT std::shared_ptr<ResultSet> RemoteQuery(const std::string &device, const AbsRdbPredicates &predicates,
        const std::vector<std::string> &columns) override;

    API_EXPORT bool SetDistributedTables(const std::vector<std::string>& tables) override;

    API_EXPORT std::string ObtainDistributedTableName(const std::string& device, const std::string& table) override;

    API_EXPORT bool Sync(
        const SyncOption &option, const AbsRdbPredicates &predicate, const SyncCallback &callback) override;

    API_EXPORT bool Subscribe(const SubscribeOption& option, RdbStoreObserver *observer) override;

    API_EXPORT bool UnSubscribe(const SubscribeOption& option, RdbStoreObserver *observer) override;

    // user must use UDID
    API_EXPORT bool DropDeviceData(const std::vector<std::string>& devices, const DropOption& option) override;

private:
    int InnerOpen(const RdbStoreConfig &config);
    int CheckAttach(const std::string &sql);
    int BeginExecuteSql(const std::string &sql, SqliteConnection **connection);
    int FreeTransaction(SqliteConnection *connection, const std::string &sql);
    std::string GetBatchInsertSql(std::map<std::string, ValueObject> &valuesMap, const std::string &table);

    SqliteConnectionPool *connectionPool;
    static const int MAX_IDLE_SESSION_SIZE = 5;
    std::mutex sessionMutex;
    std::map<std::thread::id, std::pair<std::shared_ptr<StoreSession>, int>> threadMap;
    std::list<std::shared_ptr<StoreSession>> idleSessions;
    bool isOpen;
    std::string path;
    std::string orgPath;
    bool isReadOnly;
    bool isMemoryRdb;
    std::string name;
    std::string fileType;
    std::stack<TransactionObserver *> transactionObserverStack;
    bool isShared_ = false;
    DistributedRdb::RdbSyncerParam syncerParam_;
    bool isEncrypt_;
};
} // namespace OHOS::NativeRdb
#endif
