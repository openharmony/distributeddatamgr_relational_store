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
class RdbStoreImpl : public RdbStore, public std::enable_shared_from_this<RdbStoreImpl> {
public:
    static std::shared_ptr<RdbStore> Open(const RdbStoreConfig &config, int &errCode);
    RdbStoreImpl();
    ~RdbStoreImpl() override;
#ifdef WINDOWS_PLATFORM
    void Clear() override;
#endif
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
    int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs) override;
    int ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs) override;
    int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    int Backup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey) override;
    int Attach(const std::string &alias, const std::string &pathName,
        const std::vector<uint8_t> destEncryptKey) override;
    int GetVersion(int &version) override;
    int SetVersion(int version) override;
    int BeginTransaction() override;
    int RollBack() override;
    int Commit() override;
    int MarkAsCommit() override;
    int EndTransaction() override;
    bool IsInTransaction() override;
    std::shared_ptr<SqliteStatement> BeginStepQuery(int &errCode, const std::string sql,
        const std::vector<std::string> &bindArgs);
    int EndStepQuery();
    bool IsOpen() const override;
    std::string GetPath() override;
    bool IsReadOnly() const override;
    bool IsMemoryRdb() const override;
    int PrepareAndGetInfo(const std::string &sql, bool &outIsReadOnly, int &numParameters,
        std::vector<std::string> &columnNames);
    bool IsHoldingConnection() override;
    int GiveConnectionTemporarily(int64_t milliseconds);
    int BeginTransactionWithObserver(TransactionObserver *transactionObserver);
#ifdef RDB_SUPPORT_ICU
    int ConfigLocale(const std::string localeStr);
#endif
    int Restore(const std::string backupPath, const std::vector<uint8_t> &newKey) override;
    int ChangeDbFileForRestore(const std::string newPath, const std::string backupPath,
        const std::vector<uint8_t> &newKey) override;
    std::string GetName();
    std::string GetOrgPath();
    std::string GetFileType();
    std::unique_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<std::string> &selectionArgs) override;
    std::unique_ptr<ResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> columns) override;
    int Count(int64_t &outValue, const AbsRdbPredicates &predicates) override;
    int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) override;
    int Delete(int &deletedRows, const AbsRdbPredicates &predicates) override;

private:
    int InnerOpen(const RdbStoreConfig &config);
    std::shared_ptr<StoreSession> GetThreadSession();
    void ReleaseThreadSession();
    int CheckAttach(const std::string &sql);
    std::string ExtractFilePath(const std::string& fileFullName);
    bool PathToRealPath(const std::string& path, std::string& realPath);

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
    bool isEncrypt_;
};
} // namespace OHOS::NativeRdb
#endif
