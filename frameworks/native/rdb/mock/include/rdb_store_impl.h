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

#include "abs_shared_result_set.h"
#include "concurrent_map.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "sqlite_connection_pool.h"
#include "sqlite_statement.h"

namespace OHOS::NativeRdb {
class RdbStoreImpl : public RdbStore {
public:
    RdbStoreImpl(const RdbStoreConfig &config);
    RdbStoreImpl(const RdbStoreConfig &config, int &errCode);
    ~RdbStoreImpl() override;
    const RdbStoreConfig &GetConfig();
    int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &values) override;
    int BatchInsert(
        int64_t& outInsertNum, const std::string& table, const std::vector<ValuesBucket>& values) override;
    int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) override;
    int InsertWithConflictResolution(int64_t &outRowId, const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution) override;
    int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs) override;
    int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs) override;
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
    int ExecuteSql(const std::string& sql, const std::vector<ValueObject>& bindArgs) override;
    std::pair<int32_t, ValueObject> Execute(const std::string &sql, const std::vector<ValueObject> &bindArgs,
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
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<std::string> &sqlArgs) override;
    std::shared_ptr<ResultSet> QueryByStep(
        const std::string &sql, const std::vector<ValueObject> &args) override;
    std::shared_ptr<ResultSet> QueryByStep(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override;
    std::shared_ptr<ResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override;
    int Count(int64_t &outValue, const AbsRdbPredicates &predicates) override;
    int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) override;
    int Delete(int &deletedRows, const AbsRdbPredicates &predicates) override;
    int GetRebuilt(RebuiltType &rebuilt) override;
    std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime = 2) override;
    std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime = 2) override;

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
    int ExecuteSqlInner(const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteGetLongInner(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    void SetAssetStatus(const ValueObject &val, int32_t status);
    void DoCloudSync(const std::string &table);
    int InnerBackup(const std::string &databasePath,
        const std::vector<uint8_t> &destEncryptKey = std::vector<uint8_t>());
    int RegisterDataChangeCallback();
    std::pair<int32_t, Stmt> GetStatement(const std::string& sql, std::shared_ptr<Connection> conn) const;
    std::pair<int32_t, Stmt> GetStatement(const std::string& sql, bool read = false) const;
    int AttachInner(const std::string &attachName,
        const std::string &dbPath, const std::vector<uint8_t> &key, int32_t waitTime);
    void RemoveDbFiles(std::string &path);
    int InsertWithConflictResolutionEntry(int64_t &outRowId, const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution);
    int UpdateWithConflictResolutionEntry(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs,
        ConflictResolution conflictResolution);
    int BatchInsertEntry(int64_t& outInsertNum, const std::string& table, const std::vector<ValuesBucket>& values);
    int ExecuteSqlEntry(const std::string& sql, const std::vector<ValueObject>& bindArgs);
    std::pair<int32_t, ValueObject> ExecuteEntry(const std::string& sql, const std::vector<ValueObject>& bindArgs,
        int64_t trxId);
    static constexpr char SCHEME_RDB[] = "rdb://";
    static constexpr uint32_t EXPANSION = 2;
    static constexpr uint32_t AUTO_SYNC_MAX_INTERVAL = 20000;
    static inline constexpr uint32_t INTERVAL = 10;
    static constexpr const char *ROW_ID = "ROWID";

    std::shared_ptr<SqliteConnectionPool> connectionPool_;
    ConcurrentMap<std::string, std::string> attachedInfo_;
    uint32_t rebuild_;
};
} // namespace OHOS::NativeRdb
#endif
