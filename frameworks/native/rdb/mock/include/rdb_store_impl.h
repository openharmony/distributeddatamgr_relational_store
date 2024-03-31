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

#include "concurrent_map.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "sqlite_connection_pool.h"
#include "sqlite_statement.h"


namespace OHOS::NativeRdb {
class RdbStoreImpl : public RdbStore, public std::enable_shared_from_this<RdbStoreImpl> {
public:
    RdbStoreImpl(const RdbStoreConfig &config);
    RdbStoreImpl(const RdbStoreConfig &config, int &errCode);
    ~RdbStoreImpl() override;
#ifdef WINDOWS_PLATFORM
    void Clear() override;
#endif
    const RdbStoreConfig &GetConfig();
    virtual int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &values) override;
    virtual int BatchInsert(
        int64_t& outInsertNum, const std::string& table, const std::vector<ValuesBucket>& values) override;
    virtual int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues) override;
    virtual int InsertWithConflictResolution(int64_t &outRowId, const std::string &table, const ValuesBucket &values,
        ConflictResolution conflictResolution) override;
    virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs) override;
    virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs) override;
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs,
        ConflictResolution conflictResolution) override;
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<ValueObject> &bindArgs,
        ConflictResolution conflictResolution) override;
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) override;
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<ValueObject> &bindArgs) override;
    virtual int ExecuteSql(const std::string& sql, const std::vector<ValueObject>& bindArgs) override;
    std::pair<int32_t, ValueObject> Execute(const std::string &sql, const std::vector<ValueObject> &bindArgs,
        int64_t trxId) override;
    virtual int ExecuteAndGetLong(
        int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs) override;
    virtual int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    virtual int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    virtual int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs) override;
    virtual int Backup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey) override;
    virtual int GetVersion(int &version) override;
    virtual int SetVersion(int version) override;
    virtual int BeginTransaction() override;
    virtual std::pair<int, int64_t> BeginTrans() override;
    virtual int RollBack() override;
    virtual int RollBack(int64_t trxId) override;
    virtual int Commit() override;
    virtual int Commit(int64_t trxId) override;
    virtual bool IsInTransaction() override;
    virtual bool IsOpen() const override;
    virtual std::string GetPath() override;
    virtual bool IsReadOnly() const override;
    virtual bool IsMemoryRdb() const override;
    virtual bool IsHoldingConnection() override;
    int ConfigLocale(const std::string &localeStr);
    virtual int Restore(const std::string backupPath, const std::vector<uint8_t> &newKey) override;
    virtual std::string GetName();
    virtual std::string GetOrgPath();
    virtual std::string GetFileType();
    virtual std::shared_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<std::string> &sqlArgs) override;
    virtual std::shared_ptr<ResultSet> QueryByStep(
        const std::string &sql, const std::vector<ValueObject> &args) override;
    virtual std::shared_ptr<ResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) override;
    virtual int Count(int64_t &outValue, const AbsRdbPredicates &predicates) override;
    virtual int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) override;
    virtual int Delete(int &deletedRows, const AbsRdbPredicates &predicates) override;
    virtual std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime = 2) override;
    virtual std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime = 2) override;

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
    int CheckAttach(const std::string &sql);
    bool PathToRealPath(const std::string &path, std::string &realPath);
    std::string ExtractFilePath(const std::string &fileFullName);
    int BeginExecuteSql(const std::string &sql, std::shared_ptr<SqliteConnection> &connection);
    int FreeTransaction(std::shared_ptr<SqliteConnection> connection, const std::string &sql);
    ExecuteSqls GenerateSql(const std::string& table, const std::vector<ValuesBucket>& buckets, int limit);
    ExecuteSqls MakeExecuteSqls(const std::string& sql, std::vector<ValueObject>&& args, int fieldSize, int limit);
    int GetDataBasePath(const std::string &databasePath, std::string &backupFilePath);
    int ExecuteSqlInner(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    int ExecuteGetLongInner(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    void SetAssetStatus(const ValueObject &val, int32_t status);
    void DoCloudSync(const std::string &table);
    int InnerBackup(const std::string &databasePath,
        const std::vector<uint8_t> &destEncryptKey = std::vector<uint8_t>());
    inline std::string GetSqlArgs(size_t size);
    int RegisterDataChangeCallback();
    int AttachInner(const std::string &attachName,
        const std::string &dbPath, const std::vector<uint8_t> &key, int32_t waitTime);

    static constexpr char SCHEME_RDB[] = "rdb://";
    static constexpr uint32_t EXPANSION = 2;
    static constexpr uint32_t AUTO_SYNC_MAX_INTERVAL = 20000;
    static inline constexpr uint32_t INTERVAL = 10;
    static constexpr const char *ROW_ID = "ROWID";

    std::shared_ptr<SqliteConnectionPool> connectionPool_;
    ConcurrentMap<std::string, const RdbStoreConfig> attachedInfo_;
};
} // namespace OHOS::NativeRdb
#endif
