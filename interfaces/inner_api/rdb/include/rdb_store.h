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

#ifndef NATIVE_RDB_RDB_STORE_H
#define NATIVE_RDB_RDB_STORE_H

#include <stdint.h>
#include <memory>
#include <string>
#include <vector>

#include "abs_rdb_predicates.h"
#include "abs_shared_result_set.h"
#include "result_set.h"
#include "value_object.h"
#include "values_bucket.h"
#include "rdb_types.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"

namespace OHOS::NativeRdb {
class API_EXPORT RdbStore {
public:
    /**
     * @brief Use SyncOption replace DistributedRdb::SyncOption namespace.
     */
    using SyncOption = DistributedRdb::SyncOption;

    /**
     * @brief Use AsyncBrief replace DistributedRdb::AsyncBrief namespace.
     */
    using Briefs = DistributedRdb::Briefs;
    using AsyncBrief = DistributedRdb::AsyncBrief;

    /**
     * @brief Use AsyncBrief replace DistributedRdb::AsyncBrief namespace.
     */
    using Details = DistributedRdb::Details;
    using AsyncDetail = DistributedRdb::AsyncDetail;

    /**
     * @brief Use SubscribeMode replace DistributedRdb::SubscribeMode namespace.
     */
    using SubscribeMode = DistributedRdb::SubscribeMode;

    /**
     * @brief Use SubscribeOption replace DistributedRdb::SubscribeOption namespace.
     */
    using SubscribeOption = DistributedRdb::SubscribeOption;

    /**
     * @brief Use DropOption replace DistributedRdb::DropOption namespace.
     */
    using DropOption = DistributedRdb::DropOption;

    /**
     * @brief Use RdbStoreObserver replace DistributedRdb::RdbStoreObserver namespace.
     */
    using RdbStoreObserver = DistributedRdb::RdbStoreObserver;
    using PRIKey = RdbStoreObserver::PrimaryKey;

    /**
     * @brief Use RdbSyncObserver replace DistributedRdb::RdbSyncObserver namespace.
     */
    using DetailProgressObserver = DistributedRdb::DetailProgressObserver;

    /**
     * @brief Use Date replace DistributedRdb::Date namespace.
     */
    using Date = DistributedRdb::Date;

    /**
     * @brief Destructor.
     */
    virtual ~RdbStore() {}

    /**
     * @brief Inserts a row of data into the target table.
     *
     * @param table Indicates the target table.
     * @param values Indicates the row of data {@link ValuesBucket} to be inserted into the table.
     */
    virtual int Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &values) = 0;

    /**
     * @brief Inserts a batch of data into the target table.
     *
     * @param table Indicates the target table.
     * @param initialBatchValue Indicates the rows of data {@link ValuesBucket} to be inserted into the table.
     */
    virtual int BatchInsert(
        int64_t &outInsertNum, const std::string &table, const std::vector<ValuesBucket> &values) = 0;

    /**
     * @brief Replaces a row of data into the target table.
     *
     * @param table Indicates the target table.
     * @param initialBatchValue Indicates the row of data {@link ValuesBucket} to be replaced into the table.
     */
    virtual int Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &values) = 0;

    /**
     * @brief Inserts a row of data into the target table.
     *
     * @param table Indicates the target table.
     * @param initialValues Indicates the row of data {@link ValuesBucket} to be inserted into the table.
     * @param conflictResolution Indicates the {@link ConflictResolution} to insert data into the table.
     */
    virtual int InsertWithConflictResolution(int64_t &outRowId, const std::string &table,
        const ValuesBucket &initialValues,
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) = 0;

    /**
     * @brief Updates data in the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param values Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param whereArgs Indicates the where arguments.
     */
    [[deprecated("Use Update(int &, const std::string &, const ValuesBucket &, const std::string &,"
                 " const std::vector<ValueObject> &) instead.")]]
    virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs) = 0;

    /**
     * @brief Updates data in the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param values Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param bindArgs Indicates the where arguments.
     */
    virtual int Update(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause = "", const std::vector<ValueObject> &bindArgs = {}) = 0;

    /**
     * @brief Updates data in the database based on a a specified instance object of RdbPredicates.
     *
     * @param table Indicates the target table.
     * @param values Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param whereArgs Indicates the where arguments.
     * @param conflictResolution Indicates the {@link ConflictResolution} to insert data into the table.
     */
    [[deprecated("Use UpdateWithConflictResolution(int &, const std::string &, const ValuesBucket &, "
                 "const std::string &, const std::vector<ValueObject> &,"
                 " ConflictResolution conflictResolution) instead.")]]
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
        const std::string &whereClause, const std::vector<std::string> &whereArgs,
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) = 0;

    /**
     * @brief Updates data in the database based on a a specified instance object of RdbPredicates.
     *
     * @param table Indicates the target table.
     * @param values Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param whereArgs Indicates the where arguments.
     * @param conflictResolution Indicates the {@link ConflictResolution} to insert data into the table.
     */
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table,
        const ValuesBucket &values, const std::string &whereClause = "", const std::vector<ValueObject> &bindArgs = {},
        ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE) = 0;

    /**
     * @brief Deletes data from the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param whereClause Indicates the where clause.
     * @param whereArgs Indicates the where arguments.
     */
    [[deprecated("Use Delete(int &, const std::string &, const std::string &, const std::vector<ValueObject> &) "
                 "instead.")]]
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
        const std::vector<std::string> &whereArgs) = 0;

    /**
     * @brief Deletes data from the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param whereClause Indicates the where clause.
     * @param bindArgs Indicates the where arguments.
     */
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause = "",
        const std::vector<ValueObject> &bindArgs = {}) = 0;

    /**
     * @brief Queries data in the database based on specified conditions.
     *
     * @param distinct Indicates whether to eliminate all duplicate records in the result set.
     * @param table Indicates the target table.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     * @param whereClause Indicates the selection.
     * @param bindArgs Indicates the selection arguments.
     * @param groupBy Indicates the groupBy argument.
     * @param indexName Indicates the index by argument.
     * @param orderBy Indicates the orderBy argument.
     * @param limit Indicates the limit argument.
     */
    virtual std::shared_ptr<AbsSharedResultSet> Query(int &errCode, bool distinct, const std::string &table,
        const std::vector<std::string> &columns, const std::string &whereClause = "",
        const std::vector<ValueObject> &bindArgs = {}, const std::string &groupBy = "",
        const std::string &indexName = "", const std::string &orderBy = "",
        const int &limit = AbsPredicates::INIT_LIMIT_VALUE, const int &offset = AbsPredicates::INIT_LIMIT_VALUE) = 0;

    /**
     * @brief Queries data in the database based on SQL statement.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param sqlArgs Indicates the selection arguments.
     */
    [[deprecated("Use QuerySql(const std::string &, const std::vector<ValueObject> &) instead.")]]
    virtual std::shared_ptr<AbsSharedResultSet> QuerySql(
        const std::string &sql, const std::vector<std::string> &sqlArgs) = 0;

    /**
     * @brief Queries data in the database based on SQL statement.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param bindArgs Indicates the selection arguments.
     */
    virtual std::shared_ptr<AbsSharedResultSet> QuerySql(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = {}) = 0;

    /**
     * @brief Queries data in the database based on SQL statement.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param sqlArgs Indicates the selection arguments.
     */
    [[deprecated("Use ExecuteSql(const std::string &, const std::vector<ValueObject> &) instead.")]]
    virtual std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const std::vector<std::string> &sqlArgs) = 0;

    /**
     * @brief Queries data in the database based on SQL statement.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the selection arguments.
     */
    virtual std::shared_ptr<ResultSet> QueryByStep(const std::string &sql,
        const std::vector<ValueObject> &args = {}) = 0;

    /**
     * @brief Executes an SQL statement that contains specified parameters.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param bindArgs Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs = {}) = 0;

    /**
     * @brief Executes an SQL statement that contains specified parameters and
     *        get two values of type int and ValueObject.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param bindArgs Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual std::pair<int32_t, ValueObject> Execute(const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}, int64_t trxId = 0)
    {
        return { E_NOT_SUPPORT, ValueObject() };
    }

    /**
     * @brief Executes an SQL statement that contains specified parameters and get a long integer value.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param bindArgs Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual int ExecuteAndGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}) = 0;

    /**
     * @brief Executes an SQL statement that contains specified parameters.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param bindArgs Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual int ExecuteAndGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}) = 0;

    /**
     * @brief Executes for last insert row id that contains specified parameters.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param bindArgs Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}) = 0;

    /**
     * @brief Executes for change row count that contains specified parameters.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param bindArgs Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = {}) = 0;

    /**
     * @brief Restores a database from a specified encrypted or unencrypted database file.
     *
     * @param databasePath Indicates the database file path.
     * @param destEncryptKey Indicates the database encrypt key.
     */
    virtual int Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey = {}) = 0;

    /**
     * @brief Attaches a database.
     *
     * @param alias Indicates the database alias.
     * @param pathName Indicates the database file pathname.
     * @param destEncryptKey Indicates the database encrypt key.
     */
    [[deprecated("Use Attach(const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime = 2) "
                 "instead.")]]
    virtual int Attach(
        const std::string &alias, const std::string &pathName, const std::vector<uint8_t> destEncryptKey)
    {
        return E_OK;
    }

    /**
     * @brief Get the value of the column based on specified conditions.
     *
     * @param predicates Indicates the {@link AbsRdbPredicates} AbsRdbPredicates object.
     */
    virtual int Count(int64_t &outValue, const AbsRdbPredicates &predicates) = 0;

    /**
     * @brief Queries data in the database based on specified conditions.
     *
     * @param predicates Indicates the specified query condition by the instance object of {@link AbsRdbPredicates}.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     */
    virtual std::shared_ptr<AbsSharedResultSet> Query(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) = 0;

    /**
     * @brief Queries data in the database based on specified conditions.
     *
     * @param predicates Indicates the specified query condition by the instance object of {@link AbsRdbPredicates}.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     */
    virtual std::pair<int32_t, std::shared_ptr<ResultSet>> QuerySharingResource(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
    {
        return { E_NOT_SUPPORT, nullptr };
    }

    /**
     * @brief Queries data in the database based on specified conditions.
     *
     * @param predicates Indicates the specified query condition by the instance object of {@link AbsRdbPredicates}.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     */
    virtual std::shared_ptr<ResultSet> QueryByStep(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns) = 0;

    /**
     * @brief Queries remote data in the database based on specified conditions before Synchronizing Data.
     *
     * @param device Indicates specified remote device.
     * @param predicates Indicates the specified query condition by the instance object of {@link AbsRdbPredicates}.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     */
    virtual std::shared_ptr<ResultSet> RemoteQuery(const std::string &device,
        const AbsRdbPredicates &predicates, const std::vector<std::string> &columns, int &errCode) = 0;

    /**
     * @brief Updates data in the database based on a a specified instance object of AbsRdbPredicates.
     *
     * @param values Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     */
    virtual int Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates) = 0;

    /**
     * @brief Deletes data from the database based on a specified instance object of AbsRdbPredicates.
     *
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     */
    virtual int Delete(int &deletedRows, const AbsRdbPredicates &predicates) = 0;

    /**
     * @brief Gets the version of the database.
     */
    virtual int GetVersion(int &version) = 0;

    /**
     * @brief Sets the version of a new database.
     */
    virtual int SetVersion(int version) = 0;

    /**
     * @brief Begins a transaction in EXCLUSIVE mode.
     */
    virtual int BeginTransaction() = 0;
    virtual std::pair<int, int64_t> BeginTrans()
    {
        return { E_NOT_SUPPORT, 0 };
    }

    /**
     * @brief Rollback a transaction in EXCLUSIVE mode.
     */
    virtual int RollBack() = 0;
    virtual int RollBack(int64_t trxId)
    {
        return E_NOT_SUPPORT;
    }

    /**
     * @brief Commit a transaction in EXCLUSIVE mode.
     */
    virtual int Commit() = 0;
    virtual int Commit(int64_t trxId)
    {
        return E_NOT_SUPPORT;
    }

    /**
     * @brief Check the current connection is in transaction.
     */
    virtual bool IsInTransaction() = 0;

    /**
     * @brief Get database path.
     */
    virtual std::string GetPath() = 0;

    /**
     * @brief Check the current connection pool is holding connection.
     */
    virtual bool IsHoldingConnection() = 0;

    /**
     * @brief Check the current database is open.
     */
    virtual bool IsOpen() const = 0;

    /**
     * @brief Check the current database is read only.
     */
    virtual bool IsReadOnly() const = 0;

    /**
     * @brief Check the current database is memory database.
     */
    virtual bool IsMemoryRdb() const = 0;

    /**
     * @brief Restores a database from a specified database file.
     *
     * @param backupPath  Indicates the name that saves the database file path.
     * @param newKey Indicates the database new key.
     */
    virtual int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey = {}) = 0;

    /**
     * @brief Set table to be distributed table.
     *
     * @param tables Indicates the tables name you want to set.
     */
    virtual int SetDistributedTables(const std::vector<std::string> &tables,
        int32_t type = DistributedRdb::DistributedTableType::DISTRIBUTED_DEVICE,
        const DistributedRdb::DistributedConfig &distributedConfig = { true }) = 0;

    /**
     * @brief Obtain distributed table name of specified remote device according to local table name.
     * When query remote device database, distributed table name is needed.
     *
     * @param device Indicates the remote device.
     *
     * @return Returns the distributed table name.
     */
    virtual std::string ObtainDistributedTableName(
        const std::string &device, const std::string &table, int &errCode) = 0;

    /**
     * @brief Sync data between devices or cloud.
     *
     * @param device Indicates the remote device.
     * @param predicate Indicates the AbsRdbPredicates {@link AbsRdbPredicates} object.
     */
    virtual int Sync(
        const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncBrief &async) = 0;

    /**
     * @brief Sync data between devices or cloud.
     *
     * @param device Indicates the remote device.
     * @param predicate Indicates the AbsRdbPredicates {@link AbsRdbPredicates} object.
     */
    virtual int Sync(
        const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async) = 0;

    /**
     * @brief Sync data between devices or cloud.
     *
     * @param device Indicates the remote device.
     * @param predicate Indicates the AbsRdbPredicates {@link AbsRdbPredicates} object.
     */
    virtual int Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncDetail &async) = 0;

    /**
     * @brief Subscribe to event changes.
     */
    virtual int Subscribe(const SubscribeOption& option, RdbStoreObserver *observer) = 0;

    /**
     * @brief UnSubscribe to event changes.
     */
    virtual int UnSubscribe(const SubscribeOption& option, RdbStoreObserver *observer) = 0;

    /**
     * @brief SubscribeObserver to event changes.
     */
    virtual int SubscribeObserver(const SubscribeOption& option, const std::shared_ptr<RdbStoreObserver> &observer)
    {
        return E_OK;
    }

    /**
     * @brief UnsubscribeObserver to event changes.
     */
    virtual int UnsubscribeObserver(const SubscribeOption& option, const std::shared_ptr<RdbStoreObserver> &observer)
    {
        return E_OK;
    }

    /**
     * @brief Register message for auto sync operation.
     */
    virtual int RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) = 0;

    /**
     * @brief UnRegister message for auto sync operation.
     */
    virtual int UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer) = 0;

    /**
     * @brief When SubscribeMode is LOCAL or LOCALSHARED, this function needs to be called to trigger callback.
     */
    virtual int Notify(const std::string &event) = 0;

    class ModifyTime {
    public:
        ModifyTime() = default;
        ModifyTime(std::shared_ptr<ResultSet> result, std::map<std::vector<uint8_t>, PRIKey> hashKeys,
            bool isFromRowId);
        operator std::map<PRIKey, Date>();
        operator std::shared_ptr<ResultSet>();
        PRIKey GetOriginKey(const std::vector<uint8_t>& hash);
        size_t GetMaxOriginKeySize();
        bool NeedConvert() const;

    private:
        std::shared_ptr<ResultSet> result_;
        std::map<std::vector<uint8_t>, PRIKey> hash_;
        size_t maxOriginKeySize_ = sizeof(int64_t);
        bool isFromRowId_{ false };
    };
    /**
     * @brief Get the the specified column modify time.
     *
     * @param table Indicates the specified table.
     * @param columnName Indicates the column.
     * @param PRIKey Indicates the primary key.
     *
     * @return Returns the specified column modify time.
     */
    virtual ModifyTime GetModifyTime(const std::string& table, const std::string& columnName,
        std::vector<PRIKey>& keys) = 0;

    /**
     * @brief Cleans dirty data deleted in the cloud.
     *
     * If a cursor is specified, data with a cursor smaller than the specified cursor will be cleaned up.
     * otherwise clean all.
     *
     * @param table Indicates the specified table.
     */
    virtual int CleanDirtyData(const std::string &table, uint64_t cursor = UINT64_MAX) = 0;

    /**
     * @brief Gets the rebuilt_ status of the database.
     */
    virtual int GetRebuilt(RebuiltType &rebuilt) = 0;
    /**
     * @brief Attaches a database file to the currently linked database.
     *
     * @param config Indicates the {@link RdbStoreConfig} configuration of the database related to this RDB store.
     * @param attachName Indicates the alias of the database.
     * @param waitTime Indicates the maximum time allowed for attaching the database file.
     */
    virtual std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime = 2)
    {
        return std::pair<int32_t, int32_t>(0, E_OK);
    }

    /**
     * @brief Detaches a database from this database.
     *
     * @param attachName Indicates the alias of the database.
     * @param waitTime Indicates the maximum time allowed for attaching the database file.
     */
    virtual std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime = 2)
    {
        return std::pair<int32_t, int32_t>(0, E_OK);
    }

    /**
     * @brief Locks/Unlocks data from the database based on a specified instance object of AbsRdbPredicates.
     *
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     */
    virtual int ModifyLockStatus(const AbsRdbPredicates &predicates, bool isLock)
    {
        return E_ERROR;
    }
};
} // namespace OHOS::NativeRdb
#endif
