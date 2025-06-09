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
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "knowledge_types.h"
#include "result_set.h"
#include "transaction.h"
#include "value_object.h"
#include "values_bucket.h"
#include "values_buckets.h"

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
     * @brief Use RdbKnowledgeSchema replace DistributedRdb::RdbKnowledgeSchema namespace.
     */
    using RdbKnowledgeSchema = DistributedRdb::RdbKnowledgeSchema;

    /**
     * @brief Use Date replace DistributedRdb::Date namespace.
     */
    using Date = DistributedRdb::Date;

    /**
     * @brief Use Fields replace std::vector<std::string> columns.
     */
    using Fields = std::vector<std::string>;

    /**
     * @brief Use Olds replace std::vector<std::string> args.
     */
    using Olds = std::vector<std::string>;

    /**
     * @brief Use Values replace std::vector<ValueObject> args.
     */
    using Values = std::vector<ValueObject>;

    /**
     * @brief Use Row replace ValuesBucket.
     */
    using Row = ValuesBucket;

    /**
     * @brief Use Rows replace std::vector<Row>.
     */
    using Rows = std::vector<Row>;

    /**
     * @brief Use Rows replace std::vector<Row>.
     */
    using RefRows = ValuesBuckets;

    /**
     * @brief Use Resolution replace ConflictResolution.
     */
    using Resolution = ConflictResolution;

    class API_EXPORT ModifyTime {
    public:
        ModifyTime() = default;
        API_EXPORT ModifyTime(
            std::shared_ptr<ResultSet> result, std::map<std::vector<uint8_t>, PRIKey> hashKeys, bool isFromRowId);
        API_EXPORT operator std::map<PRIKey, Date>();
        API_EXPORT operator std::shared_ptr<ResultSet>();
        API_EXPORT PRIKey GetOriginKey(const std::vector<uint8_t> &hash);
        API_EXPORT size_t GetMaxOriginKeySize();
        API_EXPORT bool NeedConvert() const;

    private:
        std::shared_ptr<ResultSet> result_;
        std::map<std::vector<uint8_t>, PRIKey> hash_;
        size_t maxOriginKeySize_ = sizeof(int64_t);
        bool isFromRowId_{ false };
    };

    static constexpr Resolution NO_ACTION = ConflictResolution::ON_CONFLICT_NONE;

    /**
     * @brief Destructor.
     */
    virtual ~RdbStore() = default;

    /**
     * @brief Inserts a row of data into the target table.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data {@link ValuesBucket} to be inserted into the table.
     * @param resolution Indicates the {@link ConflictResolution} to insert data into the table.
     */
    virtual std::pair<int, int64_t> Insert(const std::string &table, const Row &row, Resolution resolution = NO_ACTION);

    /**
     * @brief Inserts a row of data into the target table.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data {@link ValuesBucket} to be inserted into the table.
     */
    virtual int Insert(int64_t &outRowId, const std::string &table, const Row &row);

    /**
     * @brief Inserts a row of data into the target table.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data {@link ValuesBucket} to be inserted into the table.
     * @param resolution Indicates the {@link ConflictResolution} to insert data into the table.
     */
    [[deprecated("Use Insert(const std::string &, const Row &, Resolution) instead.")]]
    virtual int InsertWithConflictResolution(
        int64_t &outRowId, const std::string &table, const Row &row, Resolution resolution = NO_ACTION);

    /**
     * @brief Replaces a row of data into the target table.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data {@link ValuesBucket} to be replaced into the table.
     */
    virtual int Replace(int64_t &outRowId, const std::string &table, const Row &row);

    /**
     * @brief Inserts a batch of data into the target table.
     *
     * @param table Indicates the target table.
     * @param rows Indicates the rows of data {@link ValuesBucket} to be inserted into the table.
     */
    virtual int BatchInsert(int64_t &outInsertNum, const std::string &table, const Rows &rows);

    /**
     * @brief Inserts a batch of data into the target table.
     *
     * @param table Indicates the target table.
     * @param values Indicates the rows of data {@link ValuesBuckets} to be inserted into the table.
     */
    virtual std::pair<int, int64_t> BatchInsert(const std::string &table, const RefRows &rows);

    /**
     * @brief Inserts a batch of data into the target table with conflict resolution.
     *
     * @param table Indicates the target table.
     * @param values Indicates the rows of data {@link ValuesBuckets} to be inserted into the table.
     * @param resolution Indicates the {@link ConflictResolution} to insert data into the table.
     */
    virtual std::pair<int, int64_t> BatchInsert(const std::string &table, const RefRows &rows, Resolution resolution);

    /**
     * @brief Inserts a batch of data into the target table.
     *
     * @param table Indicates the target table.
     * @param rows Indicates the rows of data {@link ValuesBucket} to be inserted into the table.
     * @param returningFields Indicates the returning fields.
     * @param resolution Indicates the {@link ConflictResolution} to insert data into the table.
     * @return Return the inserted result. Contains error codes, affected rows,
     * and returningField values for inserting data
     * @warning 1. When using returningField, it is not recommended to use the ON_CONFLICT_FAIL strategy. This will
     * result in returned results that do not match expectations. 2.When the number of affected rows exceeds 1024,
     * only the first 1024 returningFields will be returned
     */
    virtual std::pair<int32_t, Results> BatchInsert(const std::string &table, const RefRows &rows,
        const std::vector<std::string> &returningFields, Resolution resolution = NO_ACTION);

    /**
     * @brief Updates data in the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param args Indicates the where arguments.
     */
    virtual std::pair<int, int> Update(const std::string &table, const Row &row, const std::string &where = "",
        const Values &args = {}, Resolution resolution = NO_ACTION);

    /**
     * @brief Updates data in the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param args Indicates the where arguments.
     */
    virtual int Update(int &changedRows, const std::string &table, const Row &row, const std::string &whereClause = "",
        const Values &args = {});

    /**
     * @brief Updates data in the database based on a a specified instance object of AbsRdbPredicates.
     *
     * @param values Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     */
    virtual int Update(int &changedRows, const Row &row, const AbsRdbPredicates &predicates);

    /**
     * @brief Updates data in the database based on a a specified instance object of AbsRdbPredicates.
     *
     * @param row Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     * @param returningFields Indicates the returning fields.
     * @param resolution Indicates the {@link ConflictResolution} to insert data into the table.
     * @return Return the updated result. Contains error code, number of affected rows,
     * and value of returningField after update
     * @warning 1. When using returningField, it is not recommended to use the ON_CONFLICT_FAIL strategy. This will
     * result in returned results that do not match expectations. 2.When the number of affected rows exceeds 1024,
     * only the first 1024 returningFields will be returned
     */
    virtual std::pair<int32_t, Results> Update(const Row &row, const AbsRdbPredicates &predicates,
        const std::vector<std::string> &returningFields, Resolution resolution = NO_ACTION);

    /**
     * @brief Updates data in the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param args Indicates the where arguments.
     */
    [[deprecated("Use Update(int &, const std::string &, const Row &, const std::string &, const Values &) instead.")]]
    virtual int Update(
        int &changedRows, const std::string &table, const Row &row, const std::string &whereClause, const Olds &args);

    /**
     * @brief Updates data in the database based on a a specified instance object of RdbPredicates.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param args Indicates the where arguments.
     * @param resolution Indicates the {@link ConflictResolution} to insert data into the table.
     */
    [[deprecated("Use UpdateWithConflictResolution(int &, const std::string &, const Row &, const std::string &, "
                 "const Values &, ConflictResolution conflictResolution) instead.")]]
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const Row &row,
        const std::string &whereClause, const Olds &args, Resolution resolution = NO_ACTION);

    /**
     * @brief Updates data in the database based on a a specified instance object of RdbPredicates.
     *
     * @param table Indicates the target table.
     * @param row Indicates the row of data to be updated in the database.
     * The key-value pairs are associated with column names of the database table.
     * @param whereClause Indicates the where clause.
     * @param args Indicates the where arguments.
     * @param resolution Indicates the {@link ConflictResolution} to update data into the table.
     */
    virtual int UpdateWithConflictResolution(int &changedRows, const std::string &table, const Row &row,
        const std::string &whereClause = "", const Values &args = {}, Resolution resolution = NO_ACTION);

    /**
     * @brief Deletes data from the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param whereClause Indicates the where clause.
     * @param args Indicates the where arguments.
     */
    [[deprecated("Use Delete(int &, const std::string &, const std::string &, const Values &) instead.")]]
    virtual int Delete(int &deletedRows, const std::string &table, const std::string &whereClause, const Olds &args);

    /**
     * @brief Deletes data from the database based on a specified instance object of AbsRdbPredicates.
     *
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     */
    virtual int Delete(int &deletedRows, const AbsRdbPredicates &predicates);

    /**
     * @brief Deletes data from the database based on specified conditions.
     *
     * @param table Indicates the target table.
     * @param whereClause Indicates the where clause.
     * @param args Indicates the where arguments.
     */
    virtual int Delete(
        int &deletedRows, const std::string &table, const std::string &whereClause = "", const Values &args = {});

    /**
     * @brief Deletes data from the database based on a specified instance object of AbsRdbPredicates.
     *
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     * @param returningFields Indicates the returning fields.
     * @return Return the deleted result. Contains error code, number of affected rows,
     * and value of returningField before delete
     * @warning When the number of affected rows exceeds 1024, only the first 1024 returningFields will be returned.
     */
    virtual std::pair<int32_t, Results> Delete(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &returningFields = {});
    /**
     * @brief Queries data in the database based on specified conditions.
     *
     * @param distinct Indicates whether to eliminate all duplicate records in the result set.
     * @param table Indicates the target table.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     * @param whereClause Indicates the selection.
     * @param args Indicates the selection arguments.
     * @param groupBy Indicates the groupBy argument.
     * @param indexName Indicates the index by argument.
     * @param orderBy Indicates the orderBy argument.
     * @param limit Indicates the limit argument.
     */
    [[deprecated("Use Query(int &, const std::string &, const std::string &, const Values &) instead.")]]
    virtual std::shared_ptr<AbsSharedResultSet> Query(int &errCode, bool distinct, const std::string &table,
        const Fields &columns, const std::string &whereClause = "", const Values &args = {},
        const std::string &groupBy = "", const std::string &indexName = "", const std::string &orderBy = "",
        const int &limit = AbsPredicates::INIT_LIMIT_VALUE, const int &offset = AbsPredicates::INIT_LIMIT_VALUE);

    /**
     * @brief Queries data in the database based on specified conditions.
     *
     * @param predicates Indicates the specified query condition by the instance object of {@link AbsRdbPredicates}.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     */
    virtual std::shared_ptr<AbsSharedResultSet> Query(const AbsRdbPredicates &predicates, const Fields &columns = {});

    /**
     * @brief Queries data in the database based on SQL statement.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the selection arguments.
     */
    [[deprecated("Use QuerySql(const std::string &, const Values &) instead.")]]
    virtual std::shared_ptr<AbsSharedResultSet> QuerySql(const std::string &sql, const Olds &args);

    /**
     * @brief Queries data in the database based on SQL statement.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the selection arguments.
     */
    virtual std::shared_ptr<AbsSharedResultSet> QuerySql(const std::string &sql, const Values &args = {}) = 0;

    /**
     * @brief Queries data in the database based on SQL statement.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the selection arguments.
     */
    [[deprecated("Use QueryByStep(const std::string &, const Values &) instead.")]]
    virtual std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const Olds &args);

    /**
     * @brief Queries data in the database based on SQL statement.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the selection arguments.
     * @param preCount IIndicates whether to calculate the count during query.
     */
    virtual std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const Values &args = {},
        bool preCount = true) = 0;

    /**
     * @brief Queries data in the database based on specified conditions.
     *
     * @param predicates Indicates the specified query condition by the instance object of {@link AbsRdbPredicates}.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     * @param preCount IIndicates whether to calculate the count during query.
     */
    virtual std::shared_ptr<ResultSet> QueryByStep(const AbsRdbPredicates &predicates, const Fields &columns = {},
        bool preCount = true);

    /**
     * @brief Queries remote data in the database based on specified conditions before Synchronizing Data.
     *
     * @param device Indicates specified remote device.
     * @param predicates Indicates the specified query condition by the instance object of {@link AbsRdbPredicates}.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     */
    virtual std::shared_ptr<ResultSet> RemoteQuery(
        const std::string &device, const AbsRdbPredicates &predicates, const Fields &columns, int &errCode);

    /**
     * @brief Queries data in the database based on specified conditions.
     *
     * @param predicates Indicates the specified query condition by the instance object of {@link AbsRdbPredicates}.
     * @param columns Indicates the columns to query. If the value is empty array, the query applies to all columns.
     */
    virtual std::pair<int32_t, std::shared_ptr<ResultSet>> QuerySharingResource(
        const AbsRdbPredicates &predicates, const Fields &columns);

    /**
     * @brief Executes an SQL statement that contains specified parameters.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    [[deprecated("Use Execute(const std::string &, const Values &, int64_t) instead.")]]
    virtual int ExecuteSql(const std::string &sql, const Values &args = {});

    /**
     * @brief Executes an SQL statement that contains specified parameters and
     *        get two values of type int and ValueObject.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual std::pair<int32_t, ValueObject> Execute(const std::string &sql, const Values &args = {}, int64_t trxId = 0);

    /**
     * @brief Executes an SQL statement that contains specified parameters and
     *        get two values of type int and ValueObject.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param returningField Indicates the fieldName of result.
     * @param args Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     * @return Return the result. Contains error code, number of affected rows, and value of returningField
     */
    virtual std::pair<int32_t, Results> ExecuteExt(const std::string &sql, const Values &args = {});

    /**
     * @brief Executes an SQL statement that contains specified parameters and get a long integer value.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    [[deprecated("Use Execute(const std::string &, const Values &, int64_t) instead.")]]
    virtual int ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const Values &args = {});

    /**
     * @brief Executes an SQL statement that contains specified parameters.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    [[deprecated("Use Execute(const std::string &, const Values &, int64_t) instead.")]]
    virtual int ExecuteAndGetString(std::string &outValue, const std::string &sql, const Values &args = {});

    /**
     * @brief Executes for last insert row id that contains specified parameters.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual int ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql, const Values &args = {});

    /**
     * @brief Executes for change row count that contains specified parameters.
     *
     * @param sql Indicates the SQL statement to execute.
     * @param args Indicates the {@link ValueObject} values of the parameters in the SQL statement.
     */
    virtual int ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql, const Values &args = {});

    /**
     * @brief Restores a database from a specified encrypted or unencrypted database file.
     *
     * @param databasePath Indicates the database file path.
     * @param encryptKey Indicates the database encrypt key.
     */
    virtual int Backup(const std::string &databasePath, const std::vector<uint8_t> &encryptKey = {});

    /**
     * @brief Attaches a database.
     *
     * @param alias Indicates the database alias.
     * @param pathName Indicates the database file pathname.
     * @param destEncryptKey Indicates the database encrypt key.
     */
    [[deprecated("Use Attach(const RdbStoreConfig &, const std::string &, int32_t) instead.")]]
    virtual int Attach(const std::string &alias, const std::string &pathName, const std::vector<uint8_t> encryptKey);

    /**
     * @brief Get the value of the column based on specified conditions.
     *
     * @param predicates Indicates the {@link AbsRdbPredicates} AbsRdbPredicates object.
     */
    virtual int Count(int64_t &outValue, const AbsRdbPredicates &predicates);

    /**
     * @brief Gets the version of the database.
     */
    virtual int GetVersion(int &version) = 0;

    /**
     * @brief Sets the version of a new database.
     */
    virtual int SetVersion(int version) = 0;

    /**
     * @brief Create a transaction of a new database connection.
     */
    virtual std::pair<int32_t, std::shared_ptr<Transaction>> CreateTransaction(int32_t type);

    /**
     * @brief Begins a transaction in EXCLUSIVE mode.
     */
    [[deprecated("Use CreateTransaction(int32_t) instead.")]]
    virtual int BeginTransaction();
    virtual std::pair<int, int64_t> BeginTrans();

    /**
     * @brief Rollback a transaction in EXCLUSIVE mode.
     */
    [[deprecated("Use CreateTransaction(int32_t) instead.")]]
    virtual int RollBack();
    virtual int RollBack(int64_t trxId);

    /**
     * @brief Commit a transaction in EXCLUSIVE mode.
     */
    [[deprecated("Use CreateTransaction(int32_t) instead.")]]
    virtual int Commit();
    virtual int Commit(int64_t trxId);

    /**
     * @brief Check the current connection is in transaction.
     */
    virtual bool IsInTransaction();

    /**
     * @brief Get database path.
     */
    virtual std::string GetPath();

    /**
     * @brief Check the current connection pool is holding connection.
     */
    virtual bool IsHoldingConnection();

    /**
     * @brief Check the current database is open.
     */
    virtual bool IsOpen() const;

    /**
     * @brief Check the current database is read only.
     */
    virtual bool IsReadOnly() const;

    /**
     * @brief Changes the key used to encrypt the database.
     *
     * @param Crypto parameters
     */
    virtual int32_t Rekey(const RdbStoreConfig::CryptoParam &cryptoParam);

    /**
     * @brief Check the current database is memory database.
     */
    virtual bool IsMemoryRdb() const;

    /**
     * @brief Restores a database from a specified database file.
     *
     * @param backupPath  Indicates the name that saves the database file path.
     * @param newKey Indicates the database new key.
     */
    virtual int Restore(const std::string &backupPath, const std::vector<uint8_t> &newKey = {});

    /**
     * @brief Set table to be distributed table.
     *
     * @param tables Indicates the tables name you want to set.
     */
    virtual int SetDistributedTables(const std::vector<std::string> &tables,
        int32_t type = DistributedRdb::DistributedTableType::DISTRIBUTED_DEVICE,
        const DistributedRdb::DistributedConfig &distributedConfig = { true });

    /**
     * @brief Obtain distributed table name of specified remote device according to local table name.
     * When query remote device database, distributed table name is needed.
     *
     * @param device Indicates the remote device.
     *
     * @return Returns the distributed table name.
     */
    virtual std::string ObtainDistributedTableName(const std::string &device, const std::string &table, int &errCode);

    /**
     * @brief Sync data between devices or cloud.
     *
     * @param device Indicates the remote device.
     * @param predicate Indicates the AbsRdbPredicates {@link AbsRdbPredicates} object.
     */
    virtual int Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncBrief &async);

    /**
     * @brief Sync data between devices or cloud.
     *
     * @param device Indicates the remote device.
     * @param predicate Indicates the AbsRdbPredicates {@link AbsRdbPredicates} object.
     */
    virtual int Sync(const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async);

    /**
     * @brief Sync data between devices or cloud.
     *
     * @param device Indicates the remote device.
     * @param predicate Indicates the AbsRdbPredicates {@link AbsRdbPredicates} object.
     */
    virtual int Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const AsyncDetail &async);

    /**
     * @brief Subscribe to event changes.
     */
    virtual int Subscribe(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer);

    /**
     * @brief UnSubscribe to event changes.
     */
    virtual int UnSubscribe(const SubscribeOption &option, std::shared_ptr<RdbStoreObserver> observer);

    /**
     * @brief SubscribeObserver to event changes.
     */
    virtual int SubscribeObserver(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer);

    /**
     * @brief UnsubscribeObserver to event changes.
     */
    virtual int UnsubscribeObserver(const SubscribeOption &option, const std::shared_ptr<RdbStoreObserver> &observer);

    /**
     * @brief Register message for auto sync operation.
     */
    virtual int RegisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer);

    /**
     * @brief UnRegister message for auto sync operation.
     */
    virtual int UnregisterAutoSyncCallback(std::shared_ptr<DetailProgressObserver> observer);

    /**
     * @brief When SubscribeMode is LOCAL or LOCALSHARED, this function needs to be called to trigger callback.
     */
    virtual int Notify(const std::string &event);

    /**
     * @brief Check the slave database is different from current database.
     */
    virtual bool IsSlaveDiffFromMaster() const;

    virtual int32_t GetDbType() const;

    virtual std::pair<int32_t, uint32_t> LockCloudContainer();

    virtual int32_t UnlockCloudContainer();

    virtual int InterruptBackup();

    virtual int32_t GetBackupStatus() const;

    /**
     * @brief Get the the specified column modify time.
     *
     * @param table Indicates the specified table.
     * @param column Indicates the column.
     * @param keys Indicates the primary key.
     *
     * @return Returns the specified column modify time.
     */
    virtual ModifyTime GetModifyTime(const std::string &table, const std::string &column, std::vector<PRIKey> &keys);

    /**
     * @brief Cleans dirty data deleted in the cloud.
     *
     * If a cursor is specified, data with a cursor smaller than the specified cursor will be cleaned up.
     * otherwise clean all.
     *
     * @param table Indicates the specified table.
     */
    virtual int CleanDirtyData(const std::string &table, uint64_t cursor = UINT64_MAX);

    /**
     * @brief Gets the rebuilt_ status of the database.
     */
    virtual int GetRebuilt(RebuiltType &rebuilt);

    /**
     * @brief Attaches a database file to the currently linked database.
     *
     * @param config Indicates the {@link RdbStoreConfig} configuration of the database related to this RDB store.
     * @param attachName Indicates the alias of the database.
     * @param waitTime Indicates the maximum time allowed for attaching the database file.
     */
    virtual std::pair<int32_t, int32_t> Attach(
        const RdbStoreConfig &config, const std::string &attachName, int32_t waitTime = 2);

    /**
     * @brief Detaches a database from this database.
     *
     * @param attachName Indicates the alias of the database.
     * @param waitTime Indicates the maximum time allowed for attaching the database file.
     */
    virtual std::pair<int32_t, int32_t> Detach(const std::string &attachName, int32_t waitTime = 2);

    /**
     * @brief Locks/Unlocks data from the database based on a specified instance object of AbsRdbPredicates.
     *
     * @param predicates Indicates the specified update condition by the instance object of {@link AbsRdbPredicates}.
     */
    virtual int ModifyLockStatus(const AbsRdbPredicates &predicates, bool isLock);

    /**
     * @brief Set search enable or disable.
     *
     * @param isSearchable Indicates enable or disable.
     */
    virtual int SetSearchable(bool isSearchable);

    virtual int CleanDirtyLog(const std::string &table, uint64_t cursor = 0);

    virtual int InitKnowledgeSchema(const RdbKnowledgeSchema &schema);

    /**
     * @brief Support for collations in different languages.
     *
     * @param locale Represents Language related to the locale, for example, zh.
     * The value complies with the ISO 639 standard.
     */
    virtual int ConfigLocale(const std::string &localeStr);

    /**
     * @brief Register a customised cluster algo to db
     *
     * @param clstAlgoName name of function
     * @param func ptr of function
     */
    virtual int RegisterAlgo(const std::string &clstAlgoName, ClusterAlgoFunc func);

protected:
    virtual std::string GetLogTableName(const std::string &tableName);
};
} // namespace OHOS::NativeRdb
#endif
