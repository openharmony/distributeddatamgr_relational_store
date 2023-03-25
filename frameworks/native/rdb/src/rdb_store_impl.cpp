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

#define LOG_TAG "RdbStoreImpl"

#include "rdb_store_impl.h"

#include <unistd.h>

#include <sstream>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_trace.h"
#include "sqlite_database_utils.h"
#include "sqlite_global_config.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"
#include "step_result_set.h"

#ifndef WINDOWS_PLATFORM
#include "directory_ex.h"
#endif

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "iresult_set.h"
#include "rdb_manager.h"
#include "rdb_security_manager.h"
#include "result_set_proxy.h"
#include "sqlite_shared_result_set.h"
#endif

#ifdef WINDOWS_PLATFORM
#define ISFILE(filePath) ((filePath.find("\\") == std::string::npos))
#else
#define ISFILE(filePath) ((filePath.find("/") == std::string::npos))
#endif

namespace OHOS::NativeRdb {
std::shared_ptr<RdbStore> RdbStoreImpl::Open(const RdbStoreConfig &config, int &errCode)
{
    std::shared_ptr<RdbStoreImpl> rdbStore = std::make_shared<RdbStoreImpl>();
    errCode = rdbStore->InnerOpen(config);
    if (errCode != E_OK) {
        return nullptr;
    }

    return rdbStore;
}

int RdbStoreImpl::InnerOpen(const RdbStoreConfig &config)
{
    LOG_INFO("open %{public}s.", SqliteUtils::Anonymous(config.GetPath()).c_str());
    int errCode = E_OK;
    connectionPool = SqliteConnectionPool::Create(config, errCode);
    if (connectionPool == nullptr) {
        return errCode;
    }
    isOpen = true;
    path = config.GetPath();
    orgPath = path;
    isReadOnly = config.IsReadOnly();
    isMemoryRdb = config.IsMemoryRdb();
    name = config.GetName();
    fileType = config.GetDatabaseFileType();
    isEncrypt_ = config.IsEncrypt();
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    syncerParam_.bundleName_ = config.GetBundleName();
    syncerParam_.hapName_ = config.GetModuleName();
    syncerParam_.storeName_ = config.GetName();
    syncerParam_.area_ = config.GetArea();
    syncerParam_.level_ = static_cast<int32_t>(config.GetSecurityLevel());
    syncerParam_.type_ = config.GetDistributedType();
    syncerParam_.isEncrypt_ = config.IsEncrypt();
    syncerParam_.password_ = {};
    // open uri share
    if (!config.GetUri().empty()) {
        std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
        errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
        if (errCode != E_OK) {
            LOG_ERROR("RdbStoreImpl::InnerOpen get service failed, err is %{public}d.", errCode);
            return E_OK;
        }
        errCode = service->CreateRDBTable(syncerParam_, config.GetWritePermission(), config.GetReadPermission());
        if (errCode != E_OK) {
            LOG_ERROR("RdbStoreImpl::InnerOpen service CreateRDBTable failed");
            return E_OK;
        }
        isShared_ = true;
    }
#endif
    return E_OK;
}

RdbStoreImpl::RdbStoreImpl()
    : connectionPool(nullptr), isOpen(false), path(""), orgPath(""), isReadOnly(false), isMemoryRdb(false),
      isEncrypt_(false)
{
}

RdbStoreImpl::~RdbStoreImpl()
{
    delete connectionPool;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    if (isShared_) {
        std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
        int errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
        if (errCode != E_OK) {
            LOG_ERROR("RdbStoreImpl::~RdbStoreImpl get service failed");
            return;
        }
        if (service->DestroyRDBTable(syncerParam_) != E_OK) {
            LOG_ERROR("RdbStoreImpl::~RdbStoreImpl service DestroyRDBTable failed");
        }
    }
#endif
}
#ifdef WINDOWS_PLATFORM
void RdbStoreImpl::Clear()
{
    delete connectionPool;
    connectionPool = nullptr;
}
#endif

int RdbStoreImpl::Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return InsertWithConflictResolution(outRowId, table, initialValues, ConflictResolution::ON_CONFLICT_NONE);
}

int RdbStoreImpl::BatchInsert(int64_t &outInsertNum, const std::string &table,
    const std::vector<ValuesBucket> &initialBatchValues)
{
    if (initialBatchValues.empty()) {
        outInsertNum = 0;
        return E_OK;
    }
    // prepare batch data & sql
    std::map<std::string, ValueObject> valuesMap;
    std::vector<std::pair<std::string, std::vector<ValueObject>>> vecVectorObj;
    for (auto iter = initialBatchValues.begin(); iter != initialBatchValues.end(); iter++) {
        (*iter).GetAll(valuesMap);
        vecVectorObj.push_back(GetInsertParams(valuesMap, table));
        valuesMap.clear();
    }

    // prepare BeginTransaction
    int errCode = connectionPool->AcquireTransaction();
    if (errCode != E_OK) {
        return errCode;
    }

    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    if (connection->IsInTransaction()) {
        connectionPool->ReleaseTransaction();
        connectionPool->ReleaseConnection(connection);
        LOG_ERROR("Transaction is in excuting.");
        return E_TRANSACTION_IN_EXECUTE;
    }
    BaseTransaction transaction(0);
    connection->SetInTransaction(true);
    errCode = connection->ExecuteSql(transaction.GetTransactionStr());
    if (errCode != E_OK) {
        LOG_ERROR("BeginTransaction with error code %{public}d.", errCode);
        connection->SetInTransaction(false);
        connectionPool->ReleaseConnection(connection);
        connectionPool->ReleaseTransaction();
        return errCode;
    }

    // batch insert the values
    for (auto iter = vecVectorObj.begin(); iter != vecVectorObj.end(); iter++) {
        outInsertNum++;
        errCode = connection->ExecuteSql(iter->first, iter->second);
        if (errCode != E_OK) {
            LOG_ERROR("BatchInsert with error code %{public}d.", errCode);
            outInsertNum = -1;
            return FreeTransaction(connection, transaction.GetRollbackStr());
        }
    }

    return FreeTransaction(connection, transaction.GetCommitStr());
}

std::pair<std::string, std::vector<ValueObject>> RdbStoreImpl::GetInsertParams(
    std::map<std::string, ValueObject> &valuesMap, const std::string &table)
{
    std::stringstream sql;
    std::vector<ValueObject> bindArgs;
    sql << "INSERT INTO " << table << '(';
    // prepare batch values & sql.columnName
    for (auto valueIter = valuesMap.begin(); valueIter != valuesMap.end(); valueIter++) {
        sql << ((valueIter == valuesMap.begin()) ? "" : ",");
        sql << valueIter->first;
        bindArgs.push_back(valueIter->second);
    }
    // prepare sql.value
    sql << ") VALUES (";
    for (size_t i = 0; i < valuesMap.size(); i++) {
        sql << ((i == 0) ? "?" : ",?");
    }
    sql << ')';

    // put sql & vec<value> into map<sql, args>
    return std::make_pair(sql.str(), bindArgs);
}

int RdbStoreImpl::Replace(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
{
    return InsertWithConflictResolution(outRowId, table, initialValues, ConflictResolution::ON_CONFLICT_REPLACE);
}

int RdbStoreImpl::InsertWithConflictResolution(int64_t &outRowId, const std::string &table,
    const ValuesBucket &initialValues, ConflictResolution conflictResolution)
{
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    if (initialValues.IsEmpty()) {
        return E_EMPTY_VALUES_BUCKET;
    }

    std::string conflictClause;
    int errCode = SqliteUtils::GetConflictClause(static_cast<int>(conflictResolution), conflictClause);
    if (errCode != E_OK) {
        return errCode;
    }

    std::stringstream sql;
    sql << "INSERT" << conflictClause << " INTO " << table << '(';

    std::map<std::string, ValueObject> valuesMap;
    initialValues.GetAll(valuesMap);
    std::vector<ValueObject> bindArgs;
    for (auto iter = valuesMap.begin(); iter != valuesMap.end(); iter++) {
        sql << ((iter == valuesMap.begin()) ? "" : ",");
        sql << iter->first;               // columnName
        bindArgs.push_back(iter->second); // columnValue
    }

    sql << ") VALUES (";
    for (size_t i = 0; i < valuesMap.size(); i++) {
        sql << ((i == 0) ? "?" : ",?");
    }
    sql << ')';

    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    errCode = connection->ExecuteForLastInsertedRowId(outRowId, sql.str(), bindArgs);
    connectionPool->ReleaseConnection(connection);

    return errCode;
}

int RdbStoreImpl::Update(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<std::string> &whereArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return UpdateWithConflictResolution(
        changedRows, table, values, whereClause, whereArgs, ConflictResolution::ON_CONFLICT_NONE);
}

int RdbStoreImpl::Update(int &changedRows, const ValuesBucket &values, const AbsRdbPredicates &predicates)
{
    return Update(
        changedRows, predicates.GetTableName(), values, predicates.GetWhereClause(), predicates.GetWhereArgs());
}

int RdbStoreImpl::UpdateWithConflictResolution(int &changedRows, const std::string &table, const ValuesBucket &values,
    const std::string &whereClause, const std::vector<std::string> &whereArgs, ConflictResolution conflictResolution)
{
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    if (values.IsEmpty()) {
        return E_EMPTY_VALUES_BUCKET;
    }

    std::string conflictClause;
    int errCode = SqliteUtils::GetConflictClause(static_cast<int>(conflictResolution), conflictClause);
    if (errCode != E_OK) {
        return errCode;
    }

    std::stringstream sql;
    sql << "UPDATE" << conflictClause << " " << table << " SET ";

    std::map<std::string, ValueObject> valuesMap;
    values.GetAll(valuesMap);
    std::vector<ValueObject> bindArgs;
    for (auto iter = valuesMap.begin(); iter != valuesMap.end(); iter++) {
        sql << ((iter == valuesMap.begin()) ? "" : ",");
        sql << iter->first << "=?";       // columnName
        bindArgs.push_back(iter->second); // columnValue
    }

    if (whereClause.empty() == false) {
        sql << " WHERE " << whereClause;
    }

    for (auto &iter : whereArgs) {
        bindArgs.push_back(ValueObject(iter));
    }

    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    errCode = connection->ExecuteForChangedRowCount(changedRows, sql.str(), bindArgs);
    connectionPool->ReleaseConnection(connection);

    return errCode;
}

int RdbStoreImpl::Delete(int &deletedRows, const AbsRdbPredicates &predicates)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return Delete(deletedRows, predicates.GetTableName(), predicates.GetWhereClause(), predicates.GetWhereArgs());
}

int RdbStoreImpl::Delete(int &deletedRows, const std::string &table, const std::string &whereClause,
    const std::vector<std::string> &whereArgs)
{
    if (table.empty()) {
        return E_EMPTY_TABLE_NAME;
    }

    std::stringstream sql;
    sql << "DELETE FROM " << table;
    if (whereClause.empty() == false) {
        sql << " WHERE " << whereClause;
    }

    std::vector<ValueObject> bindArgs;
    for (auto &iter : whereArgs) {
        bindArgs.push_back(ValueObject(iter));
    }

    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteForChangedRowCount(deletedRows, sql.str(), bindArgs);
    connectionPool->ReleaseConnection(connection);

    return errCode;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
std::unique_ptr<AbsSharedResultSet> RdbStoreImpl::Query(
    const AbsRdbPredicates &predicates, const std::vector<std::string> columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    return QuerySql(sql, selectionArgs);
}

std::unique_ptr<ResultSet> RdbStoreImpl::QueryByStep(
    const AbsRdbPredicates &predicates, const std::vector<std::string> columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    return QueryByStep(sql, selectionArgs);
}

std::shared_ptr<ResultSet> RdbStoreImpl::RemoteQuery(const std::string &device,
    const AbsRdbPredicates &predicates, const std::vector<std::string> &columns, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
    errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreImpl::RemoteQuery get service failed");
        return nullptr;
    }
    sptr<IRemoteObject> remoteResultSet;
    if (service->RemoteQuery(syncerParam_, device, sql, selectionArgs, remoteResultSet) != E_OK) {
        LOG_ERROR("RdbStoreImpl::RemoteQuery service RemoteQuery failed");
        return nullptr;
    }
    return std::make_shared<ResultSetProxy>(remoteResultSet);
}

std::unique_ptr<AbsSharedResultSet> RdbStoreImpl::Query(int &errCode, bool distinct, const std::string &table,
    const std::vector<std::string> &columns, const std::string &selection,
    const std::vector<std::string> &selectionArgs, const std::string &groupBy, const std::string &having,
    const std::string &orderBy, const std::string &limit)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string sql;
    errCode = SqliteSqlBuilder::BuildQueryString(distinct, table, columns, selection, groupBy, having, orderBy, limit,
        "", sql);
    if (errCode != E_OK) {
        return nullptr;
    }

    auto resultSet = QuerySql(sql, selectionArgs);
    return resultSet;
}

std::unique_ptr<AbsSharedResultSet> RdbStoreImpl::QuerySql(const std::string &sql,
    const std::vector<std::string> &selectionArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = std::make_unique<SqliteSharedResultSet>(connectionPool, path, sql, selectionArgs);
    return resultSet;
}
#endif

#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
std::unique_ptr<ResultSet> RdbStoreImpl::Query(
    const AbsRdbPredicates &predicates, const std::vector<std::string> columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreImpl::Query on called.");
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    return QueryByStep(sql, selectionArgs);
}
#endif

int RdbStoreImpl::Count(int64_t &outValue, const AbsRdbPredicates &predicates)
{
    LOG_DEBUG("RdbStoreImpl::Count on called.");
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildCountString(predicates);

    std::vector<ValueObject> bindArgs;
    std::vector<std::string> whereArgs = predicates.GetWhereArgs();
    for (const auto& whereArg : whereArgs) {
        bindArgs.emplace_back(whereArg);
    }

    return ExecuteAndGetLong(outValue, sql, bindArgs);
}

int RdbStoreImpl::ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errCode = CheckAttach(sql);
    if (errCode != E_OK) {
        return errCode;
    }

    SqliteConnection *connection;
    errCode = BeginExecuteSql(sql, &connection);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = connection->ExecuteSql(sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("RDB_STORE Execute SQL ERROR.");
        return errCode;
    }
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        errCode = connectionPool->ReOpenAvailableReadConnections();
    }
    return errCode;
}

int RdbStoreImpl::ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    SqliteConnection *connection;
    int errCode = BeginExecuteSql(sql, &connection);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = connection->ExecuteGetLong(outValue, sql, bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("RDB_STORE ExecuteAndGetLong ERROR is %{public}d.", errCode);
    }
    connectionPool->ReleaseConnection(connection);
    return errCode;
}

int RdbStoreImpl::ExecuteAndGetString(
    std::string &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    SqliteConnection *connection;
    int errCode = BeginExecuteSql(sql, &connection);
    if (errCode != E_OK) {
        return errCode;
    }
    connection->ExecuteGetString(outValue, sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    return errCode;
}

int RdbStoreImpl::ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteForLastInsertedRowId(outValue, sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    return errCode;
}

int RdbStoreImpl::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    int changeRow = 0;
    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteForChangedRowCount(changeRow, sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    outValue = changeRow;
    return errCode;
}

/**
 * Restores a database from a specified encrypted or unencrypted database file.
 */
int RdbStoreImpl::Backup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey)
{
    if (databasePath.empty()) {
        LOG_ERROR("Empty databasePath.");
        return E_INVALID_FILE_PATH;
    }
    std::string backupFilePath;
    if (ISFILE(databasePath)) {
        backupFilePath = ExtractFilePath(path) + databasePath;
    } else {
        if (!PathToRealPath(ExtractFilePath(databasePath), backupFilePath)) {
            LOG_ERROR("Invalid databasePath.");
            return E_INVALID_FILE_PATH;
        }
        backupFilePath = databasePath;
    }

    LOG_INFO("databasePath is %{public}s.", SqliteUtils::Anonymous(backupFilePath).c_str());

    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(backupFilePath));
    if (destEncryptKey.size() != 0) {
        bindArgs.push_back(ValueObject(destEncryptKey));
    } else {
        std::string str = "";
        bindArgs.push_back(ValueObject(str));
    }

    SqliteConnection *connection;

    std::string sql = GlobalExpr::ATTACH_BACKUP_SQL;
    int errCode = BeginExecuteSql(sql, &connection);
    if (errCode != 0) {
        return errCode;
    }
    errCode = connection->ExecuteSql(sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql ATTACH_BACKUP_SQL error %{public}d", errCode);
        return errCode;
    }

    int64_t count;
    sql = GlobalExpr::EXPORT_SQL;
    errCode = BeginExecuteSql(sql, &connection);
    if (errCode != 0) {
        return errCode;
    }
    errCode = connection->ExecuteGetLong(count, sql, std::vector<ValueObject>());
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql EXPORT_SQL error %{public}d", errCode);
        return errCode;
    }

    sql = GlobalExpr::DETACH_BACKUP_SQL;
    errCode = BeginExecuteSql(sql, &connection);
    if (errCode != 0) {
        return errCode;
    }
    errCode = connection->ExecuteSql(sql, std::vector<ValueObject>());
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql DETACH_BACKUP_SQL error %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int RdbStoreImpl::BeginExecuteSql(const std::string &sql, SqliteConnection **connection)
{
    int type = SqliteUtils::GetSqlStatementType(sql);
    if (SqliteUtils::IsSpecial(type)) {
        return E_TRANSACTION_IN_EXECUTE;
    }

    bool assumeReadOnly = SqliteUtils::IsSqlReadOnly(type);
    bool isReadOnly = false;
    *connection = connectionPool->AcquireConnection(assumeReadOnly);
    if (*connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = (*connection)->Prepare(sql, isReadOnly);
    if (errCode != 0) {
        connectionPool->ReleaseConnection(*connection);
        return errCode;
    }

    if (isReadOnly == (*connection)->IsWriteConnection()) {
        connectionPool->ReleaseConnection(*connection);
        *connection = connectionPool->AcquireConnection(isReadOnly);
        if (*connection == nullptr) {
            return E_CON_OVER_LIMIT;
        }

        if (!isReadOnly && !(*connection)->IsWriteConnection()) {
            LOG_ERROR("StoreSession BeginExecutea : read connection can not execute write operation");
            connectionPool->ReleaseConnection(*connection);
            return E_EXECUTE_WRITE_IN_READ_CONNECTION;
        }
    }

    return E_OK;
}
bool RdbStoreImpl::IsHoldingConnection()

{
    return connectionPool != nullptr;
}

int RdbStoreImpl::GiveConnectionTemporarily(int64_t milliseconds)
{
    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    if (connection->IsInTransaction()) {
        return E_STORE_SESSION_NOT_GIVE_CONNECTION_TEMPORARILY;
    }
    int errCode = BeginTransaction();
    if (errCode != E_OK) {
        return errCode;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    errCode = RollBack();
    if (errCode != E_OK) {
        return errCode;
    }

    return errCode;
}

/**
 * Attaches a database.
 */
int RdbStoreImpl::Attach(const std::string &alias, const std::string &pathName,
    const std::vector<uint8_t> destEncryptKey)
{
    SqliteConnection *connection;
    std::string sql = GlobalExpr::PRAGMA_JOUR_MODE_EXP;
    int errCode = BeginExecuteSql(sql, &connection);
    if (errCode != 0) {
        return errCode;
    }
    std::string journalMode;
    errCode = connection->ExecuteGetString(journalMode, sql, std::vector<ValueObject>());
    if (errCode != E_OK) {
        connectionPool->ReleaseConnection(connection);
        LOG_ERROR("RdbStoreImpl CheckAttach fail to get journal mode : %d", errCode);
        return errCode;
    }
    journalMode = SqliteUtils::StrToUpper(journalMode);
    if (journalMode == GlobalExpr::DEFAULT_JOURNAL_MODE) {
        connectionPool->ReleaseConnection(connection);
        LOG_ERROR("RdbStoreImpl attach is not supported in WAL mode");
        return E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE;
    }

    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(pathName));
    bindArgs.push_back(ValueObject(alias));
    if (destEncryptKey.size() != 0) {
        bindArgs.push_back(ValueObject(destEncryptKey));
    } else {
        std::string str = "";
        bindArgs.push_back(ValueObject(str));
    }
    sql = GlobalExpr::ATTACH_SQL;
    errCode = connection->ExecuteSql(sql, bindArgs);
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql ATTACH_SQL error %d", errCode);
    }

    return errCode;
}

/**
 * Obtains the database version.
 */
int RdbStoreImpl::GetVersion(int &version)
{
    int64_t value;
    int errCode = ExecuteAndGetLong(value, GlobalExpr::PRAGMA_VERSION, std::vector<ValueObject>());
    version = static_cast<int>(value);
    return errCode;
}

/**
 * Sets the version of a new database.
 */
int RdbStoreImpl::SetVersion(int version)
{
    std::string sql = std::string(GlobalExpr::PRAGMA_VERSION) + " = " + std::to_string(version);
    return ExecuteSql(sql, std::vector<ValueObject>());
}
/**
 * Begins a transaction in EXCLUSIVE mode.
 */
int RdbStoreImpl::BeginTransaction()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    BaseTransaction transaction(connectionPool->getTransactionStack().size());
    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteSql(transaction.GetTransactionStr());
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_DEBUG("storeSession BeginTransaction Failed");
        return errCode;
    }

    connection->SetInTransaction(true);
    connectionPool->getTransactionStack().push(transaction);
    return E_OK;
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::RollBack()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (connectionPool->getTransactionStack().empty()) {
        return E_NO_TRANSACTION_IN_SESSION;
    }
    BaseTransaction transaction = connectionPool->getTransactionStack().top();
    connectionPool->getTransactionStack().pop();
    if (transaction.GetType() != TransType::ROLLBACK_SELF && !connectionPool->getTransactionStack().empty()) {
        connectionPool->getTransactionStack().top().SetChildFailure(true);
    }
    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteSql(transaction.GetRollbackStr());
    connectionPool->ReleaseConnection(connection);
    if (connectionPool->getTransactionStack().empty()) {
        connection->SetInTransaction(false);
    }
    if (errCode != E_OK) {
        LOG_ERROR("RollBack Failed");
    }

    return E_OK;
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::Commit()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("Enter Commit.");
    if (connectionPool->getTransactionStack().empty()) {
        return E_OK;
    }
    BaseTransaction transaction = connectionPool->getTransactionStack().top();
    std::string sqlStr = transaction.GetCommitStr();
    if (sqlStr.size() <= 1) {
        connectionPool->getTransactionStack().pop();
        return E_OK;
    }

    SqliteConnection *connection = connectionPool->AcquireConnection(false);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = connection->ExecuteSql(sqlStr);
    connectionPool->ReleaseConnection(connection);
    connection->SetInTransaction(false);
    connectionPool->getTransactionStack().pop();
    if (errCode != E_OK) {
        LOG_ERROR("Commit Failed.");
    }
    return E_OK;
}

int RdbStoreImpl::FreeTransaction(SqliteConnection *connection, const std::string &sql)
{
    int errCode = connection->ExecuteSql(sql);
    if (errCode == E_OK) {
        connection->SetInTransaction(false);
        connectionPool->ReleaseTransaction();
    } else {
        LOG_ERROR("%{public}s with error code %{public}d.", sql.c_str(), errCode);
    }
    connectionPool->ReleaseConnection(connection);
    return errCode;
}

bool RdbStoreImpl::IsInTransaction()
{
    auto connection = connectionPool->AcquireConnection(false);
    if (connection != nullptr) {
        return connection->IsInTransaction();
    }
    return true;
}

int RdbStoreImpl::CheckAttach(const std::string &sql)
{
    size_t index = sql.find_first_not_of(' ');
    if (index == std::string::npos) {
        return E_OK;
    }

    /* The first 3 characters can determine the type */
    std::string sqlType = sql.substr(index, 3);
    sqlType = SqliteUtils::StrToUpper(sqlType);
    if (sqlType != "ATT") {
        return E_OK;
    }
    std::string journalMode;

    bool isRead = SqliteDatabaseUtils::BeginExecuteSql(GlobalExpr::PRAGMA_JOUR_MODE_EXP);
    SqliteConnection *connection = connectionPool->AcquireConnection(isRead);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }
    
    int errCode =
        connection->ExecuteGetString(journalMode, GlobalExpr::PRAGMA_JOUR_MODE_EXP, std::vector<ValueObject>());
    connectionPool->ReleaseConnection(connection);
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreImpl CheckAttach fail to get journal mode : %{public}d", errCode);
        return errCode;
    }

    journalMode = SqliteUtils::StrToUpper(journalMode);
    if (journalMode == GlobalExpr::DEFAULT_JOURNAL_MODE) {
        LOG_ERROR("RdbStoreImpl attach is not supported in WAL mode");
        return E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE;
    }

    return E_OK;
}

#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)

std::string RdbStoreImpl::ExtractFilePath(const std::string &fileFullName)
{
#ifdef WINDOWS_PLATFORM
    return std::string(fileFullName).substr(0, fileFullName.rfind("\\") + 1);
#else
    return std::string(fileFullName).substr(0, fileFullName.rfind("/") + 1);
#endif
}

bool RdbStoreImpl::PathToRealPath(const std::string &path, std::string &realPath)
{
    if (path.empty()) {
        LOG_ERROR("path is empty!");
        return false;
    }

    if ((path.length() >= PATH_MAX)) {
        LOG_ERROR("path len is error, the len is: [%{public}zu]", path.length());
        return false;
    }

    char tmpPath[PATH_MAX] = { 0 };
#ifdef WINDOWS_PLATFORM
    if (_fullpath(tmpPath, path.c_str(), PATH_MAX) == NULL) {
        LOG_ERROR("path to realpath error");
        return false;
    }
#else
    if (realpath(path.c_str(), tmpPath) == NULL) {
        LOG_ERROR("path (%{public}s) to realpath error", SqliteUtils::Anonymous(path).c_str());
        return false;
    }
#endif
    realPath = tmpPath;
    if (access(realPath.c_str(), F_OK) != 0) {
        LOG_ERROR("check realpath (%{public}s) error", SqliteUtils::Anonymous(realPath).c_str());
        return false;
    }
    return true;
}
#endif

bool RdbStoreImpl::IsOpen() const
{
    return isOpen;
}

std::string RdbStoreImpl::GetPath()
{
    return path;
}

std::string RdbStoreImpl::GetOrgPath()
{
    return orgPath;
}

bool RdbStoreImpl::IsReadOnly() const
{
    return isReadOnly;
}

bool RdbStoreImpl::IsMemoryRdb() const
{
    return isMemoryRdb;
}

std::string RdbStoreImpl::GetName()
{
    return name;
}
std::string RdbStoreImpl::GetFileType()
{
    return fileType;
}

#ifdef RDB_SUPPORT_ICU
/**
 * Sets the database locale.
 */
int RdbStoreImpl::ConfigLocale(const std::string localeStr)
{
    if (isOpen == false) {
        LOG_ERROR("The connection pool has been closed.");
        return E_ERROR;
    }

    if (connectionPool == nullptr) {
        LOG_ERROR("connectionPool is null");
        return E_ERROR;
    }
    return connectionPool->ConfigLocale(localeStr);
}
#endif

int RdbStoreImpl::Restore(const std::string backupPath, const std::vector<uint8_t> &newKey)
{
    return ChangeDbFileForRestore(path, backupPath, newKey);
}

/**
 * Restores a database from a specified encrypted or unencrypted database file.
 */
int RdbStoreImpl::ChangeDbFileForRestore(const std::string newPath, const std::string backupPath,
    const std::vector<uint8_t> &newKey)
{
    if (isOpen == false) {
        LOG_ERROR("ChangeDbFileForRestore:The connection pool has been closed.");
        return E_ERROR;
    }

    if (connectionPool == nullptr) {
        LOG_ERROR("ChangeDbFileForRestore:The connectionPool is null.");
        return E_ERROR;
    }
    if (newPath.empty() || backupPath.empty()) {
        LOG_ERROR("ChangeDbFileForRestore:Empty databasePath.");
        return E_INVALID_FILE_PATH;
    }
    std::string backupFilePath;
    std::string restoreFilePath;
    if (ISFILE(backupPath)) {
        backupFilePath = ExtractFilePath(path) + backupPath;
    } else {
        backupFilePath = backupPath;
    }
    if (access(backupFilePath.c_str(), F_OK) != E_OK) {
        LOG_ERROR("ChangeDbFileForRestore:The backupPath does not exists.");
        return E_INVALID_FILE_PATH;
    }

    if (ISFILE(newPath)) {
        restoreFilePath = ExtractFilePath(path) + newPath;
    } else {
        if (!PathToRealPath(ExtractFilePath(newPath), restoreFilePath)) {
            LOG_ERROR("ChangeDbFileForRestore:Invalid newPath.");
            return E_INVALID_FILE_PATH;
        }
        restoreFilePath = newPath;
    }
    if (backupFilePath == restoreFilePath) {
        LOG_ERROR("ChangeDbFileForRestore:The backupPath and newPath should not be same.");
        return E_INVALID_FILE_PATH;
    }
    if (backupFilePath == path) {
        LOG_ERROR("ChangeDbFileForRestore:The backupPath and path should not be same.");
        return E_INVALID_FILE_PATH;
    }

    int ret = connectionPool->ChangeDbFileForRestore(restoreFilePath, backupFilePath, newKey);
    if (ret == E_OK) {
        path = restoreFilePath;
    }
    return ret;
}

/**
 * Queries data in the database based on specified conditions.
 */
std::unique_ptr<ResultSet> RdbStoreImpl::QueryByStep(const std::string &sql,
    const std::vector<std::string> &selectionArgs)
{
    std::unique_ptr<ResultSet> resultSet = std::make_unique<StepResultSet>(connectionPool, sql, selectionArgs);
    return resultSet;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
int RdbStoreImpl::SetDistributedTables(const std::vector<std::string> &tables)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (tables.empty()) {
        LOG_WARN("The distributed tables to be set is empty.");
        return E_OK;
    }
    if (isEncrypt_) {
        bool status = false;
        RdbSecurityManager::GetInstance().GetKeyDistributedStatus(RdbSecurityManager::KeyFileType::PUB_KEY_FILE,
            status);
        if (!status) {
            RdbPassword key =
                RdbSecurityManager::GetInstance().GetRdbPassword(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
            syncerParam_.password_ = std::vector<uint8_t>(key.GetData(), key.GetData() + key.GetSize());
        }
    }

    std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
    int errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
    if (errCode != E_OK) {
        return errCode;
    }
    int32_t errorCode = service->SetDistributedTables(syncerParam_, tables);
    if (errorCode != E_OK) {
        LOG_ERROR("Fail to set distributed tables, error=%{public}d", errorCode);
        syncerParam_.password_.assign(syncerParam_.password_.size(), 0);
        syncerParam_.password_.clear();
        return errorCode;
    }

    if (isEncrypt_) {
        syncerParam_.password_.assign(syncerParam_.password_.size(), 0);
        syncerParam_.password_.clear();
        RdbSecurityManager::GetInstance().SetKeyDistributedStatus(
            RdbSecurityManager::KeyFileType::PUB_KEY_FILE, true);
    }
    return E_OK;
}

std::string RdbStoreImpl::ObtainDistributedTableName(const std::string &device, const std::string &table, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
    errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
    if (errCode != E_OK) {
        return "";
    }
    auto distTable = service->ObtainDistributedTableName(device, table);
    return distTable;
}

int RdbStoreImpl::Sync(const SyncOption &option, const AbsRdbPredicates &predicate, const SyncCallback &callback)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
    int errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
    if (errCode != E_OK) {
        LOG_ERROR("GetRdbService is failed, err is %{public}d.", errCode);
        return errCode;
    }
    errCode = service->Sync(syncerParam_, option, predicate.GetDistributedPredicates(), callback);
    if (errCode != E_OK) {
        LOG_ERROR("Sync is failed, err is %{public}d.", errCode);
        return errCode;
    }
    return E_OK;
}

int RdbStoreImpl::Subscribe(const SubscribeOption &option, RdbStoreObserver *observer)
{
    std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
    int errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->Subscribe(syncerParam_, option, observer);
}

int RdbStoreImpl::UnSubscribe(const SubscribeOption &option, RdbStoreObserver *observer)
{
    LOG_INFO("enter");
    std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
    int errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
    if (errCode != E_OK) {
        return errCode;
    }
    return service->UnSubscribe(syncerParam_, option, observer);
}

bool RdbStoreImpl::DropDeviceData(const std::vector<std::string> &devices, const DropOption &option)
{
    LOG_INFO("not implement");
    return true;
}
#endif
} // namespace OHOS::NativeRdb
