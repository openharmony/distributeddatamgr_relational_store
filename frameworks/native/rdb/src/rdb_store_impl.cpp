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

#include <sstream>
#include <unistd.h>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_trace.h"
#include "sqlite_sql_builder.h"
#include "sqlite_utils.h"
#include "step_result_set.h"

#ifndef WINDOWS_PLATFORM
#include "directory_ex.h"
#endif

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "iresult_set.h"
#include "rdb_device_manager_adapter.h"
#include "rdb_manager.h"
#include "rdb_security_manager.h"
#include "relational_store_manager.h"
#include "result_set_proxy.h"
#include "runtime_config.h"
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
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    syncerParam_.bundleName_ = config.GetBundleName();
    syncerParam_.hapName_ = config.GetModuleName();
    syncerParam_.storeName_ = config.GetName();
    syncerParam_.area_ = config.GetArea();
    syncerParam_.level_ = static_cast<int32_t>(config.GetSecurityLevel());
    syncerParam_.type_ = config.GetDistributedType();
    syncerParam_.isEncrypt_ = config.IsEncrypt();
    syncerParam_.password_ = {};
    isEncrypt_ = config.IsEncrypt();
    // open uri share
    if (!config.GetUri().empty()) {
        std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
        errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
        if (errCode != E_OK) {
            LOG_ERROR("RdbStoreImpl::InnerOpen get service failed, err is %{public}d.", errCode);
            return errCode;
        }
        errCode = service->CreateRDBTable(syncerParam_, config.GetWritePermission(), config.GetReadPermission());
        if (errCode != E_OK) {
            LOG_ERROR("RdbStoreImpl::InnerOpen service CreateRDBTable failed, err is %{public}d.", errCode);
            return errCode;
        }
        isShared_ = true;
    }
#endif
    return E_OK;
}

RdbStoreImpl::RdbStoreImpl()
    : connectionPool(nullptr), isOpen(false), path(""), orgPath(""), isReadOnly(false), isMemoryRdb(false)
{
}

RdbStoreImpl::~RdbStoreImpl()
{
    delete connectionPool;
    threadMap.clear();
    idleSessions.clear();
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    if (isShared_) {
        std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
        int errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
        if (errCode != E_OK) {
            LOG_ERROR("RdbStoreImpl::~RdbStoreImpl get service failed, err is %{public}d.", errCode);
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
std::shared_ptr<StoreSession> RdbStoreImpl::GetThreadSession()
{
    std::thread::id tid = std::this_thread::get_id();
    std::lock_guard<std::mutex> lock(sessionMutex);

    auto iter = threadMap.find(tid);
    if (iter != threadMap.end()) {
        iter->second.second++; // useCount++
        return iter->second.first;
    }

    // get from idle stack
    std::shared_ptr<StoreSession> session;
    if (idleSessions.empty()) {
        session = std::make_shared<StoreSession>(*connectionPool);
    } else {
        session = idleSessions.back();
        idleSessions.pop_back();
    }

    threadMap.insert(std::make_pair(tid, std::make_pair(session, 1))); // useCount is 1
    return session;
}

void RdbStoreImpl::ReleaseThreadSession()
{
    std::thread::id tid = std::this_thread::get_id();
    std::lock_guard<std::mutex> lock(sessionMutex);

    auto iter = threadMap.find(tid);
    if (iter == threadMap.end()) {
        LOG_ERROR("RdbStoreImpl ReleaseThreadSession: no session found for the current thread");
        return;
    }
    int &useCount = iter->second.second;
    useCount--;
    if (useCount > 0) {
        return;
    }

    if (idleSessions.size() < MAX_IDLE_SESSION_SIZE) {
        idleSessions.push_back(iter->second.first);
    }
    threadMap.erase(iter);
}

int RdbStoreImpl::Insert(int64_t &outRowId, const std::string &table, const ValuesBucket &initialValues)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return InsertWithConflictResolution(outRowId, table, initialValues, ConflictResolution::ON_CONFLICT_NONE);
}

int RdbStoreImpl::BatchInsert(int64_t &outInsertNum, const std::string &table,
    const std::vector<ValuesBucket> &initialBatchValues)
{
    int errCode = BeginTransaction();
    if (errCode != E_OK) {
        LOG_ERROR("Begin transaction with error code %{public}d.", errCode);
        return errCode;
    }
    int64_t outRowId = 0;
    for (auto const &value : initialBatchValues) {
        ++outInsertNum;
        if (RdbStoreImpl::Insert(outRowId, table, value) != E_OK) {
            LOG_WARN("Roll back in batch insert.");
            outRowId = -1;
            outInsertNum = -1;
            return RollBack();
        }
    }

    return Commit();
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

    std::shared_ptr<StoreSession> session = GetThreadSession();
    errCode = session->ExecuteForLastInsertedRowId(outRowId, sql.str(), bindArgs);
    ReleaseThreadSession();
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

    std::shared_ptr<StoreSession> session = GetThreadSession();
    errCode = session->ExecuteForChangedRowCount(changedRows, sql.str(), bindArgs);
    ReleaseThreadSession();
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

    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->ExecuteForChangedRowCount(deletedRows, sql.str(), bindArgs);
    ReleaseThreadSession();
    return errCode;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
std::unique_ptr<AbsSharedResultSet> RdbStoreImpl::Query(
    const AbsRdbPredicates &predicates, const std::vector<std::string> columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreImpl::Query on called.");
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    return QuerySql(sql, selectionArgs);
}

std::unique_ptr<ResultSet> RdbStoreImpl::QueryByStep(
    const AbsRdbPredicates &predicates, const std::vector<std::string> columns)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreImpl::QueryByStep on called.");
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    return QueryByStep(sql, selectionArgs);
}

std::shared_ptr<ResultSet> RdbStoreImpl::RemoteQuery(const std::string &device, const AbsRdbPredicates &predicates,
    const std::vector<std::string> &columns, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreImpl::RemoteQuery on called.");
    std::vector<std::string> selectionArgs = predicates.GetWhereArgs();
    std::string sql = SqliteSqlBuilder::BuildQueryString(predicates, columns);
    std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
    errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreImpl::RemoteQuery get service failed, err is %{public}d.", errCode);
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
    auto resultSet = std::make_unique<SqliteSharedResultSet>(shared_from_this(), path, sql, selectionArgs);
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

    std::shared_ptr<StoreSession> session = GetThreadSession();
    errCode = session->ExecuteSql(sql, bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("RDB_STORE Execute SQL ERROR.");
        ReleaseThreadSession();
        return errCode;
    }
    int sqlType = SqliteUtils::GetSqlStatementType(sql);
    if (sqlType == SqliteUtils::STATEMENT_DDL) {
        if (connectionPool == nullptr) {
            LOG_ERROR("connectionPool is null");
            return E_ERROR;
        }
        errCode = connectionPool->ReOpenAvailableReadConnections();
    }
    ReleaseThreadSession();
    return errCode;
}

int RdbStoreImpl::ExecuteAndGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->ExecuteGetLong(outValue, sql, bindArgs);
    ReleaseThreadSession();
    return errCode;
}

int RdbStoreImpl::ExecuteAndGetString(
    std::string &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->ExecuteGetString(outValue, sql, bindArgs);
    ReleaseThreadSession();
    return errCode;
}

int RdbStoreImpl::ExecuteForLastInsertedRowId(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->ExecuteForLastInsertedRowId(outValue, sql, bindArgs);
    ReleaseThreadSession();
    return errCode;
}

int RdbStoreImpl::ExecuteForChangedRowCount(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int changeRow = 0;
    int errCode = session->ExecuteForChangedRowCount(changeRow, sql, bindArgs);
    outValue = changeRow;
    ReleaseThreadSession();
    return errCode;
}

/**
 * Restores a database from a specified encrypted or unencrypted database file.
 */
int RdbStoreImpl::Backup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey)
{
    if (databasePath.empty()) {
        LOG_ERROR("Backup:Empty databasePath.");
        return E_INVALID_FILE_PATH;
    }
    std::string backupFilePath;
    if (ISFILE(databasePath)) {
        backupFilePath = ExtractFilePath(path) + databasePath;
    } else {
        if (!PathToRealPath(ExtractFilePath(databasePath), backupFilePath)) {
            LOG_ERROR("Backup:Invalid databasePath.");
            return E_INVALID_FILE_PATH;
        }
        backupFilePath = databasePath;
    }
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->Backup(backupFilePath, destEncryptKey, isEncrypt_);
    ReleaseThreadSession();
    return errCode;
}

bool RdbStoreImpl::IsHoldingConnection()
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    return session->IsHoldingConnection();
}

int RdbStoreImpl::GiveConnectionTemporarily(int64_t milliseconds)
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    return session->GiveConnectionTemporarily(milliseconds);
}

/**
 * Attaches a database.
 */
int RdbStoreImpl::Attach(const std::string &alias, const std::string &pathName,
    const std::vector<uint8_t> destEncryptKey)
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->Attach(alias, pathName, destEncryptKey, isEncrypt_);
    ReleaseThreadSession();
    return errCode;
}

/**
 * Obtains the database version.
 */
int RdbStoreImpl::GetVersion(int &version)
{
    int64_t value;
    int errCode = ExecuteAndGetLong(value, "PRAGMA user_version;", std::vector<ValueObject>());
    version = static_cast<int>(value);
    return errCode;
}

/**
 * Sets the version of a new database.
 */
int RdbStoreImpl::SetVersion(int version)
{
    std::string sql = "PRAGMA user_version = " + std::to_string(version);
    return ExecuteSql(sql, std::vector<ValueObject>());
}

/**
 * Begins a transaction in EXCLUSIVE mode.
 */
int RdbStoreImpl::BeginTransaction()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->BeginTransaction();
    if (errCode != E_OK) {
        ReleaseThreadSession();
    }
    return errCode;
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::RollBack()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->RollBack();
    if (errCode != E_OK) {
        ReleaseThreadSession();
    }
    return errCode;
}

/**
* Begins a transaction in EXCLUSIVE mode.
*/
int RdbStoreImpl::Commit()
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("Enter Commit");
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->Commit();
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreImpl::Commit with error code %{public}d.", errCode);
        ReleaseThreadSession();
    }
    return errCode;
}

int RdbStoreImpl::BeginTransactionWithObserver(TransactionObserver *transactionObserver)
{
    transactionObserverStack.push(transactionObserver);
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->BeginTransaction(transactionObserver);
    if (errCode != E_OK) {
        ReleaseThreadSession();
    }
    return errCode;
}

int RdbStoreImpl::MarkAsCommit()
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->MarkAsCommit();
    ReleaseThreadSession();
    return errCode;
}

int RdbStoreImpl::EndTransaction()
{
    TransactionObserver *transactionObserver = nullptr;
    if (transactionObserverStack.size() > 0) {
        transactionObserver = transactionObserverStack.top();
        transactionObserverStack.pop();
    }

    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode = session->EndTransactionWithObserver(transactionObserver);
    // release the session got in EndTransaction()
    ReleaseThreadSession();
    // release the session got in BeginTransaction()
    ReleaseThreadSession();

    if (!transactionObserver) {
        delete transactionObserver;
    }

    return errCode;
}

bool RdbStoreImpl::IsInTransaction()
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    bool inTransaction = session->IsInTransaction();
    ReleaseThreadSession();
    return inTransaction;
}

std::shared_ptr<SqliteStatement> RdbStoreImpl::BeginStepQuery(
    int &errCode, const std::string sql, const std::vector<std::string> &bindArgs)
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    LOG_DEBUG("session connection count:%{public}d", session->GetConnectionUseCount());
    return session->BeginStepQuery(errCode, sql, bindArgs);
}

int RdbStoreImpl::EndStepQuery()
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int err = session->EndStepQuery();
    ReleaseThreadSession(); // release session got by EndStepQuery
    ReleaseThreadSession(); // release session got by BeginStepQuery
    return err;
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
    int errCode = ExecuteAndGetString(journalMode, "PRAGMA journal_mode", std::vector<ValueObject>());
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreImpl CheckAttach fail to get journal mode : %{public}d", errCode);
        return errCode;
    }

    journalMode = SqliteUtils::StrToUpper(journalMode);
    if (journalMode == "WAL") {
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
        LOG_ERROR("path to realpath error");
        return false;
    }
#endif
    realPath = tmpPath;
    if (access(realPath.c_str(), F_OK) != 0) {
        LOG_ERROR("check realpath (%{public}s) error", realPath.c_str());
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

int RdbStoreImpl::PrepareAndGetInfo(const std::string &sql, bool &outIsReadOnly, int &numParameters,
    std::vector<std::string> &columnNames)
{
    std::shared_ptr<StoreSession> session = GetThreadSession();

    int errCode = session->PrepareAndGetInfo(sql, outIsReadOnly, numParameters, columnNames);
    ReleaseThreadSession();
    return errCode;
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

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
int RdbStoreImpl::ExecuteForSharedBlock(int &rowNum, AppDataFwk::SharedBlock *sharedBlock, int startPos,
    int requiredPos, bool isCountAllRows, std::string sql, std::vector<ValueObject> &bindArgVec)
{
    std::shared_ptr<StoreSession> session = GetThreadSession();
    int errCode =
        session->ExecuteForSharedBlock(rowNum, sql, bindArgVec, sharedBlock, startPos, requiredPos, isCountAllRows);
    ReleaseThreadSession();
    return errCode;
}
#endif

/**
 * Queries data in the database based on specified conditions.
 */
std::unique_ptr<ResultSet> RdbStoreImpl::QueryByStep(const std::string &sql,
    const std::vector<std::string> &selectionArgs)
{
    std::unique_ptr<ResultSet> resultSet =
        std::make_unique<StepResultSet>(shared_from_this(), sql, selectionArgs);
    return resultSet;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
int RdbStoreImpl::SetDistributedTables(const std::vector<std::string> &tables)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
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
        LOG_DEBUG("GetRdbService failed, err is %{public}d.", errCode);
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

    LOG_ERROR("success");
    return E_OK;
}

std::string RdbStoreImpl::ObtainDistributedTableName(
    const std::string &device, const std::string &table, int &errCode)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));

    std::string uuid;
    DeviceManagerAdaptor::RdbDeviceManagerAdaptor &deviceManager =
        DeviceManagerAdaptor::RdbDeviceManagerAdaptor::GetInstance(syncerParam_.bundleName_);
    errCode = deviceManager.GetEncryptedUuidByNetworkId(device, uuid);
    if (errCode != E_OK) {
        LOG_ERROR("GetUuid is failed");
        return "";
    }

    auto translateCall = [uuid](const std::string &oriDevId, const DistributedDB::StoreInfo &info) {
        return uuid;
    };
    DistributedDB::RuntimeConfig::SetTranslateToDeviceIdCallback(translateCall);

    return DistributedDB::RelationalStoreManager::GetDistributedTableName(uuid, table);
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
        LOG_ERROR("GetRdbService is failed, err is %{public}d.", errCode);
        return errCode;
    }
    return service->Subscribe(syncerParam_, option, observer);
}

int RdbStoreImpl::UnSubscribe(const SubscribeOption &option, RdbStoreObserver *observer)
{
    std::shared_ptr<DistributedRdb::RdbService> service = nullptr;
    int errCode = DistributedRdb::RdbManager::GetRdbService(syncerParam_, service);
    if (errCode != E_OK) {
        LOG_ERROR("GetRdbService is failed, err is %{public}d.", errCode);
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