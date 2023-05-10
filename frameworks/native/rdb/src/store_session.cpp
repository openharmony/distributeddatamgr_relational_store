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

#include "store_session.h"
#include <chrono>
#include <stack>
#include <thread>
#include "logger.h"
#include "rdb_errno.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "shared_block.h"
#include "rdb_security_manager.h"
#endif
#include "sqlite_database_utils.h"
#include "sqlite_utils.h"
#include "base_transaction.h"

namespace OHOS::NativeRdb {
StoreSession::StoreSession(SqliteConnectionPool &connectionPool)
    : connectionPool(connectionPool), readConnection(nullptr), connection(nullptr),
      readConnectionUseCount(0), connectionUseCount(0), isInStepQuery(false)
{
}

StoreSession::~StoreSession()
{
}

void StoreSession::AcquireConnection(bool isReadOnly)
{
    if (isReadOnly) {
        if (readConnection == nullptr) {
            readConnection = connectionPool.AcquireConnection(true);
        }
        readConnectionUseCount += 1;
        return;
    }
    if (connection == nullptr) {
        connection = connectionPool.AcquireConnection(false);
    }
    connectionUseCount += 1;
    return;
}

void StoreSession::ReleaseConnection(bool isReadOnly)
{
    if (isReadOnly) {
        if ((readConnection == nullptr) || (readConnectionUseCount <= 0)) {
            LOG_ERROR("SQLiteSession ReleaseConnection repeated release");
            return;
        }
        if (--readConnectionUseCount == 0) {
            connectionPool.ReleaseConnection(readConnection);
            readConnection = nullptr;
        }
        return;
    }
    if ((connection == nullptr) || (connectionUseCount <= 0)) {
        LOG_ERROR("SQLiteSession ReleaseConnection repeated release");
        return;
    }

    if (--connectionUseCount == 0) {
        connectionPool.ReleaseConnection(connection);
        connection = nullptr;
    }
}

int StoreSession::PrepareAndGetInfo(
    const std::string &sql, bool &outIsReadOnly, int &numParameters, std::vector<std::string> &columnNames)
{
    // Obtains the type of SQL statement.
    int type = SqliteUtils::GetSqlStatementType(sql);
    if (SqliteUtils::IsSpecial(type)) {
        return E_TRANSACTION_IN_EXECUTE;
    }
    bool assumeReadOnly = SqliteUtils::IsSqlReadOnly(type);
    AcquireConnection(assumeReadOnly);
    auto con = assumeReadOnly ? readConnection : connection;
    int errCode = con->PrepareAndGetInfo(sql, outIsReadOnly, numParameters, columnNames);
    if (errCode != 0) {
        ReleaseConnection(assumeReadOnly);
        return errCode;
    }

    ReleaseConnection(assumeReadOnly);
    return E_OK;
}

int StoreSession::BeginExecuteSql(const std::string &sql, bool &isReadOnly)
{
    int type = SqliteUtils::GetSqlStatementType(sql);
    if (SqliteUtils::IsSpecial(type)) {
        return E_TRANSACTION_IN_EXECUTE;
    }

    bool assumeReadOnly = SqliteUtils::IsSqlReadOnly(type);
    AcquireConnection(assumeReadOnly);
    SqliteConnection *con = assumeReadOnly ? readConnection : connection;
    int errCode = con->Prepare(sql, isReadOnly);
    if (errCode != 0) {
        ReleaseConnection(assumeReadOnly);
        return errCode;
    }

    if (isReadOnly == con->IsWriteConnection()) {
        ReleaseConnection(assumeReadOnly);
        AcquireConnection(isReadOnly);
        if (!isReadOnly && !con->IsWriteConnection()) {
            LOG_ERROR("StoreSession BeginExecute: read connection can not execute write operation");
            ReleaseConnection(isReadOnly);
            return E_EXECUTE_WRITE_IN_READ_CONNECTION;
        }
        return E_OK;
    }
    isReadOnly = assumeReadOnly;
    return E_OK;
}
int StoreSession::ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    bool isReadOnly = false;
    int errCode = BeginExecuteSql(sql, isReadOnly);
    if (errCode != 0) {
        return errCode;
    }
    SqliteConnection *con = isReadOnly ? readConnection : connection;
    errCode = con->ExecuteSql(sql, bindArgs);
    ReleaseConnection(isReadOnly);
    return errCode;
}

int StoreSession::ExecuteForChangedRowCount(
    int &changedRows, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    bool isReadOnly = false;
    int errCode = BeginExecuteSql(sql, isReadOnly);
    if (errCode != 0) {
        return errCode;
    }
    auto con = isReadOnly ? readConnection : connection;
    errCode = con->ExecuteForChangedRowCount(changedRows, sql, bindArgs);
    ReleaseConnection(isReadOnly);
    return errCode;
}

int StoreSession::ExecuteForLastInsertedRowId(
    int64_t &outRowId, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    bool isReadOnly = false;
    int errCode = BeginExecuteSql(sql, isReadOnly);
    if (errCode != 0) {
        LOG_ERROR("rdbStore BeginExecuteSql failed");
        return errCode;
    }
    auto con = isReadOnly ? readConnection : connection;
    errCode = con->ExecuteForLastInsertedRowId(outRowId, sql, bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("rdbStore ExecuteForLastInsertedRowId FAILED");
    }
    ReleaseConnection(isReadOnly);
    return errCode;
}

int StoreSession::ExecuteGetLong(int64_t &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    bool isReadOnly = false;
    int errCode = BeginExecuteSql(sql, isReadOnly);
    if (errCode != 0) {
        return errCode;
    }
    auto con = isReadOnly ? readConnection : connection;
    errCode = con->ExecuteGetLong(outValue, sql, bindArgs);
    ReleaseConnection(isReadOnly);
    return errCode;
}

int StoreSession::ExecuteGetString(
    std::string &outValue, const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    bool isReadOnly = false;
    int errCode = BeginExecuteSql(sql, isReadOnly);
    if (errCode != 0) {
        return errCode;
    }
    auto con = isReadOnly ? readConnection : connection;
    std::string sqlstr = sql;
    int type = SqliteDatabaseUtils::GetSqlStatementType(sqlstr);
    if (type == STATEMENT_PRAGMA) {
        ReleaseConnection(isReadOnly);
        AcquireConnection(false);
        con = connection;
    }

    errCode = con->ExecuteGetString(outValue, sql, bindArgs);
    ReleaseConnection(isReadOnly);
    return errCode;
}

int StoreSession::Backup(const std::string databasePath, const std::vector<uint8_t> destEncryptKey, bool isEncrypt)
{
    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(databasePath));
    if (destEncryptKey.size() != 0 && !isEncrypt) {
        bindArgs.push_back(ValueObject(destEncryptKey));
        ExecuteSql(CIPHER_DEFAULT_ATTACH_HMAC_ALGO);
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    } else if (isEncrypt) {
        std::vector<uint8_t> key;
        RdbPassword rdbPwd;
        rdbPwd = RdbSecurityManager::GetInstance().GetRdbPassword(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
        key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
        bindArgs.push_back(ValueObject(key));
        ExecuteSql(CIPHER_DEFAULT_ATTACH_HMAC_ALGO);
#endif
    } else {
        std::string str = "";
        bindArgs.push_back(ValueObject(str));
    }

    int errCode = ExecuteSql(ATTACH_BACKUP_SQL, bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql ATTACH_BACKUP_SQL error %{public}d", errCode);
        return errCode;
    }
    int64_t count;
    errCode = ExecuteGetLong(count, EXPORT_SQL, std::vector<ValueObject>());
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql EXPORT_SQL error %{public}d", errCode);
        return errCode;
    }

    errCode = ExecuteSql(DETACH_BACKUP_SQL, std::vector<ValueObject>());
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql DETACH_BACKUP_SQL error %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

// Checks whether this thread holds a database connection.
bool StoreSession::IsHoldingConnection() const
{
    if (connection == nullptr && readConnection == nullptr) {
        return false;
    } else {
        return true;
    }
}

int StoreSession::CheckNoTransaction() const
{
    int errorCode = 0;
    if (connectionPool.getTransactionStack().empty()) {
        errorCode = E_STORE_SESSION_NO_CURRENT_TRANSACTION;
        return errorCode;
    }
    return E_OK;
}

int StoreSession::GiveConnectionTemporarily(int64_t milliseconds)
{
    int errorCode = CheckNoTransaction();
    if (errorCode != E_OK) {
        return errorCode;
    }
    BaseTransaction transaction = connectionPool.getTransactionStack().top();
    if (transaction.IsMarkedSuccessful() || connectionPool.getTransactionStack().size() > 1) {
        errorCode = E_STORE_SESSION_NOT_GIVE_CONNECTION_TEMPORARILY;
        return errorCode;
    }

    MarkAsCommit();
    EndTransaction();
    if (milliseconds > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }
    BeginTransaction();
    return E_OK;
}

int StoreSession::Attach(
    const std::string &alias, const std::string &pathName, const std::vector<uint8_t> destEncryptKey, bool isEncrypt)
{
    std::string journalMode;
    int errCode = ExecuteGetString(journalMode, "PRAGMA journal_mode", std::vector<ValueObject>());
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreImpl CheckAttach fail to get journal mode : %{public}d", errCode);
        return errCode;
    }
    journalMode = SqliteUtils::StrToUpper(journalMode);
    if (journalMode == "WAL") {
        LOG_ERROR("RdbStoreImpl attach is not supported in WAL mode");
        return E_NOT_SUPPORTED_ATTACH_IN_WAL_MODE;
    }

    std::vector<ValueObject> bindArgs;
    bindArgs.push_back(ValueObject(pathName));
    bindArgs.push_back(ValueObject(alias));
    if (destEncryptKey.size() != 0 && !isEncrypt) {
        bindArgs.push_back(ValueObject(destEncryptKey));
        ExecuteSql(CIPHER_DEFAULT_ATTACH_HMAC_ALGO);
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    } else if (isEncrypt) {
        std::vector<uint8_t> key;
        RdbPassword rdbPwd;
        rdbPwd = RdbSecurityManager::GetInstance().GetRdbPassword(RdbSecurityManager::KeyFileType::PUB_KEY_FILE);
        key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
        bindArgs.push_back(ValueObject(key));
        ExecuteSql(CIPHER_DEFAULT_ATTACH_HMAC_ALGO);
#endif
    } else {
        std::string str = "";
        bindArgs.push_back(ValueObject(str));
    }
    errCode = ExecuteSql(ATTACH_SQL, bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("ExecuteSql ATTACH_SQL error %{public}d", errCode);
        return errCode;
    }

    return E_OK;
}

int StoreSession::BeginTransaction(TransactionObserver *transactionObserver)
{
    if (connectionPool.getTransactionStack().empty()) {
        AcquireConnection(false);

        int errCode = connection->ExecuteSql("BEGIN EXCLUSIVE;");
        if (errCode != E_OK) {
            ReleaseConnection(false);
            return errCode;
        }
    }

    if (transactionObserver != nullptr) {
        transactionObserver->OnBegin();
    }

    BaseTransaction transaction(connectionPool.getTransactionStack().size());
    connectionPool.getTransactionStack().push(transaction);

    return E_OK;
}

int StoreSession::MarkAsCommitWithObserver(TransactionObserver *transactionObserver)
{
    if (connectionPool.getTransactionStack().empty()) {
        return E_NO_TRANSACTION_IN_SESSION;
    }
    connectionPool.getTransactionStack().top().SetMarkedSuccessful(true);
    return E_OK;
}

int StoreSession::EndTransactionWithObserver(TransactionObserver *transactionObserver)
{
    if (connectionPool.getTransactionStack().empty()) {
        return E_NO_TRANSACTION_IN_SESSION;
    }

    BaseTransaction transaction = connectionPool.getTransactionStack().top();
    bool isSucceed = transaction.IsAllBeforeSuccessful() && transaction.IsMarkedSuccessful();
    connectionPool.getTransactionStack().pop();

    if (transactionObserver != nullptr) {
        if (isSucceed) {
            transactionObserver->OnCommit();
        } else {
            transactionObserver->OnRollback();
        }
    }

    if (!connectionPool.getTransactionStack().empty()) {
        if (transactionObserver != nullptr) {
            transactionObserver->OnRollback();
        }

        if (!isSucceed) {
            connectionPool.getTransactionStack().top().SetAllBeforeSuccessful(false);
        }
    } else {
        int errCode;
        if (connection == nullptr) {
            LOG_ERROR("connection is null");
            return E_ERROR;
        }
        if (isSucceed) {
            errCode = connection->ExecuteSql("COMMIT;");
        } else {
            errCode = connection->ExecuteSql("ROLLBACK;");
        }

        ReleaseConnection(false);
        return errCode;
    }

    return E_OK;
}

int StoreSession::MarkAsCommit()
{
    if (connectionPool.getTransactionStack().empty()) {
        return E_NO_TRANSACTION_IN_SESSION;
    }
    connectionPool.getTransactionStack().top().SetMarkedSuccessful(true);
    return E_OK;
}

int StoreSession::EndTransaction()
{
    if (connectionPool.getTransactionStack().empty()) {
        return E_NO_TRANSACTION_IN_SESSION;
    }

    BaseTransaction transaction = connectionPool.getTransactionStack().top();
    bool isSucceed = transaction.IsAllBeforeSuccessful() && transaction.IsMarkedSuccessful();
    connectionPool.getTransactionStack().pop();
    if (!connectionPool.getTransactionStack().empty()) {
        if (!isSucceed) {
            connectionPool.getTransactionStack().top().SetAllBeforeSuccessful(false);
        }
    } else {
        if (connection == nullptr) {
            LOG_ERROR("connection is null");
            return E_ERROR;
        }
        int errCode = connection->ExecuteSql(isSucceed ? "COMMIT;" : "ROLLBACK;");
        ReleaseConnection(false);
        return errCode;
    }

    return E_OK;
}
bool StoreSession::IsInTransaction() const
{
    return !connectionPool.getTransactionStack().empty();
}

std::shared_ptr<SqliteStatement> StoreSession::BeginStepQuery(
    int &errCode, const std::string &sql, const std::vector<std::string> &selectionArgs)
{
    if (isInStepQuery == true) {
        LOG_ERROR("StoreSession BeginStepQuery fail : begin more step query in one session !");
        errCode = E_MORE_STEP_QUERY_IN_ONE_SESSION;
        return nullptr; // fail,already in
    }

    if (SqliteUtils::GetSqlStatementType(sql) != SqliteUtils::STATEMENT_SELECT) {
        LOG_ERROR("StoreSession BeginStepQuery fail : not select sql !");
        errCode = E_EXECUTE_IN_STEP_QUERY;
        return nullptr;
    }

    AcquireConnection(true);
    std::shared_ptr<SqliteStatement> statement = readConnection->BeginStepQuery(errCode, sql, selectionArgs);
    if (statement == nullptr) {
        ReleaseConnection(true);
        return nullptr;
    }
    isInStepQuery = true;
    return statement;
}

int StoreSession::EndStepQuery()
{
    if (isInStepQuery == false) {
        return E_OK;
    }

    int errCode = readConnection->EndStepQuery();
    isInStepQuery = false;
    ReleaseConnection(true);
    return errCode;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
int StoreSession::ExecuteForSharedBlock(int &rowNum, std::string sql, const std::vector<ValueObject> &bindArgs,
    AppDataFwk::SharedBlock *sharedBlock, int startPos, int requiredPos, bool isCountAllRows)
{
    bool isReadOnly = false;
    int errCode = BeginExecuteSql(sql, isReadOnly);
    if (errCode != E_OK) {
        return errCode;
    }
    SqliteConnection *con = isReadOnly ? readConnection : connection;
    errCode =
        con->ExecuteForSharedBlock(rowNum, sql, bindArgs, sharedBlock, startPos, requiredPos, isCountAllRows);
    ReleaseConnection(isReadOnly);
    return errCode;
}
#endif

int StoreSession::BeginTransaction()
{
    AcquireConnection(false);

    BaseTransaction transaction(connectionPool.getTransactionStack().size());
    int errCode = connection->ExecuteSql(transaction.getTransactionStr());
    if (errCode != E_OK) {
        LOG_DEBUG("storeSession BeginTransaction Failed");
        ReleaseConnection(false);
        return errCode;
    }
    connectionPool.getTransactionStack().push(transaction);
    ReleaseConnection(false);
    return E_OK;
}

int StoreSession::Commit()
{
    if (connectionPool.getTransactionStack().empty()) {
        return E_OK;
    }
    BaseTransaction transaction = connectionPool.getTransactionStack().top();
    std::string sqlStr = transaction.getCommitStr();
    if (sqlStr.size() <= 1) {
        connectionPool.getTransactionStack().pop();
        return E_OK;
    }

    AcquireConnection(false);
    int errCode = connection->ExecuteSql(sqlStr);
    ReleaseConnection(false);
    if (errCode != E_OK) {
        // if error the transaction is leaving for rollback
        return errCode;
    }
    connectionPool.getTransactionStack().pop();
    return E_OK;
}

int StoreSession::RollBack()
{
    std::stack<BaseTransaction> transactionStack = connectionPool.getTransactionStack();
    if (transactionStack.empty()) {
        return E_NO_TRANSACTION_IN_SESSION;
    }
    BaseTransaction transaction = transactionStack.top();
    transactionStack.pop();
    if (transaction.getType() != TransType::ROLLBACK_SELF && !transactionStack.empty()) {
        transactionStack.top().setChildFailure(true);
    }
    AcquireConnection(false);
    int errCode = connection->ExecuteSql(transaction.getRollbackStr());
    ReleaseConnection(false);
    if (errCode != E_OK) {
        LOG_ERROR("storeSession RollBack Fail");
    }

    return errCode;
}

int StoreSession::GetConnectionUseCount()
{
    return connectionUseCount;
}
} // namespace OHOS::NativeRdb
