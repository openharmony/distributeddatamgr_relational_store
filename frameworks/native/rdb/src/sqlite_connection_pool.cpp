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

#include "sqlite_connection_pool.h"

#include <base_transaction.h>

#include <condition_variable>
#include <iostream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <vector>

#include "logger.h"
#include "rdb_errno.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

constexpr std::chrono::seconds WAIT_CONNECT_TIMEOUT(1);

SqliteConnectionPool *SqliteConnectionPool::Create(const RdbStoreConfig &storeConfig, int &errCode)
{
    auto pool = new (std::nothrow) SqliteConnectionPool(storeConfig);
    if (pool == nullptr) {
        LOG_ERROR("SqliteConnectionPool::Create new failed, pool is nullptr");
        return nullptr;
    }
    errCode = pool->Init();
    if (errCode != E_OK) {
        delete pool;
        return nullptr;
    }
    return pool;
}

SqliteConnectionPool::SqliteConnectionPool(const RdbStoreConfig &storeConfig)
    : config(storeConfig), writeConnection(nullptr), writeConnectionUsed(true), readConnections(),
      readConnectionCount(0), idleReadConnectionCount(0), transactionStack(), transactionUsed(false)
{
}

int SqliteConnectionPool::Init()
{
    int errCode = E_OK;
    writeConnection = SqliteConnection::Open(config, true, errCode);
    if (writeConnection == nullptr) {
        return errCode;
    }

    InitReadConnectionCount();

    // max read connect count is 64
    if (readConnectionCount > 64) {
        return E_ARGS_READ_CON_OVERLOAD;
    }
    for (int i = 0; i < readConnectionCount; i++) {
        SqliteConnection *connection = SqliteConnection::Open(config, false, errCode);
        if (connection == nullptr) {
            CloseAllConnections();
            return errCode;
        }
        readConnections.push_back(connection);
    }

    writeConnectionUsed = false;
    idleReadConnectionCount = readConnectionCount;
    return E_OK;
}

SqliteConnectionPool::~SqliteConnectionPool()
{
    CloseAllConnections();
}

void SqliteConnectionPool::InitReadConnectionCount()
{
    if (config.GetStorageMode() == StorageMode::MODE_MEMORY) {
        readConnectionCount = 0;
    } else if (config.GetJournalMode() == "WAL") {
        readConnectionCount = config.GetReadConSize();
    } else {
        readConnectionCount = 0;
    }
}

void SqliteConnectionPool::CloseAllConnections()
{
    if (writeConnection != nullptr) {
        delete writeConnection;
    }
    writeConnection = nullptr;
    writeConnectionUsed = true;

    for (auto &item : readConnections) {
        if (item != nullptr) {
            delete item;
            item = nullptr;
        }
    }
    readConnections.clear();
    idleReadConnectionCount = 0;
}

SqliteConnection *SqliteConnectionPool::AcquireConnection(bool isReadOnly)
{
    if (isReadOnly && readConnectionCount != 0) {
        return AcquireReadConnection();
    } else {
        return AcquireWriteConnection();
    }
}
void SqliteConnectionPool::ReleaseConnection(SqliteConnection *connection)
{
    if (connection == nullptr) {
        return;
    }
    connection->DesFinalize();
    if (connection == writeConnection) {
        ReleaseWriteConnection();
    } else {
        ReleaseReadConnection(connection);
    }
}

SqliteConnection *SqliteConnectionPool::AcquireWriteConnection()
{
    std::unique_lock<std::mutex> lock(writeMutex);
    if (writeCondition.wait_for(lock, WAIT_CONNECT_TIMEOUT, [this] { return !writeConnectionUsed; })) {
        writeConnectionUsed = true;
        return writeConnection;
    }
    LOG_WARN("writeConnection is %{public}d",  writeConnectionUsed);
    return nullptr;
}

int SqliteConnectionPool::AcquireTransaction()
{
    std::unique_lock<std::mutex> lock(transMutex);
    if (transCondition.wait_for(lock, WAIT_CONNECT_TIMEOUT, [this] { return !transactionUsed; })) {
        transactionUsed = true;
        return E_OK;
    }
    LOG_WARN("transactionUsed is %{public}d", transactionUsed);
    return E_TRANSACTION_IN_EXECUTE;
}

void SqliteConnectionPool::ReleaseTransaction()
{
    {
        std::unique_lock<std::mutex> lock(transMutex);
        transactionUsed = false;
    }
    transCondition.notify_one();
}

void SqliteConnectionPool::ReleaseWriteConnection()
{
    {
        std::unique_lock<std::mutex> lock(writeMutex);
        writeConnectionUsed = false;
    }
    writeCondition.notify_one();
}

/**
 * get last element from connectionPool
 * @return
 */
SqliteConnection *SqliteConnectionPool::AcquireReadConnection()
{
    std::unique_lock<std::mutex> lock(readMutex);
    if (readCondition.wait_for(lock, WAIT_CONNECT_TIMEOUT, [this] { return idleReadConnectionCount > 0; })) {
        SqliteConnection *connection = readConnections.back();
        readConnections.pop_back();
        idleReadConnectionCount--;
        return connection;
    }
    LOG_WARN("readConnectionCount is %{public}d, idleReadConnectionCount is %{public}d", readConnectionCount,
        idleReadConnectionCount);
    return nullptr;
}

/**
 * push connection back to last of connectionPool
 * @param connection
 */
void SqliteConnectionPool::ReleaseReadConnection(SqliteConnection *connection)
{
    {
        std::unique_lock<std::mutex> lock(readMutex);
        readConnections.push_back(connection);
        idleReadConnectionCount++;
    }
    readCondition.notify_one();
}

int SqliteConnectionPool::InnerReOpenReadConnections()
{
    int errCode = E_OK;
    for (auto &item : readConnections) {
        if (item != nullptr) {
            delete item;
            item = nullptr;
        }
    }
    readConnections.clear();

    for (int i = 0; i < readConnectionCount; i++) {
        SqliteConnection *connection = SqliteConnection::Open(config, false, errCode);
        if (connection == nullptr) {
            CloseAllConnections();
            return errCode;
        }
        readConnections.push_back(connection);
    }

    return errCode;
}


int SqliteConnectionPool::ReOpenAvailableReadConnections()
{
    std::unique_lock<std::mutex> lock(readMutex);
    return InnerReOpenReadConnections();
}

#ifdef RDB_SUPPORT_ICU
/**
 * The database locale.
 */
int SqliteConnectionPool::ConfigLocale(const std::string localeStr)
{
    std::unique_lock<std::mutex> lock(rdbMutex);
    if (idleReadConnectionCount != readConnectionCount) {
        return E_NO_ROW_IN_QUERY;
    }

    for (int i = 0; i < idleReadConnectionCount; i++) {
        SqliteConnection *connection = readConnections[i];
        if (connection == nullptr) {
            LOG_ERROR("Read Connection is null.");
            return E_ERROR;
        }
        connection->ConfigLocale(localeStr);
    }

    if (writeConnection == nullptr) {
        LOG_ERROR("Write Connection is null.");
        return E_ERROR;
    } else {
        writeConnection->ConfigLocale(localeStr);
    }

    return E_OK;
}
#endif

/**
 * Rename the backed up database.
 */
int SqliteConnectionPool::ChangeDbFileForRestore(const std::string newPath, const std::string backupPath,
    const std::vector<uint8_t> &newKey)
{
    if (writeConnectionUsed == true || idleReadConnectionCount != readConnectionCount) {
        LOG_ERROR("Connection pool is busy now!");
        return E_ERROR;
    }

    LOG_ERROR("restore.");
    CloseAllConnections();

    std::string currentPath = config.GetPath();
    bool ret = SqliteUtils::DeleteFile(currentPath);
    if (ret == false) {
        LOG_ERROR("DeleteFile error");
    }
    SqliteUtils::DeleteFile(currentPath + "-shm");
    SqliteUtils::DeleteFile(currentPath + "-wal");
    SqliteUtils::DeleteFile(currentPath + "-journal");

    if (currentPath != newPath) {
        SqliteUtils::DeleteFile(newPath);
        SqliteUtils::DeleteFile(newPath + "-shm");
        SqliteUtils::DeleteFile(newPath + "-wal");
        SqliteUtils::DeleteFile(newPath + "-journal");
    }

    int retVal = SqliteUtils::RenameFile(backupPath, newPath);
    if (retVal != E_OK) {
        LOG_ERROR("RenameFile error");
        return retVal;
    }

    return Init();
}

std::stack<BaseTransaction> &SqliteConnectionPool::getTransactionStack()
{
    return transactionStack;
}
} // namespace NativeRdb
} // namespace OHOS
