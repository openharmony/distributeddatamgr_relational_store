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
    : config_(storeConfig), writeConnection_(nullptr), writeConnectionUsed_(true), readConnections_(),
      readConnectionCount_(0), idleReadConnectionCount_(0), transactionStack_(), transactionUsed_(false)
{
}

int SqliteConnectionPool::Init()
{
    int errCode = E_OK;
    writeConnection_ = SqliteConnection::Open(config_, true, errCode);
    if (writeConnection_ == nullptr) {
        return errCode;
    }

    InitReadConnectionCount();

    // max read connect count is 64
    if (readConnectionCount_ > 64) {
        return E_ARGS_READ_CON_OVERLOAD;
    }
    for (int i = 0; i < readConnectionCount_; i++) {
        auto connection = SqliteConnection::Open(config_, false, errCode);
        if (connection == nullptr) {
            CloseAllConnections();
            return errCode;
        }
        readConnections_.push_back(connection);
    }

    writeConnectionUsed_ = false;
    idleReadConnectionCount_ = readConnectionCount_;
    return E_OK;
}

SqliteConnectionPool::~SqliteConnectionPool()
{
    CloseAllConnections();
}

void SqliteConnectionPool::InitReadConnectionCount()
{
    if (config_.GetStorageMode() == StorageMode::MODE_MEMORY) {
        readConnectionCount_ = 0;
    } else if (config_.GetJournalMode() == "WAL") {
        readConnectionCount_ = config_.GetReadConSize();
    } else {
        readConnectionCount_ = 0;
    }
}

void SqliteConnectionPool::CloseAllConnections()
{
    writeConnection_ = nullptr;
    writeConnectionUsed_ = true;

    for (auto &item : readConnections_) {
        item = nullptr;
    }
    readConnections_.clear();
    idleReadConnectionCount_ = 0;
}

std::shared_ptr<SqliteConnection> SqliteConnectionPool::AcquireConnection(bool isReadOnly)
{
    if (isReadOnly && readConnectionCount_ != 0) {
        return AcquireReadConnection();
    } else {
        return AcquireWriteConnection();
    }
}

void SqliteConnectionPool::ReleaseConnection(std::shared_ptr<SqliteConnection> connection)
{
    if (connection == nullptr) {
        return;
    }
    connection->DesFinalize();
    if (connection == writeConnection_) {
        connection->LimitWalSize();
        ReleaseWriteConnection();
    } else {
        ReleaseReadConnection(connection);
    }
}

std::shared_ptr<SqliteConnection> SqliteConnectionPool::AcquireWriteConnection()
{
    std::unique_lock<std::mutex> lock(writeMutex_);
    if (writeCondition_.wait_for(lock, WAIT_CONNECT_TIMEOUT, [this] { return !writeConnectionUsed_; })) {
        writeConnectionUsed_ = true;
        return writeConnection_;
    }
    LOG_WARN("writeConnection_ is %{public}d",  writeConnectionUsed_);
    return nullptr;
}

int SqliteConnectionPool::AcquireTransaction()
{
    std::unique_lock<std::mutex> lock(transMutex_);
    if (transCondition_.wait_for(lock, WAIT_CONNECT_TIMEOUT, [this] { return !transactionUsed_; })) {
        transactionUsed_ = true;
        return E_OK;
    }
    LOG_WARN("transactionUsed_ is %{public}d", transactionUsed_);
    return E_TRANSACTION_IN_EXECUTE;
}

void SqliteConnectionPool::ReleaseTransaction()
{
    {
        std::unique_lock<std::mutex> lock(transMutex_);
        transactionUsed_ = false;
    }
    transCondition_.notify_one();
}

void SqliteConnectionPool::ReleaseWriteConnection()
{
    {
        std::unique_lock<std::mutex> lock(writeMutex_);
        writeConnectionUsed_ = false;
    }
    writeCondition_.notify_one();
}

/**
 * get last element from connectionPool
 * @return
 */
std::shared_ptr<SqliteConnection> SqliteConnectionPool::AcquireReadConnection()
{
    std::unique_lock<std::mutex> lock(readMutex_);
    if (readCondition_.wait_for(lock, WAIT_CONNECT_TIMEOUT, [this] { return idleReadConnectionCount_ > 0; })) {
        auto connection = readConnections_.back();
        readConnections_.pop_back();
        idleReadConnectionCount_--;
        return connection;
    }
    LOG_WARN("readConnectionCount_ is %{public}d, idleReadConnectionCount_ is %{public}d", readConnectionCount_,
        idleReadConnectionCount_);
    return nullptr;
}

/**
 * push connection back to last of connectionPool
 * @param connection
 */
void SqliteConnectionPool::ReleaseReadConnection(std::shared_ptr<SqliteConnection> connection)
{
    {
        std::unique_lock<std::mutex> lock(readMutex_);
        readConnections_.push_back(connection);
        idleReadConnectionCount_++;
    }
    readCondition_.notify_one();
}

int SqliteConnectionPool::InnerReOpenReadConnections()
{
    int errCode = E_OK;
    for (auto &item : readConnections_) {
        item = nullptr;
    }
    readConnections_.clear();

    for (int i = 0; i < readConnectionCount_; i++) {
        auto connection = SqliteConnection::Open(config_, false, errCode);
        if (connection == nullptr) {
            CloseAllConnections();
            return errCode;
        }
        readConnections_.push_back(connection);
    }

    return errCode;
}


int SqliteConnectionPool::ReOpenAvailableReadConnections()
{
    std::unique_lock<std::mutex> lock(readMutex_);
    return InnerReOpenReadConnections();
}

#ifdef RDB_SUPPORT_ICU
/**
 * The database locale.
 */
int SqliteConnectionPool::ConfigLocale(const std::string localeStr)
{
    std::unique_lock<std::mutex> lock(rdbMutex_);
    if (idleReadConnectionCount_ != readConnectionCount_) {
        return E_NO_ROW_IN_QUERY;
    }

    for (int i = 0; i < idleReadConnectionCount_; i++) {
        auto connection = readConnections_[i];
        if (connection == nullptr) {
            LOG_ERROR("Read Connection is null.");
            return E_ERROR;
        }
        connection->ConfigLocale(localeStr);
    }

    if (writeConnection_ == nullptr) {
        LOG_ERROR("Write Connection is null.");
        return E_ERROR;
    } else {
        writeConnection_->ConfigLocale(localeStr);
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
    if (writeConnectionUsed_ == true || idleReadConnectionCount_ != readConnectionCount_) {
        LOG_ERROR("Connection pool is busy now!");
        return E_ERROR;
    }

    LOG_ERROR("restore.");
    CloseAllConnections();

    std::string currentPath = config_.GetPath();
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

std::stack<BaseTransaction> &SqliteConnectionPool::GetTransactionStack()
{
    return transactionStack_;
}

std::mutex &SqliteConnectionPool::GetTransactionStackMutex()
{
    return transactionStackMutex_;
}
} // namespace NativeRdb
} // namespace OHOS
