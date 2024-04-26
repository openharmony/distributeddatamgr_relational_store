/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "RdbConnectionPool"
#include "rdb_connection_pool.h"
#include "logger.h"
#include "rd_connection.h"
#include "sqlite_connection_pool.h"
#include "rdb_errno.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

RdbConnectionPool::RdbConnectionPool(const RdbStoreConfig &storeConfig) : transactionStack_(), config_(storeConfig)
{
}

int RdbConnectionPool::Init()
{
    std::unique_lock<std::mutex> lock(idleConnsMutex_);
    int errCode = E_OK;
    while (writeConnNum_ < DEFAULT_WRITE_CONN_NUM) {
        auto connection = RdConnection::Open(config_, true, errCode);
        if (connection == nullptr) {
            CloseAllConns();
            return errCode;
        }
        idleWriteConns_.push_back(connection);
        writeConnNum_++;
    }
    while (readConnNum_ < DEFAULT_READ_CONN_NUM) {
        auto connection = RdConnection::Open(config_, false, errCode);
        if (connection == nullptr) {
            CloseAllConns();
            return errCode;
        }
        idleReadConns_.push_back(connection);
        readConnNum_++;
    }
    return E_OK;
}

std::shared_ptr<RdbConnectionPool> RdbConnectionPool::Create(const RdbStoreConfig &storeConfig, int &errCode)
{
    std::shared_ptr<RdbConnectionPool> pool = std::make_shared<RdbConnectionPool>(storeConfig);
    if (pool == nullptr) {
        LOG_ERROR("RdbConnectionPool::Create new failed, pool is nullptr");
        return nullptr;
    }
    errCode = pool->Init();
    if (errCode != E_OK) {
        pool = nullptr;
        return nullptr;
    }
    return pool;
}

RdbConnectionPool::~RdbConnectionPool()
{
    CloseAllConns();
}

std::shared_ptr<RdbConnection> RdbConnectionPool::AcquireConnection(bool isReadOnly, int64_t trxId)
{
    return AcquireConnectionByTrxId(isReadOnly, trxId);
}

int RdbConnectionPool::RestartReaders()
{
    return E_NOT_SUPPORTED;
}

std::pair<std::shared_ptr<RdbConnection>, std::vector<std::shared_ptr<RdbConnection>>> RdbConnectionPool::AcquireAll(
    int32_t time)
{
    return {};
}

std::shared_ptr<RdbConnection> RdbConnectionPool::AcquireWriteConnByTrxId(int64_t trxId)
{
    if (trxId != 0) {
        auto it = trxConnMap_.find(trxId);
        if (it != trxConnMap_.end()) {
            return it->second;
        }
        return nullptr;
    }
    std::shared_ptr<RdbConnection> connection = nullptr;
    if (idleWriteConns_.empty()) {
        if (writeConnNum_ >= MAX_WRITE_CONN_NUM) {
            LOG_INFO("Open rdbConnection has exceed the limit");
            return nullptr;
        }
        int errCode = E_OK;
        connection = RdConnection::Open(config_, true, errCode);
        if (errCode != E_OK) {
            LOG_ERROR("Open rdbConnection ret %{public}d", errCode);
            return nullptr;
        }
        writeConnNum_++;
    } else {
        connection = idleWriteConns_.back();
        idleWriteConns_.pop_back();
    }
    if (trxId != 0) {
        trxConnMap_[trxId] = connection;
    }
    return connection;
}

std::shared_ptr<RdbConnection> RdbConnectionPool::AcquireReadConnByTrxId(int64_t trxId)
{
    if (trxId != 0) {
        LOG_ERROR("Read connection should not bind with transaction id");
        return nullptr;
    }
    std::shared_ptr<RdbConnection> connection = nullptr;
    if (idleReadConns_.empty()) {
        if (readConnNum_ >= MAX_READ_CONN_NUM) {
            LOG_WARN("Read connection is out of limit");
            return nullptr;
        }
        int errCode = E_OK;
        connection = RdbConnection::Open(config_, false, errCode);
        if (errCode != E_OK) {
            LOG_ERROR("Open rdbConnection ret %{public}d", errCode);
            return nullptr;
        }
        readConnNum_++;
    } else {
        connection = idleReadConns_.back();
        idleReadConns_.pop_back();
    }
    return connection;
}

std::shared_ptr<RdbConnection> RdbConnectionPool::AcquireNewConnection(bool isReadOnly, int64_t &trxId)
{
    std::shared_ptr<RdbConnection> conn = AcquireConnectionByTrxId(isReadOnly, 0);
    if (isReadOnly) {
        trxId = 0;
        return conn;
    }
    std::unique_lock<std::mutex> lock(idleConnsMutex_);
    if (trxConnMap_.find(newtrxId_) != trxConnMap_.end()) {
        LOG_ERROR("trxId has appeared before");
        conn = nullptr;
        return nullptr;
    }
    trxConnMap_[newtrxId_] = conn;
    trxId = newtrxId_;
    newtrxId_++;
    return conn;
}


std::shared_ptr<RdbConnection> RdbConnectionPool::AcquireConnectionByTrxId(bool isReadOnly, int64_t trxId)
{
    std::unique_lock<std::mutex> lock(idleConnsMutex_);
    return isReadOnly ? AcquireReadConnByTrxId(trxId) : AcquireWriteConnByTrxId(trxId);
}

void RdbConnectionPool::ReleaseConnection(std::shared_ptr<RdbConnection> rdbConnection, int64_t trxId)
{
    std::unique_lock<std::mutex> lock(idleConnsMutex_);
    if (rdbConnection->IsWriteConnection()) {
        if (trxId != 0) {
            if (trxConnMap_.find(trxId) == trxConnMap_.end()) {
                LOG_ERROR("RdbConnectionPool cannot find connection according to trxId");
                return;
            }
            trxConnMap_.erase(trxId);
        }
        if (writeConnNum_ >= MAX_WRITE_CONN_NUM) {
            rdbConnection = nullptr;
            --writeConnNum_;
            return;
        }
        idleWriteConns_.push_back(rdbConnection);
        return;
    }
    if (readConnNum_ >= MAX_READ_CONN_NUM) {
        rdbConnection = nullptr;
        --readConnNum_;
        return;
    }
    idleReadConns_.push_back(rdbConnection);
    return;
}

void RdbConnectionPool::CloseAllConns()
{
    std::unique_lock<std::mutex> lock(idleConnsMutex_);
    for (auto &item : idleWriteConns_) {
        item = nullptr;
    }
    for (auto &item : idleReadConns_) {
        item = nullptr;
    }
    idleReadConns_.clear();
}

int RdbConnectionPool::ConfigLocale(const std::string &localeStr)
{
    return E_NOT_SUPPORTED;
}

int RdbConnectionPool::ChangeDbFileForRestore(const std::string &newPath, const std::string &backupPath,
    const std::vector<uint8_t> &newKey)
    {
        return E_NOT_SUPPORTED;
    }

std::stack<BaseTransaction> &RdbConnectionPool::GetTransactionStack()
{
    return transactionStack_;
}

std::mutex &RdbConnectionPool::GetTransactionStackMutex()
{
    return transactionStackMutex_;
}

std::pair<int, std::shared_ptr<RdbConnection>> RdbConnectionPool::DisableWalMode()
{
    return {};
}

int RdbConnectionPool::AcquireTransaction()
{
    return 0;
}

void RdbConnectionPool::ReleaseTransaction()
{
    return;
}

int RdbConnectionPool::EnableWalMode()
{
    return 0;
}

void RdbConnectionPool::CloseAllConnections()
{
    return;
}

} // namespace NativeRdb
} // namespace OHOS
