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
#include <unistd.h>
#include <vector>

#include "logger.h"
#include "rdb_errno.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

constexpr int32_t TRANSACTION_TIMEOUT(2);

std::shared_ptr<SqliteConnectionPool> SqliteConnectionPool::Create(const RdbStoreConfig &storeConfig, int &errCode)
{
    std::shared_ptr<SqliteConnectionPool> pool(new (std::nothrow) SqliteConnectionPool(storeConfig));
    if (pool == nullptr) {
        LOG_ERROR("SqliteConnectionPool::Create new failed, pool is nullptr");
        return nullptr;
    }
    errCode = pool->Init();
    if (errCode != E_OK) {
        return nullptr;
    }
    return pool;
}

SqliteConnectionPool::SqliteConnectionPool(const RdbStoreConfig& storeConfig)
    : config_(storeConfig), writers_(), readers_(), transactionStack_(), transactionUsed_(false)
{
}

int SqliteConnectionPool::Init()
{
    if (config_.GetRoleType() == OWNER) {
        auto errCode = writers_.Initialize(1, writeTimeout_, [this]() {
            int32_t errCode = E_OK;
            auto conn = SqliteConnection::Open(config_, true, errCode);
            return std::pair{ errCode, conn };
        });
        if (errCode != E_OK) {
            return errCode;
        }
    }

    maxReader_ = GetMaxReaders();
    // max read connect count is 64
    if (maxReader_ > 64) {
        return E_ARGS_READ_CON_OVERLOAD;
    }

    return readers_.Initialize(maxReader_, readTimeout_, [this]() {
        int32_t errCode = E_OK;
        auto conn = SqliteConnection::Open(config_, false, errCode);
        return std::pair{ errCode, conn };
    });
}

SqliteConnectionPool::~SqliteConnectionPool()
{
    CloseAllConnections();
}

int32_t SqliteConnectionPool::GetMaxReaders()
{
    if (config_.GetStorageMode() != StorageMode::MODE_MEMORY && config_.GetJournalMode() == "WAL") {
        return config_.GetReadConSize();
    } else {
        return 0;
    }
}

void SqliteConnectionPool::CloseAllConnections()
{
    writers_.Clear();
    readers_.Clear();
}

std::shared_ptr<SqliteConnection> SqliteConnectionPool::AcquireConnection(bool isReadOnly)
{
    Container *container = (isReadOnly && maxReader_ != 0) ? &readers_ : &writers_;
    auto node = container->Acquire();
    if (node == nullptr) {
        const char *header = (isReadOnly && maxReader_ != 0) ? "readers_" : "writers_";
        container->Dump(header);
        return nullptr;
    }
    auto conn = node->GetConnect();
    if (conn == nullptr) {
        return nullptr;
    }
    return std::shared_ptr<SqliteConnection>(conn.get(), [pool = weak_from_this(), node](SqliteConnection*) {
        auto realPool = pool.lock();
        if (realPool == nullptr) {
            return;
        }
        realPool->ReleaseNode(node);
    });
}

void SqliteConnectionPool::ReleaseNode(std::shared_ptr<ConnNode> node)
{
    if (node == nullptr) {
        return;
    }
    node->Unused();
    if (node->IsWriter()) {
        writers_.Release(node);
    } else {
        readers_.Release(node);
    }
}

int SqliteConnectionPool::AcquireTransaction()
{
    std::unique_lock<std::mutex> lock(transMutex_);
    if (transCondition_.wait_for(lock, std::chrono::seconds(TRANSACTION_TIMEOUT), [this] {
        return !transactionUsed_; })) {
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

int SqliteConnectionPool::RestartReaders()
{
    readers_.Clear();
    return readers_.Initialize(maxReader_, readTimeout_, [this]() {
        int32_t errCode = E_OK;
        auto conn = SqliteConnection::Open(config_, false, errCode);
        return std::pair{ errCode, conn };
    });
}

/**
 * The database locale.
 */
int SqliteConnectionPool::ConfigLocale(const std::string &localeStr)
{
    auto errCode = readers_.ConfigLocale(localeStr);
    if (errCode != E_OK) {
        return errCode;
    }
    return writers_.ConfigLocale(localeStr);
}

/**
 * Rename the backed up database.
 */
int SqliteConnectionPool::ChangeDbFileForRestore(const std::string &newPath, const std::string &backupPath,
    const std::vector<uint8_t> &newKey)
{
    if (!writers_.IsFull() || !readers_.IsFull()) {
        LOG_ERROR("Connection pool is busy now!");
        return E_ERROR;
    }

    CloseAllConnections();

    std::string currentPath = config_.GetPath();
    SqliteUtils::DeleteFile(currentPath);
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

SqliteConnectionPool::ConnNode::ConnNode(std::shared_ptr<SqliteConnection> conn) : connect_(std::move(conn)) {}

std::shared_ptr<SqliteConnection> SqliteConnectionPool::ConnNode::GetConnect()
{
    tid_ = gettid();
    time_ = std::chrono::steady_clock::now();
    return connect_;
}

int64_t SqliteConnectionPool::ConnNode::GetUsingTime() const
{
    auto time = std::chrono::steady_clock::now() - time_;
    return std::chrono::duration_cast<std::chrono::milliseconds>(time).count();
}

void SqliteConnectionPool::ConnNode::Unused()
{
    tid_ = 0;
    time_ = std::chrono::steady_clock::now();
    if (connect_ != nullptr) {
        connect_->DesFinalize();
        connect_->TryCheckPoint();
    }
}

bool SqliteConnectionPool::ConnNode::IsWriter() const
{
    if (connect_ != nullptr) {
        return connect_->IsWriteConnection();
    }
    return false;
}

int32_t SqliteConnectionPool::Container::Initialize(int32_t max, int32_t timeout, Creator creator)
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    for (int i = 0; i < max; ++i) {
        auto [error, conn] = creator();
        if (conn == nullptr) {
            nodes_.clear();
            details_.clear();
            return error;
        }
        auto node = std::make_shared<ConnNode>(conn);
        node->id_ = right_++;
        nodes_.push_back(node);
        details_.push_back(node);
    }
    max_ = max;
    count_ = max;
    timeout_ = std::chrono::seconds(timeout);
    return E_OK;
}

int32_t SqliteConnectionPool::Container::ConfigLocale(const std::string& locale)
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    if (max_ != count_) {
        return E_NO_ROW_IN_QUERY;
    }
    for (auto it = details_.begin(); it != details_.end(); ) {
        auto conn = it->lock();
        if (conn == nullptr || conn->connect_ == nullptr) {
            it = details_.erase(it);
            continue;
        }
        conn->connect_->ConfigLocale(locale);
    }
    return E_OK;
}

std::shared_ptr<SqliteConnectionPool::ConnNode> SqliteConnectionPool::Container::Acquire()
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    if (cond_.wait_for(lock, timeout_, [this] { return count_ > 0; })) {
        auto node = nodes_.back();
        nodes_.pop_back();
        count_--;
        return node;
    }
    return nullptr;
}

int32_t SqliteConnectionPool::Container::Release(std::shared_ptr<ConnNode> node)
{
    {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        if (node->id_ < left_ || node->id_ >= right_) {
            return E_OK;
        }
        nodes_.push_back(node);
        count_++;
    }
    cond_.notify_one();
    return E_OK;
}

int32_t SqliteConnectionPool::Container::Clear()
{
    std::list<std::shared_ptr<ConnNode>> nodes;
    std::list<std::weak_ptr<ConnNode>> details;
    {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        nodes = std::move(nodes_);
        details = std::move(details_);
        max_ = 0;
        count_ = 0;
        left_ = right_;
    }
    nodes.clear();
    details.clear();
    return 0;
}

bool SqliteConnectionPool::Container::IsFull()
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    return max_ == count_;
}

int32_t SqliteConnectionPool::Container::Dump(const char *header)
{
    std::string info;
    for (auto& detail : details_) {
        auto node = detail.lock();
        if (node == nullptr) {
            continue;
        }
        info.append("<")
            .append(std::to_string(node->id_))
            .append(",")
            .append(std::to_string(node->tid_))
            .append(",")
            .append(std::to_string(node->GetUsingTime()))
            .append(">");
        if (info.size() > 256) {
            LOG_WARN("%{public}s: %{public}s", header, info.c_str());
            info.clear();
        }
    }
    LOG_WARN("%{public}s: %{public}s", header, info.c_str());
    return 0;
}
} // namespace NativeRdb
} // namespace OHOS
