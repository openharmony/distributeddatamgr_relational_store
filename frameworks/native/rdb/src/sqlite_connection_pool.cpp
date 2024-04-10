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
#define LOG_TAG "SqliteConnectionPool"
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
#include "rdb_common.h"
#include "rdb_errno.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Conn = Connection;
using ConnPool = SqliteConnectionPool;
using SharedConn = std::shared_ptr<Connection>;
using SharedConns = std::vector<std::shared_ptr<Connection>>;

constexpr int32_t TRANSACTION_TIMEOUT(2);
constexpr int USE_COUNT_MAX = 2;

std::atomic<RebuiltType> ConnPool::rebuild_ = RebuiltType::NONE;

std::shared_ptr<ConnPool> ConnPool::Create(const RdbStoreConfig &storeConfig, int &errCode)
{
    std::shared_ptr<ConnPool> pool(new (std::nothrow) ConnPool(storeConfig));
    if (pool == nullptr) {
        LOG_ERROR("ConnPool::Create new failed, pool is nullptr");
        return nullptr;
    }
    errCode = pool->Init();
    if (errCode == E_DATABASE_CORRUPT) {
        if (!storeConfig.GetAllowRebuild()) {
            LOG_WARN("DB corrupt but not allow rebuild");
            return nullptr;
        }
        errCode = RebuildDBInner(pool);
    }
    if (errCode != E_OK) {
        return nullptr;
    }
    return pool;
}

ConnPool::SqliteConnectionPool(const RdbStoreConfig &storeConfig)
    : config_(storeConfig), writers_(), readers_(), transactionStack_(), transactionUsed_(false)
{
}

int ConnPool::Init()
{
    if (config_.GetRoleType() == OWNER) {
        // write connect count is 1
        auto errCode = writers_.Initialize(1, config_.GetWriteTime(), [this]() {
            auto [errCode, conn] = Connection::Create(config_, true);
            return std::pair{ errCode, conn };
        });
        if (errCode != E_OK) {
            return errCode;
        }
    }

    maxReader_ = GetMaxReaders(config_);
    // max read connect count is 64
    if (maxReader_ > 64) {
        return E_ARGS_READ_CON_OVERLOAD;
    }
    return readers_.Initialize(maxReader_, config_.GetReadTime(), [this]() {
        return Connection::Create(config_, false);
    });
}

ConnPool::~SqliteConnectionPool()
{
    CloseAllConnections();
}

int32_t ConnPool::GetMaxReaders(const RdbStoreConfig &config)
{
    if (config.GetStorageMode() != StorageMode::MODE_MEMORY &&
        config.GetJournalMode() == GlobalExpr::JOURNAL_MODE_WAL) {
        return config.GetReadConSize();
    } else {
        return 0;
    }
}

void ConnPool::CloseAllConnections()
{
    writers_.Clear();
    readers_.Clear();
}

bool ConnPool::IsInTransaction()
{
    return isInTransaction_.load();
}

void ConnPool::SetInTransaction(bool isInTransaction)
{
    isInTransaction_.store(isInTransaction);
}

std::shared_ptr<Conn> ConnPool::AcquireConnection(bool isReadOnly)
{
    return Acquire(isReadOnly);
}

std::pair<SharedConn, SharedConns> ConnPool::AcquireAll(int32_t time)
{
    using namespace std::chrono;
    std::pair<SharedConn, SharedConns> result;
    auto &[writer, readers] = result;
    auto interval = duration_cast<milliseconds>(seconds(time));
    auto start = steady_clock::now();
    writer = Acquire(false, interval);
    auto usedTime = duration_cast<milliseconds>(steady_clock::now() - start);
    if (writer == nullptr || usedTime >= interval) {
        return {};
    }
    for (int i = 0; i < maxReader_; ++i) {
        auto conn = Acquire(true, interval - usedTime);
        usedTime = duration_cast<milliseconds>(steady_clock::now() - start);
        if (conn == nullptr || usedTime >= interval) {
            return {};
        }
        auto realConn = AcquireByID(conn->GetId());
        if (realConn && realConn.use_count() > USE_COUNT_MAX) {
            return {};
        }
        readers.emplace_back(conn);
    }

    return result;
}

std::shared_ptr<Connection> ConnPool::Acquire(bool isReadOnly, std::chrono::milliseconds ms)
{
    Container *container = (isReadOnly && maxReader_ != 0) ? &readers_ : &writers_;
    auto node = container->Acquire(ms);
    if (node == nullptr) {
        const char *header = (isReadOnly && maxReader_ != 0) ? "readers_" : "writers_";
        container->Dump(header);
        return nullptr;
    }
    auto conn = node->GetConnect();
    if (conn == nullptr) {
        return nullptr;
    }
    return std::shared_ptr<Connection>(conn.get(), [pool = weak_from_this(), node](Connection*) {
        auto realPool = pool.lock();
        if (realPool == nullptr) {
            return;
        }
        realPool->ReleaseNode(node);
    });
}

std::shared_ptr<Conn> ConnPool::AcquireByID(int32_t id)
{
    Container *container = (maxReader_ != 0) ? &readers_ : &writers_;
    auto node = container->AcquireById(id);
    if (node == nullptr) {
        const char *header = (maxReader_ != 0) ? "readers_" : "writers_";
        container->Dump(header);
        return nullptr;
    }
    auto conn = node->GetConnect(true);
    if (conn == nullptr) {
        return nullptr;
    }
    return conn;
}

void ConnPool::ReleaseNode(std::shared_ptr<ConnNode> node)
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

int ConnPool::AcquireTransaction()
{
    std::unique_lock<std::mutex> lock(transMutex_);
    if (transCondition_.wait_for(lock, std::chrono::seconds(TRANSACTION_TIMEOUT), [this] {
            return !transactionUsed_;
        })) {
        transactionUsed_ = true;
        return E_OK;
    }
    LOG_WARN("transactionUsed_ is %{public}d", transactionUsed_);
    return E_DATABASE_BUSY;
}

void ConnPool::ReleaseTransaction()
{
    {
        std::unique_lock<std::mutex> lock(transMutex_);
        transactionUsed_ = false;
    }
    transCondition_.notify_one();
}

RebuiltType ConnPool::GetRebuildType()
{
    return rebuild_.load();
}

int ConnPool::RestartReaders()
{
    readers_.Clear();
    return readers_.Initialize(maxReader_, config_.GetReadTime(), [this]() {
        return Connection::Create(config_, false);
    });
}

/**
 * The database locale.
 */
int ConnPool::ConfigLocale(const std::string &localeStr)
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
int ConnPool::ChangeDbFileForRestore(
    const std::string &newPath, const std::string &backupPath, const std::vector<uint8_t> &newKey)
{
    if (!writers_.IsFull() || !readers_.IsFull()) {
        LOG_ERROR("Connection pool is busy now!");
        return E_ERROR;
    }

    CloseAllConnections();
    RemoveDBFile();

    if (config_.GetPath() != newPath) {
        RemoveDBFile(newPath);
    }

    int retVal = SqliteUtils::RenameFile(backupPath, newPath);
    if (retVal != E_OK) {
        LOG_ERROR("RenameFile error");
        return retVal;
    }

    return Init();
}

std::stack<BaseTransaction> &ConnPool::GetTransactionStack()
{
    return transactionStack_;
}

std::mutex &ConnPool::GetTransactionStackMutex()
{
    return transactionStackMutex_;
}

std::pair<int32_t, std::shared_ptr<Conn>> ConnPool::DisableWal()
{
    auto [errCode, node] = writers_.Initialize(1, config_.GetWriteTime(), true, [this]() {
        RdbStoreConfig config = config_;
        config.SetJournalMode(JournalMode::MODE_TRUNCATE);
        maxReader_ = GetMaxReaders(config);
        return Connection::Create(config, true);
    });
    if (errCode != E_OK) {
        return { errCode, nullptr };
    }
    auto conn = node->GetConnect();
    if (conn == nullptr) {
        return { E_ERROR, nullptr };
    }
    auto result =
        std::shared_ptr<Conn>(conn.get(), [pool = weak_from_this(), hold = node](Conn *) {
            auto realPool = pool.lock();
            if (realPool == nullptr) {
                return;
            }
            realPool->ReleaseNode(hold);
        });
    return { E_OK, std::move(result) };
}

int ConnPool::EnableWal()
{
    CloseAllConnections();
    auto errCode = Init();
    return errCode;
}

ConnPool::ConnNode::ConnNode(std::shared_ptr<Conn> conn) : connect_(std::move(conn)) {}

std::shared_ptr<Conn> ConnPool::ConnNode::GetConnect(bool justHold)
{
    if (!justHold) {
        tid_ = gettid();
        time_ = std::chrono::steady_clock::now();
    }
    return connect_;
}

int64_t ConnPool::ConnNode::GetUsingTime() const
{
    auto time = std::chrono::steady_clock::now() - time_;
    return std::chrono::duration_cast<std::chrono::milliseconds>(time).count();
}

void ConnPool::ConnNode::Unused()
{
    tid_ = 0;
    time_ = std::chrono::steady_clock::now();
    if (connect_ != nullptr) {
        connect_->TryCheckPoint();
    }
}

bool ConnPool::ConnNode::IsWriter() const
{
    if (connect_ != nullptr) {
        return connect_->IsWriter();
    }
    return false;
}

int32_t ConnPool::Container::Initialize(int32_t max, int32_t timeout, Creator creator)
{
    auto [errCode, node] = Initialize(max, timeout, false, std::move(creator));
    return errCode;
}

std::pair<int32_t, std::shared_ptr<ConnPool::ConnNode>> ConnPool::Container::Initialize(
    int32_t max, int32_t timeout, bool needAcquire, Creator creator)
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    for (int i = 0; i < max; ++i) {
        auto [error, conn] = creator();
        if (conn == nullptr) {
            nodes_.clear();
            details_.clear();
            return { error, nullptr };
        }
        auto node = std::make_shared<ConnNode>(conn);
        node->id_ = right_++;
        conn->SetId(node->id_);
        nodes_.push_back(node);
        details_.push_back(node);
    }
    max_ = max;
    count_ = max;
    timeout_ = std::chrono::seconds(timeout);
    std::shared_ptr<ConnNode> connNode = nullptr;
    if (needAcquire) {
        connNode = nodes_.back();
        nodes_.pop_back();
        count_--;
    }
    return { E_OK, connNode };
}

int32_t ConnPool::Container::ConfigLocale(const std::string& locale)
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    if (max_ != count_) {
        return E_DATABASE_BUSY;
    }
    for (auto it = details_.begin(); it != details_.end();) {
        auto conn = it->lock();
        if (conn == nullptr || conn->connect_ == nullptr) {
            it = details_.erase(it);
            continue;
        }
        conn->connect_->ConfigLocale(locale);
    }
    return E_OK;
}

std::shared_ptr<ConnPool::ConnNode> ConnPool::Container::Acquire(std::chrono::milliseconds milliS)
{
    auto interval = (milliS == INVALID_TIME) ?  timeout_ : milliS;
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    if (cond_.wait_for(lock, interval, [this] { return count_ > 0; })) {
        auto node = nodes_.back();
        nodes_.pop_back();
        count_--;
        return node;
    }
    return nullptr;
}

std::shared_ptr<ConnPool::ConnNode> ConnPool::Container::AcquireById(int32_t id)
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    for (auto& detail : details_) {
        auto node = detail.lock();
        if (node == nullptr) {
            continue;
        }
        if (node->id_ == id) {
            return node;
        }
    }
    return nullptr;
}

int32_t ConnPool::Container::Release(std::shared_ptr<ConnNode> node)
{
    {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        if (node->id_ < left_ || node->id_ >= right_) {
            return E_OK;
        }
        nodes_.push_front(node);
        count_++;
    }
    cond_.notify_one();
    return E_OK;
}

int32_t ConnPool::Container::Clear()
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

bool ConnPool::Container::IsFull()
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    return max_ == count_;
}

int32_t ConnPool::Container::Dump(const char *header)
{
    std::string info;
    std::vector<std::shared_ptr<ConnNode>> details;
    {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        details.reserve(details_.size());
        for (auto& detail : details_) {
            auto node = detail.lock();
            if (node == nullptr) {
                continue;
            }
            details.push_back(node);
        }
    }

    for (auto& node : details) {
        info.append("<")
            .append(std::to_string(node->id_))
            .append(",")
            .append(std::to_string(node->tid_))
            .append(",")
            .append(std::to_string(node->GetUsingTime()))
            .append(">");
        // 256 represent that limit to info length
        if (info.size() > 256) {
            LOG_WARN("%{public}s: %{public}s", header, info.c_str());
            info.clear();
        }
    }
    LOG_WARN("%{public}s: %{public}s", header, info.c_str());
    return 0;
}

void ConnPool::RemoveDBFile()
{
    RemoveDBFile(config_.GetPath());
}

void ConnPool::RemoveDBFile(const std::string &path)
{
    SqliteUtils::DeleteFile(path);
    SqliteUtils::DeleteFile(path + "-shm");
    SqliteUtils::DeleteFile(path + "-wal");
    SqliteUtils::DeleteFile(path + "-journal");
}

int ConnPool::RebuildDBInner(std::shared_ptr<ConnPool> &pool)
{
    pool->RemoveDBFile();
    int errCode = pool->Init();
    if (errCode != E_OK) {
        LOG_ERROR("RebuildDB error %{public}d", errCode);
    } else {
        LOG_INFO("rebuild success");
        rebuild_.store(RebuiltType::REBUILT);
    }
    return errCode;
}
} // namespace NativeRdb
} // namespace OHOS
