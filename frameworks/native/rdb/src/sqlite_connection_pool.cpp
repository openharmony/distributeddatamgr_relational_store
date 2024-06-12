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
#include <iterator>
#include <mutex>
#include <sstream>
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

std::shared_ptr<ConnPool> ConnPool::Create(const RdbStoreConfig &storeConfig, int &errCode)
{
    std::shared_ptr<ConnPool> pool(new (std::nothrow) ConnPool(storeConfig));
    if (pool == nullptr) {
        LOG_ERROR("ConnPool::Create new failed, pool is nullptr");
        errCode = E_ERROR;
        return nullptr;
    }
    std::shared_ptr<Connection> conn;
    std::tie(errCode, conn) = pool->Init(storeConfig);
    return errCode == E_OK ? pool : nullptr;
}

ConnPool::SqliteConnectionPool(const RdbStoreConfig &storeConfig)
    : config_(storeConfig), writers_(), readers_(), transactionStack_(), transactionUsed_(false)
{
}

std::pair<int32_t, std::shared_ptr<Connection>> ConnPool::Init(const RdbStoreConfig &config, bool needWriter)
{
    std::pair<int32_t, std::shared_ptr<Connection>> result;
    auto &[errCode, conn] = result;
    if (config.GetRoleType() == OWNER) {
        // write connect count is 1
        std::shared_ptr<ConnPool::ConnNode> node;
        std::tie(errCode, node) = writers_.Initialize(
            [config]() {
                return Connection::Create(config, true);
            },
            1, config.GetWriteTime(), true, needWriter);
        conn = Convert2AutoConn(node);
        if (errCode != E_OK) {
            return result;
        }
    }

    maxReader_ = GetMaxReaders(config);
    // max read connect count is 64
    if (maxReader_ > 64) {
        return { E_ARGS_READ_CON_OVERLOAD, nullptr };
    }
    auto [ret, node] = readers_.Initialize(
        [config]() {
            return Connection::Create(config, false);
        },
        maxReader_, config.GetReadTime(), maxReader_ == 0);
    errCode = ret;
    return result;
}

ConnPool::~SqliteConnectionPool()
{
    CloseAllConnections();
}

int32_t ConnPool::GetMaxReaders(const RdbStoreConfig &config)
{
    if (config.GetStorageMode() != StorageMode::MODE_MEMORY &&
        config.GetJournalMode() == RdbStoreConfig::GetJournalModeValue(JournalMode::MODE_WAL)) {
        return config.GetReadConSize();
    } else {
        return 0;
    }
}

std::shared_ptr<Connection> ConnPool::Convert2AutoConn(std::shared_ptr<ConnNode> node)
{
    if (node == nullptr) {
        return nullptr;
    }

    auto conn = node->GetConnect();
    if (conn == nullptr) {
        return nullptr;
    }
    return std::shared_ptr<Connection>(conn.get(), [pool = weak_from_this(), node](Connection *) {
        auto realPool = pool.lock();
        if (realPool == nullptr) {
            return;
        }
        realPool->ReleaseNode(node);
    });
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
    writer = Convert2AutoConn(writers_.AcquireAll(interval).front());

    auto usedTime = duration_cast<milliseconds>(steady_clock::now() - start);
    if (writer == nullptr || usedTime >= interval) {
        return {};
    }

    if (maxReader_ == 0) {
        return result;
    }

    readers_.Disable();
    auto nodes = readers_.AcquireAll(interval - usedTime);
    if (nodes.empty()) {
        readers_.Enable();
        return {};
    }

    for (auto node : nodes) {
        auto conn = Convert2AutoConn(node);
        if (conn == nullptr) {
            continue;
        }
        readers.push_back(conn);
    }
    return result;
}

std::shared_ptr<Conn> ConnPool::Acquire(bool isReadOnly, std::chrono::milliseconds ms)
{
    Container *container = (isReadOnly && maxReader_ != 0) ? &readers_ : &writers_;
    auto node = container->Acquire(ms);
    if (node == nullptr) {
        const char *header = (isReadOnly && maxReader_ != 0) ? "readers_" : "writers_";
        container->Dump(header);
        return nullptr;
    }
    return Convert2AutoConn(node);
}

SharedConn ConnPool::AcquireRef(bool isReadOnly, std::chrono::milliseconds ms)
{
    if (maxReader_ != 0) {
        return Acquire(isReadOnly, ms);
    }
    auto node = writers_.Acquire(ms);
    if (node == nullptr) {
        writers_.Dump("writers_");
        return nullptr;
    }
    auto conn = node->connect_;
    writers_.Release(node);
    return std::shared_ptr<Connection>(conn.get(), [pool = weak_from_this(), conn](Connection *) {
        auto realPool = pool.lock();
        if (realPool == nullptr) {
            return;
        }
        realPool->writers_.cond_.notify_all();
    });
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

int ConnPool::RestartReaders()
{
    readers_.Clear();
    auto [errCode, node] = readers_.Initialize(
        [this]() {
            return Connection::Create(config_, false);
        },
        maxReader_, config_.GetReadTime(), maxReader_ == 0);
    return errCode;
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
int ConnPool::ChangeDbFileForRestore(const std::string &newPath, const std::string &backupPath,
    const std::vector<uint8_t> &newKey)
{
    if (!writers_.IsFull() || config_.GetPath() == backupPath || newPath == backupPath) {
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

    auto [errCode, node] = Init(config_);
    return errCode;
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
    RdbStoreConfig config = config_;
    config.SetJournalMode(JournalMode::MODE_TRUNCATE);
    return Init(config, true);
}

int ConnPool::EnableWal()
{
    auto [errCode, node] = Init(config_);
    return errCode;
}

ConnPool::ConnNode::ConnNode(std::shared_ptr<Conn> conn) : connect_(std::move(conn))
{
}

std::shared_ptr<Conn> ConnPool::ConnNode::GetConnect()
{
    tid_ = gettid();
    time_ = std::chrono::steady_clock::now();
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
        connect_->ClearCache();
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

std::pair<int32_t, std::shared_ptr<ConnPool::ConnNode>> ConnPool::Container::Initialize(Creator creator, int32_t max,
    int32_t timeout, bool disable, bool acquire)
{
    std::shared_ptr<ConnNode> connNode = nullptr;
    {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        disable_ = disable;
        max_ = max;
        creator_ = creator;
        timeout_ = std::chrono::seconds(timeout);
        for (int i = 0; i < max; ++i) {
            auto errCode = ExtendNode();
            if (errCode != E_OK) {
                nodes_.clear();
                details_.clear();
                return { errCode, nullptr };
            }
        }

        if (acquire && count_ > 0) {
            connNode = nodes_.back();
            nodes_.pop_back();
            count_--;
        }
    }
    cond_.notify_all();
    return { E_OK, connNode };
}

int32_t ConnPool::Container::ConfigLocale(const std::string &locale)
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    if (total_ != count_) {
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
    auto interval = (milliS == INVALID_TIME) ? timeout_ : milliS;
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    if (max_ == 0) {
        return nullptr;
    }
    auto waiter = [this]() -> bool {
        if (count_ > 0) {
            return true;
        }

        if (disable_) {
            return false;
        }

        return ExtendNode() == E_OK;
    };
    if (cond_.wait_for(lock, interval, waiter)) {
        auto node = nodes_.back();
        nodes_.pop_back();
        count_--;
        return node;
    }
    return nullptr;
}

int32_t ConnPool::Container::ExtendNode()
{
    if (creator_ == nullptr) {
        return E_ERROR;
    }
    auto [errCode, conn] = creator_();
    if (conn == nullptr) {
        return errCode;
    }
    auto node = std::make_shared<ConnNode>(conn);
    node->id_ = right_++;
    conn->SetId(node->id_);
    nodes_.push_back(node);
    details_.push_back(node);
    count_++;
    total_++;
    return E_OK;
}

std::list<std::shared_ptr<ConnPool::ConnNode>> ConnPool::Container::AcquireAll(std::chrono::milliseconds milliS)
{
    std::list<std::shared_ptr<ConnNode>> nodes;
    int32_t count = 0;
    auto interval = (milliS == INVALID_TIME) ? timeout_ : milliS;
    auto time = std::chrono::steady_clock::now() + interval;
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    while (count < total_ && cond_.wait_until(lock, time, [this]() {
        return count_ > 0;
    })) {
        nodes.merge(std::move(nodes_));
        nodes_.clear();
        count += count_;
        count_ = 0;
    }

    if (count != total_) {
        count_ = count;
        nodes_ = std::move(nodes);
        nodes.clear();
        return nodes;
    }
    auto func = [](const std::list<std::shared_ptr<ConnNode>> &nodes) -> bool {
        for (auto &node : nodes) {
            if (node->connect_ == nullptr) {
                continue;
            }
            if (node->connect_.use_count() != 1) {
                return false;
            }
        }
        return true;
    };
    bool failed = false;
    while (failed = !func(nodes), failed && cond_.wait_until(lock, time) != std::cv_status::timeout) {
    }
    if (failed) {
        count_ = count;
        nodes_ = std::move(nodes);
        nodes.clear();
    }
    return nodes;
}

void ConnPool::Container::Disable()
{
    disable_ = true;
    cond_.notify_one();
}

void ConnPool::Container::Enable()
{
    disable_ = false;
    cond_.notify_one();
}

int32_t ConnPool::Container::Release(std::shared_ptr<ConnNode> node)
{
    {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        if (node->id_ < left_ || node->id_ >= right_) {
            return E_OK;
        }
        if (count_ == max_) {
            total_ = total_ > count_ ? total_ - 1 : count_;
            RelDetails(node);
        } else {
            nodes_.push_front(node);
            count_++;
        }
    }
    cond_.notify_one();
    return E_OK;
}

int32_t SqliteConnectionPool::Container::RelDetails(std::shared_ptr<ConnNode> node)
{
    for (auto it = details_.begin(); it != details_.end();) {
        auto detailNode = it->lock();
        if (detailNode == nullptr || detailNode->id_ == node->id_) {
            it = details_.erase(it);
        } else {
            it++;
        }
    }
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
        disable_ = true;
        total_ = 0;
        count_ = 0;
        if (right_ > MAX_RIGHT) {
            right_ = 0;
        }
        left_ = right_;
        creator_ = nullptr;
    }
    nodes.clear();
    details.clear();
    return 0;
}

bool ConnPool::Container::IsFull()
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    return total_ == count_;
}

int32_t ConnPool::Container::Dump(const char *header)
{
    std::string info;
    std::vector<std::shared_ptr<ConnNode>> details;
    {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        details.reserve(details_.size());
        for (auto &detail : details_) {
            auto node = detail.lock();
            if (node == nullptr) {
                continue;
            }
            details.push_back(node);
        }
    }

    for (auto &node : details) {
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
} // namespace NativeRdb
} // namespace OHOS
