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
#define LOG_TAG "GdbConnPool"
#include "connection_pool.h"

#include <unistd.h>
#include <utility>

#include "aip_errors.h"
#include "gdb_utils.h"
#include "logger.h"
#include "rdb_store_config.h"

namespace OHOS::DistributedDataAip {
using namespace std::chrono;

std::shared_ptr<ConnectionPool> ConnectionPool::Create(const StoreConfig &config, int &errCode)
{
    std::shared_ptr<ConnectionPool> pool = std::make_shared<ConnectionPool>(config);
    if (pool == nullptr) {
        LOG_ERROR("ConnectionPool::Create new failed, pool is nullptr.");
        errCode = E_INIT_CONN_POOL_FAILED;
        return nullptr;
    }
    std::shared_ptr<Connection> conn;
    for (uint32_t retry = 0; retry < ITERS_COUNT; ++retry) {
        std::tie(errCode, conn) = pool->Init();
        if (errCode != E_GRD_DATA_CORRUPTED) {
            break;
        }
        config.SetIter(ITER_V1);
    }
    return errCode == E_OK ? pool : nullptr;
}

ConnectionPool::ConnectionPool(const StoreConfig &storeConfig) : config_(storeConfig), writers_(), readers_()
{
}

std::pair<int32_t, std::shared_ptr<Connection>> ConnectionPool::Init(bool isAttach, bool needWriter)
{
    std::pair<int32_t, std::shared_ptr<Connection>> result;
    auto &[errCode, conn] = result;
    config_.GenerateEncryptedKey();
    // write connect count is 1
    std::shared_ptr<ConnectionPool::ConnNode> node;
    std::tie(errCode, node) = writers_.Initialize(
        [this, isAttach]() { return Connection::Create(config_, true); }, 1, config_.GetWriteTime(), true, needWriter);
    conn = Convert2AutoConn(node);
    if (errCode != E_OK) {
        return result;
    }

    maxReader_ = GetMaxReaders(config_);
    LOG_DEBUG("ConnectionPool::Init maxReader=%{public}d", maxReader_);
    // max read connect count is 64
    if (maxReader_ > 64) {
        LOG_ERROR("maxReader is too big. maxReader=%{public}d", maxReader_);
        return { E_ARGS_READ_CON_OVERLOAD, nullptr };
    }
    auto [ret, nodeRead] = readers_.Initialize([this, isAttach]() { return Connection::Create(config_, false); },
        maxReader_, config_.GetReadTime(), maxReader_ == 0);
    errCode = ret;
    return result;
}

ConnectionPool::~ConnectionPool()
{
    LOG_DEBUG("enter");
    CloseAllConnections();
}

int32_t ConnectionPool::GetMaxReaders(const StoreConfig &config)
{
    return config.GetReadConSize();
}

std::shared_ptr<Connection> ConnectionPool::Convert2AutoConn(std::shared_ptr<ConnNode> node, bool isTrans)
{
    if (node == nullptr) {
        return nullptr;
    }

    auto conn = node->GetConnect();
    if (conn == nullptr) {
        return nullptr;
    }
    if (isTrans) {
        transCount_++;
    }

    return std::shared_ptr<Connection>(conn.get(), [pool = weak_from_this(), node, isTrans](auto *) mutable {
        auto realPool = pool.lock();
        if (realPool == nullptr) {
            return;
        }
        realPool->ReleaseNode(node, !isTrans);
        if (isTrans) {
            realPool->transCount_--;
        }
        node = nullptr;
    });
}

void ConnectionPool::CloseAllConnections()
{
    writers_.Clear();
    readers_.Clear();
}

std::shared_ptr<Connection> ConnectionPool::Acquire(bool isReadOnly, std::chrono::milliseconds ms)
{
    Container *container = (isReadOnly && maxReader_ != 0) ? &readers_ : &writers_;
    auto node = container->Acquire(ms);
    if (node == nullptr) {
        const char *header = (isReadOnly && maxReader_ != 0) ? "readers_" : "writers_";
        container->Dump(header, transCount_ + isInTransaction_);
        return nullptr;
    }
    return Convert2AutoConn(node);
}

std::shared_ptr<Connection> ConnectionPool::AcquireRef(bool isReadOnly, std::chrono::milliseconds ms)
{
    if (maxReader_ != 0) {
        return Acquire(isReadOnly, ms);
    }
    auto node = writers_.Acquire(ms);
    if (node == nullptr) {
        writers_.Dump("writers_", transCount_ + isInTransaction_);
        return nullptr;
    }
    auto conn = node->connect_;
    writers_.Release(node);
    return {conn.get(), [pool = weak_from_this(), conn](Connection *) {
        auto realPool = pool.lock();
        if (realPool == nullptr) {
            return;
        }
        realPool->writers_.cond_.notify_all();
    }};
}

void ConnectionPool::ReleaseNode(std::shared_ptr<ConnNode> node, bool reuse)
{
    if (node == nullptr) {
        return;
    }
    auto now = steady_clock::now();
    auto timeout = now > (failedTime_.load() + minutes(CHECK_POINT_INTERVAL)) || now < failedTime_.load() ||
                   failedTime_.load() == steady_clock::time_point();
    auto transCount = transCount_ + isInTransaction_;
    auto remainCount = reuse ? transCount : transCount - 1;
    auto errCode = node->Unused(remainCount, timeout);
    if (errCode == E_DATABASE_BUSY) {
        writers_.Dump("WAL writers_", transCount);
        readers_.Dump("WAL readers_", transCount);
    }
    LOG_DEBUG(
        "ConnectionPool::ReleaseNode reuse=%{public}d,timeout=%{public}d,remainCount=%{public}d,isWriter=%{public}d",
        reuse, timeout, remainCount, node->IsWriter());

    if (node->IsWriter() && errCode != E_NOT_SUPPORT) {
        failedTime_ = errCode != E_OK ? now : steady_clock::time_point();
    }

    auto &container = node->IsWriter() ? writers_ : readers_;
    if (reuse) {
        container.Release(node);
    } else {
        container.Drop(node);
    }
}

int ConnectionPool::RestartReaders()
{
    readers_.Clear();
    auto [errCode, node] = readers_.Initialize(
        [this]() { return Connection::Create(config_, false); }, maxReader_, config_.GetReadTime(), maxReader_ == 0);
    return errCode;
}

int32_t ConnectionPool::Dump(bool isWriter, const char *header)
{
    Container *container = (isWriter || maxReader_ == 0) ? &writers_ : &readers_;
    container->Dump(header, transCount_ + isInTransaction_);
    return E_OK;
}

ConnectionPool::ConnNode::ConnNode(std::shared_ptr<Connection> conn) : connect_(std::move(conn))
{
}

std::shared_ptr<Connection> ConnectionPool::ConnNode::GetConnect()
{
    tid_ = gettid();
    time_ = steady_clock::now();
    return connect_;
}

int64_t ConnectionPool::ConnNode::GetUsingTime() const
{
    auto time = steady_clock::now() - time_;
    return duration_cast<milliseconds>(time).count();
}

int32_t ConnectionPool::ConnNode::Unused(int32_t count, bool timeout)
{
    time_ = steady_clock::now();
    if (connect_ == nullptr) {
        return E_OK;
    }
    time_ = steady_clock::now();
    if (!connect_->IsWriter()) {
        tid_ = 0;
    }
    return E_OK;
}

bool ConnectionPool::ConnNode::IsWriter() const
{
    if (connect_ != nullptr) {
        return connect_->IsWriter();
    }
    return false;
}

std::pair<int32_t, std::shared_ptr<ConnectionPool::ConnNode>> ConnectionPool::Container::Initialize(
    Creator creator, int32_t max, int32_t timeout, bool disable, bool acquire)
{
    std::shared_ptr<ConnNode> connNode = nullptr;
    {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        disable_ = disable;
        max_ = max;
        creator_ = std::move(creator);
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

std::shared_ptr<ConnectionPool::ConnNode> ConnectionPool::Container::Acquire(std::chrono::milliseconds milliS)
{
    auto interval = (milliS == INVALID_TIME) ? timeout_ : milliS;
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    LOG_DEBUG("count %{public}d max %{public}d total %{public}d left %{public}d right%{public}d", count_, max_, total_,
        left_, right_);
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
        if (nodes_.empty()) {
            LOG_ERROR("nodes is empty.count %{public}d max %{public}d total %{public}d left %{public}d right%{public}d",
                count_, max_, total_, left_, right_);
            count_ = 0;
            return nullptr;
        }
        auto node = nodes_.back();
        nodes_.pop_back();
        count_--;
        return node;
    }
    return nullptr;
}

int32_t ConnectionPool::Container::ExtendNode()
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

void ConnectionPool::Container::Disable()
{
    disable_ = true;
    cond_.notify_one();
}

void ConnectionPool::Container::Enable()
{
    disable_ = false;
    cond_.notify_one();
}

int32_t ConnectionPool::Container::Release(std::shared_ptr<ConnNode> node)
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

int32_t ConnectionPool::Container::Drop(std::shared_ptr<ConnNode> node)
{
    {
        std::unique_lock<decltype(mutex_)> lock(mutex_);
        RelDetails(node);
    }
    cond_.notify_one();
    return E_OK;
}

int32_t ConnectionPool::Container::RelDetails(std::shared_ptr<ConnNode> node)
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

int32_t ConnectionPool::Container::Clear()
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
    LOG_DEBUG(
        "Container::Clear success count=%{public}d, max=%{public}d, total=%{public}d, left=%{public}d, "
        "right=%{public}d", count_, max_, total_, left_, right_);
    return 0;
}

bool ConnectionPool::Container::IsFull()
{
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    return total_ == count_;
}

int32_t ConnectionPool::Container::Dump(const char *header, int32_t count)
{
    std::string info;
    std::vector<std::shared_ptr<ConnNode>> details;
    std::string title = "B_M_T_C[" + std::to_string(count) + "," + std::to_string(max_) + "," +
                        std::to_string(total_) + "," + std::to_string(count_) + "]";
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
            LOG_WARN("%{public}s %{public}s:%{public}s", header, title.c_str(), info.c_str());
            info.clear();
        }
    }
    LOG_WARN("%{public}s %{public}s:%{public}s", header, title.c_str(), info.c_str());
    return 0;
}
} // namespace OHOS::DistributedDataAip