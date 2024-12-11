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
#define LOG_TAG "ConnectionPool"
#include "connection_pool.h"

#include <base_transaction.h>
#include <condition_variable>
#include <iterator>
#include <mutex>
#include <sstream>
#include <vector>

#include "connection.h"
#include "logger.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "rdb_sql_statistic.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
using Conn = Connection;
using ConnPool = ConnectionPool;
using SharedConn = std::shared_ptr<Connection>;
using SharedConns = std::vector<std::shared_ptr<Connection>>;
using SqlStatistic = DistributedRdb::SqlStatistic;
using Reportor = RdbFaultHiViewReporter;
constexpr int32_t TRANSACTION_TIMEOUT(2);

std::shared_ptr<ConnPool> ConnPool::Create(const RdbStoreConfig &config, int &errCode)
{
    std::shared_ptr<ConnPool> pool(new (std::nothrow) ConnPool(config));
    if (pool == nullptr) {
        LOG_ERROR("ConnPool::Create new failed, pool is nullptr.");
        errCode = E_ERROR;
        return nullptr;
    }
    std::shared_ptr<Connection> conn;
    for (uint32_t retry = 0; retry < ITERS_COUNT; ++retry) {
        std::tie(errCode, conn) = pool->Init();
        if (errCode != E_SQLITE_CORRUPT) {
            break;
        }
        config.SetIter(ITER_V1);
    }
    std::string dbPath;
    (void)SqliteGlobalConfig::GetDbPath(config, dbPath);
    LOG_INFO("code:%{public}d app[%{public}s:%{public}s] path[%{public}s] "
             "cfg[%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}d]"
             "%{public}s",
        errCode, config.GetBundleName().c_str(), config.GetModuleName().c_str(),
        SqliteUtils::Anonymous(dbPath).c_str(), config.GetDBType(), config.GetHaMode(), config.IsEncrypt(),
        config.GetArea(), config.GetSecurityLevel(), config.GetRoleType(), config.IsReadOnly(),
        Reportor::FormatBrief(Connection::Collect(config), SqliteUtils::Anonymous(config.GetName())).c_str());
    return errCode == E_OK ? pool : nullptr;
}

std::pair<RebuiltType, std::shared_ptr<ConnectionPool>> ConnPool::HandleDataCorruption(
    const RdbStoreConfig &storeConfig, int &errCode)
{
    std::pair<RebuiltType, std::shared_ptr<ConnectionPool>> result;
    auto &[rebuiltType, pool] = result;

    errCode = Connection::Repair(storeConfig);
    if (errCode == E_OK) {
        rebuiltType = RebuiltType::REPAIRED;
    } else if (storeConfig.GetAllowRebuild()) {
        Connection::Delete(storeConfig);
        rebuiltType = RebuiltType::REBUILT;
    } else if (storeConfig.IsEncrypt() && storeConfig.GetEncryptKey().empty()) {
        errCode = E_INVALID_SECRET_KEY;
        return result;
    } else {
        errCode = E_SQLITE_CORRUPT;
        return result;
    }
    pool = Create(storeConfig, errCode);
    if (errCode != E_OK) {
        LOG_WARN("Failed, type %{public}d db %{public}s encrypt %{public}d error %{public}d, errno",
            static_cast<uint32_t>(rebuiltType), SqliteUtils::Anonymous(storeConfig.GetName()).c_str(),
            storeConfig.IsEncrypt(), errCode, errno);
    } else {
        Reportor::ReportRestore(Reportor::Create(storeConfig, E_OK, "RestoreType:Rebuild"), false);
    }

    return result;
}

ConnPool::ConnectionPool(const RdbStoreConfig &storeConfig)
    : config_(storeConfig), attachConfig_(storeConfig), writers_(), readers_(), transactionStack_(),
      transactionUsed_(false)
{
    attachConfig_.SetJournalMode(JournalMode::MODE_TRUNCATE);
}

std::pair<int32_t, std::shared_ptr<Connection>> ConnPool::Init(bool isAttach, bool needWriter)
{
    const RdbStoreConfig &config = isAttach ? attachConfig_ : config_;
    std::pair<int32_t, std::shared_ptr<Connection>> result;
    auto &[errCode, conn] = result;
    errCode = config.Initialize();
    if (errCode != E_OK) {
        return result;
    }

    if ((config.GetRoleType() == OWNER || config.GetRoleType() == VISITOR_WRITE) && !config.IsReadOnly()) {
        // write connect count is 1
        std::shared_ptr<ConnPool::ConnNode> node;
        std::tie(errCode, node) = writers_.Initialize(
            [this, isAttach]() {
                const RdbStoreConfig &config = isAttach ? attachConfig_ : config_;
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
        [this, isAttach]() {
            const RdbStoreConfig &config = isAttach ? attachConfig_ : config_;
            return Connection::Create(config, false);
        },
        maxReader_, config.GetReadTime(), maxReader_ == 0);
    errCode = ret;
    return result;
}

ConnPool::~ConnectionPool()
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

std::shared_ptr<Connection> ConnPool::Convert2AutoConn(std::shared_ptr<ConnNode> node, bool isTrans)
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

std::pair<int32_t, std::shared_ptr<Connection>> ConnPool::CreateTransConn(bool limited)
{
    if (transCount_ >= MAX_TRANS && limited) {
        writers_.Dump("NO TRANS", transCount_ + isInTransaction_);
        return { E_DATABASE_BUSY, nullptr };
    }
    auto [errCode, node] = writers_.Create();
    return { errCode, Convert2AutoConn(node, true) };
}

std::shared_ptr<Conn> ConnPool::AcquireConnection(bool isReadOnly)
{
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_WAIT);
    return Acquire(isReadOnly);
}

std::pair<SharedConn, SharedConns> ConnPool::AcquireAll(int32_t time)
{
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_WAIT);
    using namespace std::chrono;
    std::pair<SharedConn, SharedConns> result;
    auto &[writer, readers] = result;
    auto interval = duration_cast<milliseconds>(seconds(time));
    auto start = steady_clock::now();
    auto writerNodes = writers_.AcquireAll(interval);
    if (writerNodes.empty()) {
        return {};
    }
    writer = Convert2AutoConn(writerNodes.front());

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
        container->Dump(header, transCount_ + isInTransaction_);
        return nullptr;
    }
    return Convert2AutoConn(node);
}

SharedConn ConnPool::AcquireRef(bool isReadOnly, std::chrono::milliseconds ms)
{
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_WAIT);
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
    return std::shared_ptr<Connection>(conn.get(), [pool = weak_from_this(), conn](Connection *) {
        auto realPool = pool.lock();
        if (realPool == nullptr) {
            return;
        }
        realPool->writers_.cond_.notify_all();
    });
}

void ConnPool::ReleaseNode(std::shared_ptr<ConnNode> node, bool reuse)
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
    if (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
        writers_.Dump("WAL writers_", transCount);
        readers_.Dump("WAL readers_", transCount);
    }

    if (node->IsWriter() && (errCode != E_INNER_WARNING && errCode != E_NOT_SUPPORT)) {
        failedTime_ = errCode != E_OK ? now : steady_clock::time_point();
    }

    auto &container = node->IsWriter() ? writers_ : readers_;
    if (reuse) {
        container.Release(node);
    } else {
        container.Drop(node);
    }
}

int ConnPool::AcquireTransaction()
{
    std::unique_lock<std::mutex> lock(transMutex_);
    if (transCondition_.wait_for(
        lock, std::chrono::seconds(TRANSACTION_TIMEOUT),
        [this] { return !transactionUsed_; })) {
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
        [this]() { return Connection::Create(config_, false); }, maxReader_, config_.GetReadTime(), maxReader_ == 0);
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
    const std::vector<uint8_t> &newKey, SlaveStatus &slaveStatus)
{
    if (!writers_.IsFull() || config_.GetPath() == backupPath || newPath == backupPath) {
        LOG_ERROR("Connection pool is busy now!");
        return E_ERROR;
    }
    if (config_.GetDBType() == DB_VECTOR) {
        CloseAllConnections();
        auto [retVal, conn] = Connection::Create(config_, false);
        if (retVal != E_OK) {
            LOG_ERROR("Create connection fail, errCode:%{public}d", retVal);
            return retVal;
        }

        retVal = conn->Restore(backupPath, newKey, slaveStatus);
        if (retVal != E_OK) {
            LOG_ERROR("Restore failed, errCode:0x%{public}x", retVal);
            return retVal;
        }

        conn = nullptr;
        auto initRes = Init();
        if (initRes.first != E_OK) {
            LOG_ERROR("Init fail, errCode:%{public}d", initRes.first);
            return initRes.first;
        }
        return retVal;
    }
    return RestoreMasterDb(newPath, backupPath, slaveStatus);
}

int ConnPool::RestoreMasterDb(const std::string &newPath, const std::string &backupPath, SlaveStatus &slaveStatus)
{
    if (SqliteUtils::IsSlaveDbName(backupPath) && config_.GetHaMode() == HAMode::MAIN_REPLICA) {
        auto connection = AcquireConnection(false);
        if (connection == nullptr) {
            return E_DATABASE_BUSY;
        }
        return connection->Restore(backupPath, {}, slaveStatus);
    }

    CloseAllConnections();
    int ret = Connection::Restore(config_, backupPath, newPath);
    int32_t errCode = E_OK;
    std::shared_ptr<Connection> pool;
    for (uint32_t retry = 0; retry < ITERS_COUNT; ++retry) {
        std::tie(errCode, pool) = Init();
        if (errCode == E_OK) {
            break;
        }
        if (errCode != E_SQLITE_CORRUPT || !config_.IsEncrypt()) {
            break;
        }
        config_.SetIter(ITER_V1);
    }
    if (errCode != E_OK) {
        CloseAllConnections();
        Connection::Delete(config_);
        std::tie(errCode, pool) = Init();
        LOG_WARN("Restore failed! rebuild res:%{public}d, path:%{public}s.", errCode,
            SqliteUtils::Anonymous(backupPath).c_str());
    }
    return ret == E_OK ? errCode : ret;
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
    return Init(true, true);
}

int ConnPool::EnableWal()
{
    auto [errCode, node] = Init();
    return errCode;
}

int32_t ConnectionPool::Dump(bool isWriter, const char *header)
{
    Container *container = (isWriter || maxReader_ == 0) ? &writers_ : &readers_;
    container->Dump(header, transCount_ + isInTransaction_);
    return E_OK;
}

ConnPool::ConnNode::ConnNode(std::shared_ptr<Conn> conn) : connect_(std::move(conn))
{
}

std::shared_ptr<Conn> ConnPool::ConnNode::GetConnect()
{
    tid_ = gettid();
    time_ = steady_clock::now();
    return connect_;
}

int64_t ConnPool::ConnNode::GetUsingTime() const
{
    auto time = steady_clock::now() - time_;
    return duration_cast<milliseconds>(time).count();
}

int32_t ConnPool::ConnNode::Unused(int32_t count, bool timeout)
{
    if (connect_ == nullptr) {
        return E_OK;
    }

    connect_->ClearCache();
    int32_t errCode = E_INNER_WARNING;
    if (count <= 0) {
        errCode = connect_->TryCheckPoint(timeout);
    }

    time_ = steady_clock::now();
    if (!connect_->IsWriter()) {
        tid_ = 0;
    }
    return errCode;
}

bool ConnPool::ConnNode::IsWriter() const
{
    if (connect_ != nullptr) {
        return connect_->IsWriter();
    }
    return false;
}

std::pair<int32_t, std::shared_ptr<ConnPool::ConnNode>> ConnPool::Container::Initialize(
    Creator creator, int32_t max, int32_t timeout, bool disable, bool acquire)
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
    std::unique_lock<decltype(mutex_)> lock(mutex_);
    auto interval = (milliS == INVALID_TIME) ? timeout_ : milliS;
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
            LOG_ERROR("Nodes is empty.count %{public}d max %{public}d total %{public}d left %{public}d right%{public}d",
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

std::pair<int32_t, std::shared_ptr<ConnPool::ConnNode>> ConnPool::Container::Create()
{
    if (creator_ == nullptr) {
        return { E_NOT_SUPPORT, nullptr };
    }

    auto [errCode, conn] = creator_();
    if (conn == nullptr) {
        return { errCode, nullptr };
    }

    auto node = std::make_shared<ConnNode>(conn);
    if (node == nullptr) {
        return { E_ERROR, nullptr };
    }
    node->id_ = MIN_TRANS_ID + trans_;
    conn->SetId(node->id_);
    details_.push_back(node);
    trans_++;
    return { E_OK, node };
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
    while (count < total_ && cond_.wait_until(lock, time, [this]() { return count_ > 0; })) {
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

bool ConnectionPool::CheckIntegrity(const std::string &dbPath)
{
    RdbStoreConfig config(config_);
    config.SetPath(dbPath);
    config.SetIntegrityCheck(IntegrityCheck::FULL);
    config.SetHaMode(HAMode::SINGLE);
    for (uint32_t retry = 0; retry < ITERS_COUNT; ++retry) {
        auto [ret, connection] = Connection::Create(config, true);
        if (ret == E_OK) {
            return true;
        }
        if (ret != E_SQLITE_CORRUPT || !config.IsEncrypt()) {
            break;
        }
        config.SetIter(ITER_V1);
    }
    return false;
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

int32_t ConnPool::Container::Dump(const char *header, int32_t count)
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
} // namespace NativeRdb
} // namespace OHOS
