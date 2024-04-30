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

#ifndef NATIVE_RDB_SQLITE_CONNECTION_POOL_H
#define NATIVE_RDB_SQLITE_CONNECTION_POOL_H

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <iterator>
#include <list>
#include <memory>
#include <mutex>
#include <sstream>
#include <stack>
#include <vector>

#include "base_transaction.h"
#include "connection.h"
#include "rdb_common.h"
#include "rdb_store_config.h"
namespace OHOS {
namespace NativeRdb {
class SqliteConnectionPool : public std::enable_shared_from_this<SqliteConnectionPool> {
public:
    using SharedConn = std::shared_ptr<Connection>;
    using SharedConns = std::vector<SharedConn>;
    static constexpr std::chrono::milliseconds INVALID_TIME = std::chrono::milliseconds(0);
    static std::shared_ptr<SqliteConnectionPool> Create(const RdbStoreConfig &storeConfig, int &errCode);
    ~SqliteConnectionPool();
    SharedConn AcquireConnection(bool isReadOnly);
    SharedConn Acquire(bool isReadOnly, std::chrono::milliseconds ms = INVALID_TIME);
    // this interface is only provided for resultSet
    SharedConn AcquireRef(bool isReadOnly, std::chrono::milliseconds ms = INVALID_TIME);
    std::pair<SharedConn, SharedConns> AcquireAll(int32_t time);
    std::pair<int32_t, SharedConn> DisableWal();
    int32_t EnableWal();
    int RestartReaders();
    int ConfigLocale(const std::string &localeStr);
    int ChangeDbFileForRestore(const std::string &newPath, const std::string &backupPath,
        const std::vector<uint8_t> &newKey);
    std::stack<BaseTransaction> &GetTransactionStack();
    std::mutex &GetTransactionStackMutex();
    int AcquireTransaction();
    void ReleaseTransaction();
    void CloseAllConnections();
    bool IsInTransaction();
    void SetInTransaction(bool isInTransaction);

private:
    struct ConnNode {
        bool using_ = false;
        int32_t tid_ = 0;
        int32_t id_ = 0;
        std::chrono::steady_clock::time_point time_ = std::chrono::steady_clock::now();
        std::shared_ptr<Connection> connect_;

        explicit ConnNode(std::shared_ptr<Connection> conn);
        std::shared_ptr<Connection> GetConnect();
        int64_t GetUsingTime() const;
        bool IsWriter() const;
        void Unused();
    };

    struct Container {
        using Creator = std::function<std::pair<int32_t, std::shared_ptr<Connection>>()>;
        static constexpr int32_t MAX_RIGHT = 0x4FFFFFFF;
        bool disable_ = true;
        int max_ = 0;
        int total_ = 0;
        int count_ = 0;
        int32_t left_ = 0;
        int32_t right_ = 0;
        std::chrono::seconds timeout_;
        std::list<std::shared_ptr<ConnNode>> nodes_;
        std::list<std::weak_ptr<ConnNode>> details_;
        std::mutex mutex_;
        std::condition_variable cond_;
        Creator creator_ = nullptr;
        std::pair<int32_t, std::shared_ptr<ConnNode>> Initialize(Creator creator, int32_t max, int32_t timeout,
            bool disable, bool acquire = false);
        int32_t ConfigLocale(const std::string &locale);
        std::shared_ptr<ConnNode> Acquire(std::chrono::milliseconds milliS);
        std::list<std::shared_ptr<ConnNode>> AcquireAll(std::chrono::milliseconds milliS);

        void Disable();
        void Enable();
        int32_t Release(std::shared_ptr<ConnNode> node);
        int32_t Clear();
        bool IsFull();
        int32_t Dump(const char *header);

    private:
        int32_t ExtendNode();
        int32_t RelDetails(std::shared_ptr<ConnNode> node);
    };

    explicit SqliteConnectionPool(const RdbStoreConfig &storeConfig);
    std::pair<int32_t, std::shared_ptr<Connection>> Init(const RdbStoreConfig &config, bool needWriter = false);
    int32_t GetMaxReaders(const RdbStoreConfig &config);
    std::shared_ptr<Connection> Convert2AutoConn(std::shared_ptr<ConnNode> node);
    void ReleaseNode(std::shared_ptr<ConnNode> node);
    void RemoveDBFile();
    void RemoveDBFile(const std::string &path);

    static constexpr int LIMITATION = 1024;
    RdbStoreConfig config_;
    Container writers_;
    Container readers_;
    int32_t maxReader_ = 0;

    std::stack<BaseTransaction> transactionStack_;
    std::mutex transactionStackMutex_;
    std::condition_variable transCondition_;
    std::mutex transMutex_;
    bool transactionUsed_;
    std::atomic<bool> isInTransaction_ = false;
};

} // namespace NativeRdb
} // namespace OHOS
#endif
