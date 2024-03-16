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

#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>
#include <sstream>
#include <iostream>
#include <iterator>
#include <stack>
#include <list>
#include "rdb_store_config.h"
#include "sqlite_connection.h"
#include "base_transaction.h"
namespace OHOS {
namespace NativeRdb {
class SqliteConnectionPool : public std::enable_shared_from_this<SqliteConnectionPool> {
public:
    static std::shared_ptr<SqliteConnectionPool> Create(const RdbStoreConfig &storeConfig, int &errCode);
    ~SqliteConnectionPool();
    std::shared_ptr<SqliteConnection> AcquireConnection(bool isReadOnly);
    int RestartReaders();
    int ConfigLocale(const std::string &localeStr);
    int ChangeDbFileForRestore(const std::string &newPath, const std::string &backupPath,
        const std::vector<uint8_t> &newKey);
    std::stack<BaseTransaction> &GetTransactionStack();
    std::mutex &GetTransactionStackMutex();
    int AcquireTransaction();
    void ReleaseTransaction();
    std::shared_ptr<SqliteConnection> AcquireByID(int32_t id);
private:
    struct ConnNode {
        bool using_ = false;
        uint32_t tid_ = 0;
        uint32_t id_ = 0;
        std::chrono::steady_clock::time_point time_ = std::chrono::steady_clock::now();
        std::shared_ptr<SqliteConnection> connect_;

        explicit ConnNode(std::shared_ptr<SqliteConnection> conn);
        std::shared_ptr<SqliteConnection> GetConnect(bool justHold = false);
        int64_t GetUsingTime() const;
        bool IsWriter() const;
        void Unused();
    };

    struct Container {
        using Creator = std::function<std::pair<int32_t, std::shared_ptr<SqliteConnection>>()>;
        int max_ = 0;
        int count_ = 0;
        uint32_t left_ = 0;
        uint32_t right_ = 0;
        std::chrono::seconds timeout_;
        std::list<std::shared_ptr<ConnNode>> nodes_;
        std::list<std::weak_ptr<ConnNode>> details_;
        std::mutex mutex_;
        std::condition_variable cond_;
        int32_t Initialize(int32_t max, int32_t timeout, Creator creator);
        int32_t ConfigLocale(const std::string &locale);
        std::shared_ptr<ConnNode> Acquire();
        int32_t Release(std::shared_ptr<ConnNode> node);
        int32_t Clear();
        bool IsFull();
        int32_t Dump(const char *header);
        std::shared_ptr<SqliteConnectionPool::ConnNode> AcquireById(int32_t id);
    };

    explicit SqliteConnectionPool(const RdbStoreConfig &storeConfig);
    int Init();
    int32_t GetMaxReaders();
    void ReleaseNode(std::shared_ptr<ConnNode> node);
    void CloseAllConnections();

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
    int32_t writeTimeout_ = 2;
    int32_t readTimeout_ = 2;
};

} // namespace NativeRdb
} // namespace OHOS
#endif
