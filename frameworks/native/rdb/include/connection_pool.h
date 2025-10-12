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
#include <cstdint>
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
#include "delay_actuator.h"
#include "rdb_common.h"
#include "rdb_store_config.h"

namespace OHOS {
class ExecutorPool;
namespace NativeRdb {
class ConnectionPool : public std::enable_shared_from_this<ConnectionPool> {
public:
    using SharedConn = std::shared_ptr<Connection>;
    using SharedConns = std::vector<SharedConn>;
    static constexpr std::chrono::milliseconds INVALID_TIME = std::chrono::milliseconds(0);
    static constexpr int32_t START_NODE_ID = -1;
    static std::shared_ptr<ConnectionPool> Create(const RdbStoreConfig &config, int &errCode);
    ~ConnectionPool();
    static std::pair<RebuiltType, std::shared_ptr<ConnectionPool>> HandleDataCorruption(
        const RdbStoreConfig &storeConfig, int &errCode);
    std::pair<int32_t, std::shared_ptr<Connection>> CreateTransConn(bool limited = true);
    SharedConn AcquireConnection(bool isReadOnly);
    SharedConn Acquire(bool isReadOnly, std::chrono::milliseconds ms = INVALID_TIME);
    // this interface is only provided for resultSet
    SharedConn AcquireRef(bool isReadOnly, std::chrono::milliseconds ms = INVALID_TIME);
    std::pair<SharedConn, SharedConns> AcquireAll(int32_t time);
    std::pair<int32_t, SharedConn> DisableWal();
    int32_t EnableWal();
    int32_t Dump(bool isWriter, const char *header);

    int32_t SetTokenizer(Tokenizer tokenizer);
    int RestartConns();
    int ReopenConns();
    int ConfigLocale(const std::string &localeStr);
    int ChangeDbFileForRestore(const std::string &newPath, const std::string &backupPath,
        const std::vector<uint8_t> &newKey, std::shared_ptr<SlaveStatus> slaveStatus);
    int Rekey(const RdbStoreConfig::CryptoParam &cryptoParam);
    std::stack<BaseTransaction> &GetTransactionStack();
    std::mutex &GetTransactionStackMutex();
    int AcquireTransaction();
    void ReleaseTransaction();
    void CloseAllConnections();
    bool IsInTransaction();
    void SetInTransaction(bool isInTransaction);
    SharedConn AcquireById(bool isReadOnly, int32_t id);

private:
    struct ConnNode {
        bool using_ = false;
        int32_t tid_ = 0;
        int32_t id_ = 0;
        std::chrono::steady_clock::time_point time_ = std::chrono::steady_clock::now();
        const std::shared_ptr<Connection> connect_;

        explicit ConnNode(std::shared_ptr<Connection> conn);
        std::shared_ptr<Connection> GetConnect();
        int64_t GetUsingTime() const;
        bool IsWriter() const;
        int32_t Unused(int32_t count, bool timeout);
        bool IsRecyclable();
    };

    struct Container {
        using Creator = std::function<std::pair<int32_t, std::shared_ptr<Connection>>()>;
        static constexpr int32_t MAX_RIGHT = 0x4FFFFFFF;
        static constexpr int32_t MIN_TRANS_ID = 10000;
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
        std::pair<int32_t, std::shared_ptr<ConnNode>> Initialize(
            Creator creator, int32_t max, int32_t timeout, bool disable, bool acquire = false);
        int32_t ConfigLocale(const std::string &locale);
        int32_t SetTokenizer(Tokenizer tokenizer);
        std::pair<int, std::shared_ptr<ConnNode>> Acquire(std::chrono::milliseconds milliS);
        std::pair<bool, std::list<std::shared_ptr<ConnNode>>> AcquireAll(std::chrono::milliseconds milliS);
        std::pair<int32_t, std::shared_ptr<ConnNode>> Create();
        void InitMembers(Creator creator, int32_t max, int32_t timeout, bool disable);

        void Disable();
        void Enable();
        int32_t Release(std::shared_ptr<ConnNode> node);
        int32_t ReleaseTrans(std::shared_ptr<ConnNode> node);
        int32_t Clear();
        bool IsFull();
        bool Empty();
        int32_t Dump(const char *header, int32_t count);
        int32_t ClearUnusedTrans(std::shared_ptr<ConnectionPool> pool);
        std::shared_ptr<ConnNode> AcquireById(int32_t id);

    private:
        int32_t ExtendNode();
        int32_t RelDetails(std::shared_ptr<ConnNode> node);
    };

    explicit ConnectionPool(const RdbStoreConfig &storeConfig);
    std::pair<int32_t, std::shared_ptr<Connection>> Init(bool isAttach = false, bool needWriter = false);
    int32_t GetMaxReaders(const RdbStoreConfig &config);
    std::shared_ptr<Connection> Convert2AutoConn(std::shared_ptr<ConnNode> node, bool isTrans = false);
    void ReleaseNode(std::shared_ptr<ConnNode> node, bool reuse = true);
    int RestoreByDbSqliteType(const std::string &newPath, const std::string &backupPath,
        std::shared_ptr<SlaveStatus> slaveStatus);
    int RestoreMasterDb(const std::string &newPath, const std::string &backupPath);
    bool CheckIntegrity(const std::string &dbPath);
    void DelayClearTrans();
    void ClearCache();

    static constexpr uint32_t CHECK_POINT_INTERVAL = 5; // 5 min
    static constexpr int LIMITATION = 1024;
    static constexpr uint32_t ITER_V1 = 5000;
    static constexpr uint32_t ITERS_COUNT = 2;
    static constexpr uint32_t MAX_TRANS = 4;
    static constexpr std::chrono::steady_clock::duration TRANS_CLEAR_INTERVAL = std::chrono::seconds(150);
    static constexpr uint32_t FIRST_DELAY_INTERVAL = ActuatorBase::INVALID_INTERVAL;
    static constexpr uint32_t MIN_EXECUTE_INTERVAL = ActuatorBase::INVALID_INTERVAL;
    static constexpr uint32_t MAX_EXECUTE_INTERVAL = 30000; // 30000ms
    std::shared_ptr<DelayActuator> clearActuator_;
    const RdbStoreConfig &config_;
    RdbStoreConfig attachConfig_;
    Container writers_;
    Container readers_;
    Container trans_;
    int32_t maxReader_ = 0;

    std::stack<BaseTransaction> transactionStack_;
    std::mutex transactionStackMutex_;
    std::condition_variable transCondition_;
    std::mutex transMutex_;
    bool transactionUsed_;
    bool isAttach_ = false;
    std::atomic<bool> isInTransaction_ = false;
    std::atomic<uint32_t> transCount_ = 0;
    std::atomic<std::chrono::steady_clock::time_point> failedTime_;
};

} // namespace NativeRdb
} // namespace OHOS
#endif
