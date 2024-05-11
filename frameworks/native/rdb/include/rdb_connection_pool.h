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

#ifndef NATIVE_RDB_CONNECTION_POOL_H
#define NATIVE_RDB_CONNECTION_POOL_H

#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>
#include <sstream>
#include <iostream>
#include <iterator>
#include <stack>

#include "rdb_store_config.h"
#include "rdb_connection.h"
#include "sqlite_connection.h"
#include "base_transaction.h"
namespace OHOS {
namespace NativeRdb {
class RdbConnectionPool {
public:
    static std::shared_ptr<RdbConnectionPool> Create(const RdbStoreConfig &storeConfig, int &errCode);
    explicit RdbConnectionPool(const RdbStoreConfig &storeConfig);
    virtual ~RdbConnectionPool();
    virtual std::shared_ptr<RdbConnection> AcquireNewConnection(bool isReadOnly, int64_t &trxId);
    virtual void ReleaseConnection(std::shared_ptr<RdbConnection> rdbConnection, int64_t trxId = 0);
    virtual std::shared_ptr<RdbConnection> AcquireConnection(bool isReadOnly, int64_t trxId = 0);
    virtual int RestartReaders();
    virtual std::pair<std::shared_ptr<RdbConnection>, std::vector<std::shared_ptr<RdbConnection>>>
        AcquireAll(int32_t time);
    virtual int ConfigLocale(const std::string &localeStr);
    virtual int ChangeDbFileForRestore(const std::string &newPath, const std::string &backupPath,
        const std::vector<uint8_t> &newKey);
    virtual std::stack<BaseTransaction> &GetTransactionStack();
    virtual std::mutex &GetTransactionStackMutex();
    virtual std::pair<int, std::shared_ptr<RdbConnection>> DisableWalMode();
    virtual int AcquireTransaction();
    virtual void ReleaseTransaction();
    virtual int EnableWalMode();
    virtual void CloseAllConnections();
protected:
    std::mutex transactionStackMutex_;
    std::stack<BaseTransaction> transactionStack_;
    RdbStoreConfig config_;
private:
    static constexpr uint32_t MAX_WRITE_CONN_NUM = 16;
    static constexpr uint32_t MAX_READ_CONN_NUM = 64;
    static constexpr uint32_t DEFAULT_WRITE_CONN_NUM = 2;
    static constexpr uint32_t DEFAULT_READ_CONN_NUM = 8;

    virtual int Init();
    std::shared_ptr<RdbConnection> AcquireConnectionByTrxId(bool isReadOnly, int64_t trxId = 0);
    std::shared_ptr<RdbConnection> AcquireReadConnByTrxId(int64_t trxId);
    std::shared_ptr<RdbConnection> AcquireWriteConnByTrxId(int64_t trxId);
    void CloseAllConns();

    std::mutex idleConnsMutex_;
    std::vector<std::shared_ptr<RdbConnection>> idleReadConns_;
    std::vector<std::shared_ptr<RdbConnection>> idleWriteConns_;
    std::map<int64_t, std::shared_ptr<RdbConnection>> trxConnMap_ = {};

    std::atomic<int64_t> newtrxId_ = 1;
    std::atomic<uint32_t> writeConnNum_ = 0;
    std::atomic<uint32_t> readConnNum_ = 0;
};

} // namespace NativeRdb
} // namespace OHOS
#endif // NATIVE_RDB_CONNECTION_POOL_H
