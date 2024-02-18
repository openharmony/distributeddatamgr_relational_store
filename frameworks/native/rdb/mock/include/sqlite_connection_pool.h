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
#include <mutex>
#include <vector>
#include <sstream>
#include <iostream>
#include <iterator>
#include <stack>

#include "rdb_store_config.h"
#include "sqlite_connection.h"
#include "base_transaction.h"
namespace OHOS {
namespace NativeRdb {
class SqliteConnectionPool {
public:
    static SqliteConnectionPool *Create(const RdbStoreConfig &storeConfig, int &errCode);
    ~SqliteConnectionPool();
    std::shared_ptr<SqliteConnection> AcquireConnection(bool isReadOnly);
    void ReleaseConnection(std::shared_ptr<SqliteConnection> connection);
    int ReOpenAvailableReadConnections();
#ifdef RDB_SUPPORT_ICU
    int ConfigLocale(const std::string localeStr);
#endif
    int ChangeDbFileForRestore(const std::string newPath, const std::string backupPath,
        const std::vector<uint8_t> &newKey);
    std::stack<BaseTransaction> &GetTransactionStack();
    std::mutex &GetTransactionStackMutex();
    int AcquireTransaction();
    void ReleaseTransaction();

private:
    explicit SqliteConnectionPool(const RdbStoreConfig &storeConfig);
    int Init();
    void InitReadConnectionCount();
    std::shared_ptr<SqliteConnection> AcquireWriteConnection();
    void ReleaseWriteConnection();
    std::shared_ptr<SqliteConnection> AcquireReadConnection();
    void ReleaseReadConnection(std::shared_ptr<SqliteConnection> connection);
    void CloseAllConnections();
    int InnerReOpenReadConnections();

    RdbStoreConfig config_;
    std::shared_ptr<SqliteConnection> writeConnection_;
    std::mutex writeMutex_;
    std::condition_variable writeCondition_;
    bool writeConnectionUsed_;

    std::vector<std::shared_ptr<SqliteConnection>> readConnections_;
    std::mutex readMutex_;
    std::mutex rdbMutex_;
    std::condition_variable readCondition_;
    int readConnectionCount_;
    int idleReadConnectionCount_;
    const static int LIMITATION = 1024;

    std::stack<BaseTransaction> transactionStack_;
    std::mutex transactionStackMutex_;
    std::condition_variable transCondition_;
    std::mutex transMutex_;
    bool transactionUsed_;
    std::chrono::seconds writeTimeout_ = std::chrono::seconds(2);
    std::chrono::seconds readTimeout_ = std::chrono::seconds(1);
};

} // namespace NativeRdb
} // namespace OHOS
#endif
