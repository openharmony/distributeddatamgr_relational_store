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

#ifndef NATIVE_RDB_SQLITE_CONNECTION_H
#define NATIVE_RDB_SQLITE_CONNECTION_H

#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <vector>

#include "connection.h"
#include "rdb_local_db_observer.h"
#include "rdb_store_config.h"
#include "sqlite3sym.h"
#include "sqlite_statement.h"
#include "value_object.h"

typedef struct ClientChangedData ClientChangedData;
namespace OHOS {
namespace NativeRdb {
/**
 * @brief Use DataChangeCallback replace std::function<void(ClientChangedData &clientChangedData)>.
 */
using DataChangeCallback = std::function<void(ClientChangedData &clientChangedData)>;

class SqliteConnection : public Connection {
public:
    static std::pair<int32_t, std::shared_ptr<Connection>> Create(const RdbStoreConfig &config, bool isWrite);
    ~SqliteConnection();
    int32_t OnInitialize() override;
    int TryCheckPoint() override;
    int LimitWalSize() override;
    int ConfigLocale(const std::string &localeStr) override;
    int CleanDirtyData(const std::string &table, uint64_t cursor) override;
    int ReSetKey(const RdbStoreConfig &config) override;
    int32_t GetJournalMode() override;
    std::pair<int32_t, Stmt> CreateStatement(const std::string &sql, SConn conn) override;
    bool IsWriter() const override;
    int SubscribeTableChanges(const Notifier &notifier) override;
    int GetMaxVariable() const override;
    int32_t GetDBType() const override;
    int ClearCache() override;
    int32_t Subscribe(const std::string &event,
        const std::shared_ptr<DistributedRdb::RdbStoreObserver> &observer) override;
    int32_t Unsubscribe(const std::string &event,
        const std::shared_ptr<DistributedRdb::RdbStoreObserver> &observer) override;

protected:
    int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteEncryptSql(const RdbStoreConfig &config, uint32_t iter);
    void SetInTransaction(bool transaction);

private:
    static constexpr const char *MERGE_ASSETS_FUNC = "merge_assets";
    explicit SqliteConnection(bool isWriteConnection);
    int InnerOpen(const RdbStoreConfig &config, uint32_t retry);
    int Configure(const RdbStoreConfig &config, uint32_t retry, std::string &dbPath);
    int SetPageSize(const RdbStoreConfig &config);
    std::string GetSecManagerName(const RdbStoreConfig &config);
    int SetEncryptKey(const RdbStoreConfig &config, uint32_t iter);
    int SetJournalMode(const RdbStoreConfig &config);
    int SetJournalSizeLimit(const RdbStoreConfig &config);
    int SetAutoCheckpoint(const RdbStoreConfig &config);
    int SetWalSyncMode(const std::string &syncMode);
    void LimitPermission(const std::string &dbPath) const;

    int SetPersistWal();
    int SetBusyTimeout(int timeout);

    int RegDefaultFunctions(sqlite3 *dbHandle);
    static void MergeAssets(sqlite3_context *ctx, int argc, sqlite3_value **argv);
    static void CompAssets(std::map<std::string, ValueObject::Asset> &oldAssets,
        std::map<std::string, ValueObject::Asset> &newAssets);
    static void MergeAsset(ValueObject::Asset &oldAsset, ValueObject::Asset &newAsset);

    int SetCustomFunctions(const RdbStoreConfig &config);
    int SetCustomScalarFunction(const std::string &functionName, int argc, ScalarFunction *function);
    int32_t UnsubscribeLocalDetail(const std::string &event,
        const std::shared_ptr<DistributedRdb::RdbStoreObserver> &observer);
    int32_t UnsubscribeLocalDetailAll(const std::string &event);

    static constexpr int DEFAULT_BUSY_TIMEOUT_MS = 2000;
    static constexpr uint32_t NO_ITER = 0;
    static constexpr uint32_t ITER_V1 = 5000;
    static constexpr uint32_t ITERS[] = { NO_ITER, ITER_V1 };
    static constexpr uint32_t ITERS_COUNT = sizeof(ITERS) / sizeof(ITERS[0]);
    static const int32_t g_reg;

    sqlite3 *dbHandle;
    bool isWriter_;
    bool isReadOnly;
    bool isConfigured_ = false;
    bool hasClientObserver_ = false;
    JournalMode mode_ = JournalMode::MODE_WAL;
    int openFlags;
    int maxVariableNumber_;
    std::mutex mutex_;
    std::string filePath;
    std::map<std::string, ScalarFunctionInfo> customScalarFunctions_;
    std::map<std::string, std::list<std::shared_ptr<RdbStoreLocalDbObserver>>> rdbStoreLocalDbObservers_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif
