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

#include <mutex>
#include <memory>
#include <vector>

#include "sqlite3sym.h"
#include "rdb_store_config.h"
#include "sqlite_statement.h"
#include "value_object.h"

typedef struct ClientChangedData ClientChangedData;
namespace OHOS {
namespace NativeRdb {
/**
 * @brief Use DataChangeCallback replace std::function<void(ClientChangedData &clientChangedData)>.
 */
using DataChangeCallback = std::function<void(ClientChangedData &clientChangedData)>;

class SqliteConnection {
public:
    static std::shared_ptr<SqliteConnection> Open(const RdbStoreConfig &config, bool isWriteConnection, int &errCode);
    ~SqliteConnection();
    bool IsWriteConnection() const;
    int Prepare(const std::string &sql, bool &outIsReadOnly);
    int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteForChangedRowCount(int &changedRows, const std::string &sql, const std::vector<ValueObject> &bindArgs);
    int ExecuteForLastInsertedRowId(int64_t &outRowId, const std::string &sql,
        const std::vector<ValueObject> &bindArgs);
    int ExecuteGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    std::shared_ptr<SqliteStatement> BeginStepQuery(int &errCode, const std::string &sql,
        const std::vector<ValueObject> &args) const;
    int ExecuteEncryptSql(const RdbStoreConfig &config, uint32_t iter);
    int ReSetKey(const RdbStoreConfig &config);
    int DesFinalize();
    int EndStepQuery();
    void SetInTransaction(bool transaction);
    bool IsInTransaction();
    int TryCheckPoint();
    int LimitWalSize();
    int ConfigLocale(const std::string &localeStr);

    int RegisterCallBackObserver(const DataChangeCallback &clientChangedData);
    int GetMaxVariableNumber();
    uint32_t GetId() const;
    int32_t SetId(uint32_t id);
private:
    static constexpr const char *MERGE_ASSETS_FUNC = "merge_assets";
    explicit SqliteConnection(bool isWriteConnection);
    int InnerOpen(const RdbStoreConfig &config, uint32_t retry);
    int GetDbPath(const RdbStoreConfig &config, std::string &dbPath);
    int Configure(const RdbStoreConfig &config, uint32_t retry, std::string &dbPath);
    int SetPageSize(const RdbStoreConfig &config);
    int SetEncryptKey(const RdbStoreConfig &config, uint32_t iter);
    int SetJournalMode(const RdbStoreConfig &config);
    int SetJournalSizeLimit(const RdbStoreConfig &config);
    int SetAutoCheckpoint(const RdbStoreConfig &config);
    int SetWalSyncMode(const std::string &syncMode);
    int PrepareAndBind(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    void LimitPermission(const std::string &dbPath) const;

    int SetPersistWal();
    int SetBusyTimeout(int timeout);
    int RegDefaultFunctions(sqlite3 *dbHandle);
    static void MergeAssets(sqlite3_context *ctx, int argc, sqlite3_value **argv);
    static void CompAssets(std::map<std::string, ValueObject::Asset> &oldAssets, std::map<std::string,
        ValueObject::Asset> &newAssets);
    static void MergeAsset(ValueObject::Asset &oldAsset, ValueObject::Asset &newAsset);
    int SetCustomFunctions(const RdbStoreConfig &config);
    int SetCustomScalarFunction(const std::string &functionName, int argc, ScalarFunction *function);

    friend class SqliteStatement;

    sqlite3 *dbHandle;
    bool isWriteConnection;
    bool isReadOnly;
    SqliteStatement statement;
    std::shared_ptr<SqliteStatement> stepStatement;
    std::string filePath;
    int openFlags;
    std::mutex rdbMutex;
    bool inTransaction_;
    std::map<std::string, ScalarFunctionInfo> customScalarFunctions_;

    static constexpr int DEFAULT_BUSY_TIMEOUT_MS = 2000;
    static constexpr uint32_t NO_ITER = 0;
    static constexpr uint32_t ITER_V1 = 5000;
    static constexpr uint32_t ITERS[] = {NO_ITER, ITER_V1};
    static constexpr uint32_t ITERS_COUNT = sizeof(ITERS) / sizeof(ITERS[0]);

    bool isConfigured_ = false;
    int maxVariableNumber_;
    bool hasClientObserver_ = false;
    int id_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif
