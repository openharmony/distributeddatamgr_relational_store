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

namespace OHOS {
namespace NativeRdb {
class SqliteConnection {
public:
    static SqliteConnection *Open(const RdbStoreConfig &config, bool isWriteConnection, int &errCode);
    ~SqliteConnection();
    bool IsWriteConnection() const;
    int Prepare(const std::string &sql, bool &outIsReadOnly);
    int PrepareAndGetInfo(const std::string &sql, bool &outIsReadOnly, int &numParameters,
        std::vector<std::string> &columnNames);
    int ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteForChangedRowCount(int &changedRows, const std::string &sql, const std::vector<ValueObject> &bindArgs);
    int ExecuteForLastInsertedRowId(int64_t &outRowId, const std::string &sql,
        const std::vector<ValueObject> &bindArgs);
    int ExecuteGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    int ExecuteGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    std::shared_ptr<SqliteStatement> BeginStepQuery(int &errCode, const std::string &sql,
        const std::vector<std::string> &selectionArgs) const;
    int DesFinalize();
    int EndStepQuery();
    void SetInTransaction(bool transaction);
    bool IsInTransaction();
    int LimitWalSize();
#ifdef RDB_SUPPORT_ICU
    int ConfigLocale(const std::string localeStr);
#endif

private:
    explicit SqliteConnection(bool isWriteConnection);
    int InnerOpen(const RdbStoreConfig &config);
    int Config(const RdbStoreConfig &config);
    int SetPageSize(const RdbStoreConfig &config);
    int SetEncryptKey(const RdbStoreConfig &config);
    int SetJournalMode(const RdbStoreConfig &config);
    int SetJournalSizeLimit(const RdbStoreConfig &config);
    int SetAutoCheckpoint(const RdbStoreConfig &config);
    int SetWalSyncMode(const std::string &syncMode);
    int PrepareAndBind(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    void LimitPermission(const std::string &dbPath) const;

    int SetPersistWal();
    int SetBusyTimeout(int timeout);
    int SetCustomFunctions(const RdbStoreConfig &config);
    int SetCustomScalarFunction(const std::string &functionName, int argc, ScalarFunction *function);

    sqlite3 *dbHandle;
    bool isWriteConnection;
    bool isReadOnly;
    SqliteStatement statement;
    std::shared_ptr<SqliteStatement> stepStatement;
    std::string filePath;
    int openFlags;
    std::mutex rdbMutex;
    bool inTransaction_;

    static constexpr int DEFAULT_BUSY_TIMEOUT_MS = 2000;
};
} // namespace NativeRdb
} // namespace OHOS
#endif
