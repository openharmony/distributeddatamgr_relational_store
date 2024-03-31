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

#ifndef NATIVE_RDB_CONNECTION_H
#define NATIVE_RDB_CONNECTION_H

#include <mutex>
#include <memory>
#include <vector>

#include "rdb_statement.h"
#include "rdb_store_config.h"
#include "value_object.h"
#include "shared_block.h"

typedef struct ClientChangedData ClientChangedData;
namespace OHOS {
namespace NativeRdb {

/**
 * @brief Use DataChangeCallback replace std::function<void(ClientChangedData &clientChangedData)>.
 */
using DataChangeCallback = std::function<void(ClientChangedData &clientChangedData)>;

class RdbConnection {
public:
    static std::shared_ptr<RdbConnection> Open(const RdbStoreConfig &config, bool isWriteConnection, int &errCode);
    virtual ~RdbConnection() = default;
    virtual bool IsWriteConnection() const;
    virtual int Prepare(const std::string &sql, bool &outIsReadOnly);
    virtual int ExecuteSql(
        const std::string &sql, const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    virtual std::shared_ptr<RdbStatement> BeginStepQuery(int &errCode, const std::string &sql,
        const std::vector<ValueObject> &args) const;
    virtual int DesFinalize();
    virtual int EndStepQuery();
    virtual int ExecuteForChangedRowCount(
        int &changedRows, const std::string &sql, const std::vector<ValueObject> &bindArgs);
    virtual int ExecuteForLastInsertedRowId(int64_t &outRowId, const std::string &sql,
        const std::vector<ValueObject> &bindArgs);
    virtual int ExecuteGetLong(int64_t &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    virtual int ExecuteGetString(std::string &outValue, const std::string &sql,
        const std::vector<ValueObject> &bindArgs = std::vector<ValueObject>());
    virtual int ExecuteEncryptSql(const RdbStoreConfig &config, uint32_t iter);
    virtual int ReSetKey(const RdbStoreConfig &config);
    virtual void SetInTransaction(bool transaction);
    virtual bool IsInTransaction();
    virtual int TryCheckPoint();
    virtual int LimitWalSize();
    virtual int ConfigLocale(const std::string &localeStr);
    virtual int ExecuteForSharedBlock(int &rowNum, std::string sql, const std::vector<ValueObject> &bindArgs,
        AppDataFwk::SharedBlock *sharedBlock, int startPos, int requiredPos, bool isCountAllRows);
    virtual int CleanDirtyData(const std::string &table, uint64_t cursor);
    virtual int RegisterCallBackObserver(const DataChangeCallback &clientChangedData);
    virtual int GetMaxVariableNumber();
    virtual uint32_t GetId() const;
    virtual int32_t SetId(uint32_t id);
    virtual JournalMode GetJournalMode();
protected:
    explicit RdbConnection(bool isWriteConnection);
    int GetDbPath(const RdbStoreConfig &config, std::string &dbPath);
    bool isWriteConnection_;
    bool isReadOnly_;
    bool isConfigured_ = false;
    std::shared_ptr<RdbStatement> statement_ = nullptr;
    std::shared_ptr<RdbStatement> stepStatement_ = nullptr;
    std::string filePath_;
    int openFlags;

    static constexpr int DEFAULT_BUSY_TIMEOUT_MS = 2000;
    static constexpr uint32_t NO_ITER = 0;
    static constexpr uint32_t ITER_V1 = 5000;
    static constexpr uint32_t ITERS[] = {NO_ITER, ITER_V1};
    static constexpr uint32_t ITERS_COUNT = sizeof(ITERS) / sizeof(ITERS[0]);
};

} // namespace NativeRdb
} // namespace OHOS
#endif // NATIVE_RDB_CONNECTION_H