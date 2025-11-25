/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_SQLITE_STATEMENT_H
#define NATIVE_RDB_SQLITE_STATEMENT_H

#include <memory>
#include <vector>

#include "rdb_store_config.h"
#include "share_block.h"
#include "sqlite3sym.h"
#include "sqlite_utils.h"
#include "statement.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
class Connection;
class SqliteStatement : public Statement {
public:
    static constexpr int COLUMN_TYPE_ASSET = 1000;
    static constexpr int COLUMN_TYPE_ASSETS = 1001;
    static constexpr int COLUMN_TYPE_FLOATS = 1002;
    static constexpr int COLUMN_TYPE_BIGINT = 1003;

    SqliteStatement(const RdbStoreConfig *config = nullptr);
    ~SqliteStatement();
    int Prepare(const std::string &sql) override;
    int Bind(const std::vector<ValueObject> &args) override;
    std::pair<int32_t, int32_t> Count() override;
    int Step() override;
    int Reset() override;
    int Finalize() override;
    int Execute(const std::vector<ValueObject> &args) override;
    int32_t Execute(const std::vector<std::reference_wrapper<ValueObject>> &args) override;
    std::pair<int, ValueObject> ExecuteForValue(const std::vector<ValueObject> &args) override;
    std::pair<int, std::vector<ValuesBucket>> ExecuteForRows(
        const std::vector<ValueObject> &args, int32_t maxCount) override;
    std::pair<int, std::vector<ValuesBucket>> ExecuteForRows(
        const std::vector<std::reference_wrapper<ValueObject>> &args, int32_t maxCount) override;
    int Changes() const override;
    int64_t LastInsertRowId() const override;
    int32_t GetColumnCount() const override;
    std::pair<int32_t, std::string> GetColumnName(int index) const override;
    std::pair<int32_t, int32_t> GetColumnType(int index) const override;
    std::pair<int32_t, size_t> GetSize(int index) const override;
    std::pair<int32_t, ValueObject> GetColumn(int index) const override;
    std::pair<int32_t, std::vector<ValuesBucket>> GetRows(int32_t maxCount) override;
    bool ReadOnly() const override;
    bool SupportBlockInfo() const override;
    int32_t FillBlockInfo(SharedBlockInfo *info) const override;
    int ModifyLockStatus(
        const std::string &table, const std::vector<std::vector<uint8_t>> &hashKeys, bool isLock) override;

private:
    friend class SqliteConnection;
    using Asset = ValueObject::Asset;
    using Assets = ValueObject::Assets;
    using BigInt = ValueObject::BigInt;
    using Floats = ValueObject::FloatVector;
    using Action = int32_t (*)(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindNil(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindInteger(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindDouble(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindText(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindBool(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindBlob(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindAsset(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindAssets(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindFloats(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindBigInt(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static const int SQLITE_SET_SHAREDBLOCK = 2004;
    static const int SQLITE_USE_SHAREDBLOCK = 2005;
    static constexpr Action ACTIONS[ValueObject::TYPE_MAX] = { BindNil, BindInteger, BindDouble, BindText, BindBool,
        BindBlob, BindAsset, BindAssets, BindFloats, BindBigInt };

    int CheckEnvironment(int paramCount) const;
    int Prepare(sqlite3 *dbHandle, const std::string &sql);
    int BindArgs(const std::vector<ValueObject> &bindArgs);
    int BindArgs(const std::vector<std::reference_wrapper<ValueObject>> &bindArgs);
    int IsValid(int index) const;
    int InnerStep();
    int InnerFinalize();
    ValueObject GetValueFromBlob(int32_t index, int32_t type) const;
    void ReadFile2Buffer();
    void PrintInfoForDbError(int errCode, const std::string &sql);
    void TableReport(const std::string &errMsg, const std::string &bundleName, ErrMsgState state);
    void ColumnReport(const std::string &errMsg, const std::string &bundleName, ErrMsgState state);
    void HandleErrMsg(const std::string &errMsg, const std::string &dbPath, const std::string &bundleName);
    void TryNotifyErrorLog(const int &errCode, sqlite3 *dbHandle, const std::string &sql);

    static constexpr uint32_t BUFFER_LEN = 16;

    static constexpr int MAX_RETRY_TIMES = 50;
    // Interval of retrying query in millisecond
    static constexpr int RETRY_INTERVAL = 1000;

    bool readOnly_;
    bool bound_ = false;
    int columnCount_ = -1;
    int numParameters_;
    uint32_t seqId_ = 0;
    sqlite3_stmt *stmt_;
    std::shared_ptr<Connection> conn_;
    std::string sql_;
    mutable std::vector<int32_t> types_;
    std::shared_ptr<Statement> slave_;
    const RdbStoreConfig *config_ = nullptr;
};
} // namespace NativeRdb
} // namespace OHOS
#endif
