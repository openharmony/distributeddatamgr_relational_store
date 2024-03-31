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

#include "sqlite3sym.h"
#include "value_object.h"
#include "share_block.h"
namespace OHOS {
namespace NativeRdb {
class SqliteConnection;

class SqliteStatement {
public:
    static constexpr int COLUMN_TYPE_ASSET = 1000;
    static constexpr int COLUMN_TYPE_ASSETS = 1001;
    static constexpr int COLUMN_TYPE_BIGINT = 1002;

    SqliteStatement();
    ~SqliteStatement();
    static std::shared_ptr<SqliteStatement> CreateStatement(std::shared_ptr<SqliteConnection> connection,
        const std::string& sql);
    int Prepare(sqlite3 *dbHandle, const std::string &sql);
    int Finalize();
    int BindArguments(const std::vector<ValueObject> &bindArgs) const;
    int ResetStatementAndClearBindings() const;
    int Step() const;

    int GetColumnCount(int &count) const;
    int GetColumnName(int index, std::string &columnName) const;
    int GetColumnType(int index, int &columnType) const;
    int GetColumnBlob(int index, std::vector<uint8_t> &value) const;
    int GetColumnString(int index, std::string &value) const;
    int GetColumnLong(int index, int64_t &value) const;
    int GetColumnDouble(int index, double &value) const;
    int GetSize(int index, size_t &size) const;
    int GetColumn(int index, ValueObject &value) const;
    bool IsReadOnly() const;
    bool SupportSharedBlock() const;
    sqlite3_stmt *GetSql3Stmt() const
    {
        return stmtHandle;
    }

private:
    using Asset = ValueObject::Asset;
    using Assets = ValueObject::Assets;
    using BigInt = ValueObject::BigInt;
    using Floats = ValueObject::FloatVector;
    using Binder = int32_t (*)(sqlite3_stmt *stat, int index, const ValueObject::Type &object);
    static int32_t BindNil(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static int32_t BindInteger(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static int32_t BindDouble(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static int32_t BindText(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static int32_t BindBool(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static int32_t BindBlob(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static int32_t BindAsset(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static int32_t BindAssets(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static int32_t BindFloats(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static int32_t BindBigInt(sqlite3_stmt* stat, int index, const ValueObject::Type& object);
    static const int SQLITE_SET_SHAREDBLOCK = 2004;
    static const int SQLITE_USE_SHAREDBLOCK = 2005;
    static constexpr Binder BINDERS[ValueObject::TYPE_MAX] = {
        BindNil,
        BindInteger,
        BindDouble,
        BindText,
        BindBool,
        BindBlob,
        BindAsset,
        BindAssets,
        BindFloats,
        BindBigInt
    };

    int GetCustomerValue(int index, ValueObject &value) const;
    int InnerBindArguments(const std::vector<ValueObject> &bindArgs) const;
    int IsValid(int index) const;
    std::string sql;
    sqlite3_stmt *stmtHandle;
    bool readOnly;
    int columnCount;
    int numParameters;
};

} // namespace NativeRdb
} // namespace OHOS
#endif