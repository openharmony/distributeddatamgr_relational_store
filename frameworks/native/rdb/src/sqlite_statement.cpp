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
#define LOG_TAG "SqliteStatement"
#include "sqlite_statement.h"

#include <chrono>
#include <cinttypes>
#include <iomanip>
#include <sstream>
#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "sqlite3sym.h"
#include "sqlite_connection.h"
#include "sqlite_errno.h"
#include "sqlite_utils.h"
#include "shared_block_serializer_info.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
// Setting Data Precision
const int SET_DATA_PRECISION = 15;
SqliteStatement::SqliteStatement() : sql(""), stmtHandle(nullptr), readOnly(false), columnCount(0), numParameters(0)
{
}

SqliteStatement::~SqliteStatement()
{
    Finalize();
}

std::shared_ptr<SqliteStatement> SqliteStatement::CreateStatement(
    std::shared_ptr<SqliteConnection> connection, const std::string &sql)
{
    sqlite3_stmt *stmt = nullptr;
    int errCode = sqlite3_prepare_v2(connection->dbHandle, sql.c_str(), sql.length(), &stmt, nullptr);
    if (errCode != SQLITE_OK) {
        auto time = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
        LOG_ERROR("prepare_v2 ret is %{public}d %{public}" PRIu64 ".", errCode, time);
        if (stmt != nullptr) {
            sqlite3_finalize(stmt);
        }
        return nullptr;
    }
    std::shared_ptr<SqliteStatement> sqliteStatement = std::make_shared<SqliteStatement>();
    sqliteStatement->stmtHandle = stmt;
    sqliteStatement->readOnly = (sqlite3_stmt_readonly(stmt) != 0);
    sqliteStatement->columnCount = sqlite3_column_count(stmt);
    sqliteStatement->numParameters = sqlite3_bind_parameter_count(stmt);
    return sqliteStatement;
}

int SqliteStatement::Prepare(sqlite3 *dbHandle, const std::string &newSql)
{
    if (sql.compare(newSql) == 0) {
        return E_OK;
    }
    // prepare the new sqlite3_stmt
    sqlite3_stmt *stmt = nullptr;
    int errCode = sqlite3_prepare_v2(dbHandle, newSql.c_str(), newSql.length(), &stmt, nullptr);
    if (errCode != SQLITE_OK) {
        if (stmt != nullptr) {
            sqlite3_finalize(stmt);
        }
        return SQLiteError::ErrNo(errCode);
    }
    Finalize(); // finalize the old
    sql = newSql;
    stmtHandle = stmt;
    readOnly = (sqlite3_stmt_readonly(stmtHandle) != 0) ? true : false;
    columnCount = sqlite3_column_count(stmtHandle);
    numParameters = sqlite3_bind_parameter_count(stmtHandle);
    return E_OK;
}

int SqliteStatement::Finalize()
{
    if (stmtHandle == nullptr) {
        return E_OK;
    }

    int errCode = sqlite3_finalize(stmtHandle);
    stmtHandle = nullptr;
    sql = "";
    readOnly = false;
    columnCount = 0;
    numParameters = 0;
    if (errCode != SQLITE_OK) {
        LOG_ERROR("finalize ret is %{public}d", errCode);
        return SQLiteError::ErrNo(errCode);
    }
    return E_OK;
}

int SqliteStatement::BindArguments(const std::vector<ValueObject> &bindArgs) const
{
    int count = static_cast<int>(bindArgs.size());
    std::vector<ValueObject> abindArgs;

    if (count == 0) {
        return E_OK;
    }
    // Obtains the bound parameter set.
    if ((numParameters != 0) && (count <= numParameters)) {
        for (const auto& i : bindArgs) {
            abindArgs.push_back(i);
        }

        for (int i = count; i < numParameters; i++) { // TD: when count <> numParameters
            ValueObject val;
            abindArgs.push_back(val);
        }
    }

    if (count > numParameters) {
        LOG_ERROR("bind args count(%{public}d) > numParameters(%{public}d)", count, numParameters);
        return E_INVALID_BIND_ARGS_COUNT;
    }

    return InnerBindArguments(abindArgs);
}

int SqliteStatement::InnerBindArguments(const std::vector<ValueObject> &bindArgs) const
{
    int index = 1;
    for (auto &arg : bindArgs) {
        auto action = BINDERS[arg.value.index()];
        if (action == nullptr) {
            LOG_ERROR("not support the type %{public}zu", arg.value.index());
            return E_INVALID_ARGS;
        }
        auto errCode = action(stmtHandle, index, arg.value);
        if (errCode != SQLITE_OK) {
            LOG_ERROR("bind ret is %{public}d", errCode);
            return SQLiteError::ErrNo(errCode);
        }
        index++;
    }

    return E_OK;
}

int SqliteStatement::ResetStatementAndClearBindings() const
{
    if (stmtHandle == nullptr) {
        return E_OK;
    }

    int errCode = sqlite3_reset(stmtHandle);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("reset ret is %{public}d", errCode);
        return SQLiteError::ErrNo(errCode);
    }

    errCode = sqlite3_clear_bindings(stmtHandle);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("clear_bindings ret is %{public}d", errCode);
        return SQLiteError::ErrNo(errCode);
    }

    return E_OK;
}

int SqliteStatement::Step() const
{
    int errCode = sqlite3_step(stmtHandle);
    return errCode;
}

int SqliteStatement::GetColumnCount(int &count) const
{
    if (stmtHandle == nullptr) {
        LOG_ERROR("invalid statement.");
        return E_INVALID_STATEMENT;
    }
    count = columnCount;
    return E_OK;
}

int SqliteStatement::GetColumnName(int index, std::string &columnName) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }

    const char *name = sqlite3_column_name(stmtHandle, index);
    if (name == nullptr) {
        LOG_ERROR("column_name is null.");
        return E_ERROR;
    }
    columnName = std::string(name);
    return E_OK;
}

int SqliteStatement::GetColumnType(int index, int &columnType) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }

    int type = sqlite3_column_type(stmtHandle, index);
    switch (type) {
        case SQLITE_INTEGER:
        case SQLITE_FLOAT:
        case SQLITE_NULL:
        case SQLITE_TEXT:
            columnType = type;
            return E_OK;
        case SQLITE_BLOB: {
            auto declType = SqliteUtils::StrToUpper(std::string(sqlite3_column_decltype(stmtHandle, index)));
            if (declType == ValueObject::DeclType<ValueObject::Asset>()) {
                columnType = COLUMN_TYPE_ASSET;
                return E_OK;
            }
            if (declType == ValueObject::DeclType<ValueObject::Assets>()) {
                columnType = COLUMN_TYPE_ASSETS;
                return E_OK;
            }
            if (declType == ValueObject::DeclType<ValueObject::FloatVector>()) {
                columnType = COLUMN_TYPE_FLOATS;
                return E_OK;
            }
            if (declType == ValueObject::DeclType<ValueObject::BigInt>()) {
                columnType = COLUMN_TYPE_BIGINT;
                return E_OK;
            }
            columnType = type;
            return E_OK;
        }
        default:
            LOG_ERROR("invalid type %{public}d.", type);
            return E_ERROR;
    }
}

int SqliteStatement::GetColumnBlob(int index, std::vector<uint8_t> &value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }

    int type = sqlite3_column_type(stmtHandle, index);
    if (type != SQLITE_BLOB && type != SQLITE_TEXT && type != SQLITE_NULL) {
        LOG_ERROR("invalid type %{public}d.", type);
        return E_INVALID_COLUMN_TYPE;
    }

    int size = sqlite3_column_bytes(stmtHandle, index);
    auto blob = static_cast<const uint8_t *>(sqlite3_column_blob(stmtHandle, index));
    if (size == 0 || blob == nullptr) {
        value.resize(0);
    } else {
        value.resize(size);
        value.assign(blob, blob + size);
    }

    return E_OK;
}

int SqliteStatement::GetColumnString(int index, std::string &value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }

    int type = sqlite3_column_type(stmtHandle, index);
    switch (type) {
        case SQLITE_TEXT: {
            auto val = reinterpret_cast<const char *>(sqlite3_column_text(stmtHandle, index));
            value = (val == nullptr) ? "" : std::string(val, sqlite3_column_bytes(stmtHandle, index));
            break;
        }
        case SQLITE_INTEGER: {
            int64_t val = sqlite3_column_int64(stmtHandle, index);
            value = std::to_string(val);
            break;
        }
        case SQLITE_FLOAT: {
            double val = sqlite3_column_double(stmtHandle, index);
            std::ostringstream os;
            if (os << std::setprecision(SET_DATA_PRECISION) << val)
                value = os.str();
            break;
        }
        case SQLITE_NULL: {
            value = "";
            return E_OK;
        }
        case SQLITE_BLOB: {
            return E_INVALID_COLUMN_TYPE;
        }
        default:
            return E_ERROR;
    }
    return E_OK;
}

int SqliteStatement::GetColumnLong(int index, int64_t &value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }

    char *errStr = nullptr;
    int type = sqlite3_column_type(stmtHandle, index);
    if (type == SQLITE_INTEGER) {
        value = sqlite3_column_int64(stmtHandle, index);
    } else if (type == SQLITE_TEXT) {
        auto val = reinterpret_cast<const char *>(sqlite3_column_text(stmtHandle, index));
        value = (val == nullptr) ? 0 : strtoll(val, &errStr, 0);
    } else if (type == SQLITE_FLOAT) {
        double val = sqlite3_column_double(stmtHandle, index);
        value = static_cast<int64_t>(val);
    } else if (type == SQLITE_NULL) {
        value = 0;
    } else if (type == SQLITE_BLOB) {
        return E_INVALID_COLUMN_TYPE;
    } else {
        return E_ERROR;
    }

    return E_OK;
}
int SqliteStatement::GetColumnDouble(int index, double &value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }

    char *ptr = nullptr;
    int type = sqlite3_column_type(stmtHandle, index);
    if (type == SQLITE_FLOAT) {
        value = sqlite3_column_double(stmtHandle, index);
    } else if (type == SQLITE_INTEGER) {
        int64_t val = sqlite3_column_int64(stmtHandle, index);
        value = static_cast<double>(val);
    } else if (type == SQLITE_TEXT) {
        auto val = reinterpret_cast<const char *>(sqlite3_column_text(stmtHandle, index));
        value = (val == nullptr) ? 0.0 : std::strtod(val, &ptr);
    } else if (type == SQLITE_NULL) {
        value = 0.0;
    } else if (type == SQLITE_BLOB) {
        return E_INVALID_COLUMN_TYPE;
    } else {
        LOG_ERROR("invalid type %{public}d.", type);
        return E_ERROR;
    }

    return E_OK;
}

int SqliteStatement::GetColumn(int index, ValueObject& value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }

    int type = sqlite3_column_type(stmtHandle, index);
    switch (type) {
        case SQLITE_FLOAT:
            value = sqlite3_column_double(stmtHandle, index);
            break;
        case SQLITE_INTEGER:
            value = static_cast<int64_t>(sqlite3_column_int64(stmtHandle, index));
            break;
        case SQLITE_TEXT: {
            int size = sqlite3_column_bytes(stmtHandle, index);
            auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmtHandle, index));
            value = ValueObject(text == nullptr ? std::string("") : std::string(text, size));
        }
            break;
        case SQLITE_BLOB:
            return GetCustomerValue(index, value);
        case SQLITE_NULL:
        default:
            break;
    }
    return E_OK;
}

int SqliteStatement::GetCustomerValue(int index, ValueObject& value) const
{
    const char *decl = sqlite3_column_decltype(stmtHandle, index);
    if (decl == nullptr) {
        LOG_ERROR("index %{public}d invalid type.", index);
        return E_ERROR;
    }

    int size = sqlite3_column_bytes(stmtHandle, index);
    auto blob = static_cast<const uint8_t *>(sqlite3_column_blob(stmtHandle, index));
    std::string declType = SqliteUtils::StrToUpper(decl);
    if (declType == ValueObject::DeclType<Asset>()) {
        Asset asset;
        RawDataParser::ParserRawData(blob, size, asset);
        value = std::move(asset);
        return E_OK;
    }
    if (declType == ValueObject::DeclType<Assets>()) {
        Assets assets;
        RawDataParser::ParserRawData(blob, size, assets);
        value = std::move(assets);
        return E_OK;
    }
    if (declType == ValueObject::DeclType<Floats>()) {
        Floats floats;
        RawDataParser::ParserRawData(blob, size, floats);
        value = std::move(floats);
        return E_OK;
    }
    if (declType == ValueObject::DeclType<BigInt>()) {
        BigInt bigint;
        RawDataParser::ParserRawData(blob, size, bigint);
        value = std::move(bigint);
        return E_OK;
    }
    std::vector<uint8_t> rawData;
    if (size > 0 || blob != nullptr) {
        rawData.resize(size);
        rawData.assign(blob, blob + size);
    }
    value = std::move(rawData);
    return E_OK;
}

int SqliteStatement::GetSize(int index, size_t &size) const
{
    size = 0;
    if (stmtHandle == nullptr) {
        return E_INVALID_STATEMENT;
    }

    if (index >= columnCount) {
        return E_INVALID_COLUMN_INDEX;
    }

    int type = sqlite3_column_type(stmtHandle, index);
    if (type == SQLITE_BLOB || type == SQLITE_TEXT || type == SQLITE_NULL) {
        size = static_cast<size_t>(sqlite3_column_bytes(stmtHandle, index));
        return E_OK;
    }

    return E_INVALID_COLUMN_TYPE;
}

bool SqliteStatement::IsReadOnly() const
{
    return readOnly;
}

int SqliteStatement::IsValid(int index) const
{
    if (stmtHandle == nullptr) {
        LOG_ERROR("invalid statement.");
        return E_INVALID_STATEMENT;
    }

    if (index >= columnCount) {
        LOG_ERROR("index (%{public}d) >= columnCount (%{public}d)", index, columnCount);
        return E_INVALID_COLUMN_INDEX;
    }

    return E_OK;
}

bool SqliteStatement::SupportSharedBlock() const
{
    auto db = sqlite3_db_handle(stmtHandle);
    return (sqlite3_db_config(db, SQLITE_USE_SHAREDBLOCK) == SQLITE_OK);
}

int32_t SqliteStatement::BindNil(sqlite3_stmt* stat, int index, const ValueObject::Type& arg)
{
    return sqlite3_bind_null(stat, index);
}

int32_t SqliteStatement::BindInteger(sqlite3_stmt* stat, int index, const ValueObject::Type& arg)
{
    auto val = std::get_if<int64_t>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_int64(stat, index, *val);
}

int32_t SqliteStatement::BindDouble(sqlite3_stmt* stat, int index, const ValueObject::Type& arg)
{
    auto val = std::get_if<double>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_double(stat, index, *val);
}

int32_t SqliteStatement::BindText(sqlite3_stmt* stat, int index, const ValueObject::Type& arg)
{
    auto val = std::get_if<std::string>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_text(stat, index, val->c_str(), val->length(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindBool(sqlite3_stmt* stat, int index, const ValueObject::Type& arg)
{
    auto val = std::get_if<bool>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_int64(stat, index, *val ? 1 : 0);
}

int32_t SqliteStatement::BindBlob(sqlite3_stmt* stat, int index, const ValueObject::Type& arg)
{
    auto val = std::get_if<std::vector<uint8_t>>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_blob(stat, index, static_cast<const void*>((*val).data()), (*val).size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindAsset(sqlite3_stmt* stat, int index, const ValueObject::Type& arg)
{
    auto val = std::get_if<Asset>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void*>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindAssets(sqlite3_stmt* stat, int index, const ValueObject::Type& arg)
{
    auto val = std::get_if<Assets>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void*>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindFloats(sqlite3_stmt* stat, int index, const ValueObject::Type& object)
{
    auto val = std::get_if<Floats>(&object);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void*>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindBigInt(sqlite3_stmt* stat, int index, const ValueObject::Type& arg)
{
    auto val = std::get_if<BigInt>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void*>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}
} // namespace NativeRdb
} // namespace OHOS
