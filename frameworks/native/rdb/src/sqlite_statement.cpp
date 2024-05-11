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

#include <cstdint>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>

#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "relational_store_client.h"
#include "share_block.h"
#include "shared_block_serializer_info.h"
#include "sqlite3.h"
#include "sqlite3ext.h"
#include "sqlite_connection.h"
#include "sqlite_connection_pool.h"
#include "sqlite_errno.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
// Setting Data Precision
constexpr SqliteStatement::Action SqliteStatement::ACTIONS[ValueObject::TYPE_MAX];
SqliteStatement::SqliteStatement() : readOnly_(false), columnCount_(0), numParameters_(0), stmt_(nullptr), sql_("") {}

SqliteStatement::~SqliteStatement()
{
    Finalize();
    conn_ = nullptr;
}

int SqliteStatement::Prepare(sqlite3 *dbHandle, const std::string &newSql)
{
    if (sql_.compare(newSql) == 0) {
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
    sql_ = newSql;
    stmt_ = stmt;
    readOnly_ = (sqlite3_stmt_readonly(stmt_) != 0);
    columnCount_ = sqlite3_column_count(stmt_);
    types_ = std::vector<int32_t>(columnCount_, 0);
    numParameters_ = sqlite3_bind_parameter_count(stmt_);
    return E_OK;
}

int SqliteStatement::BindArgs(const std::vector<ValueObject> &bindArgs)
{
    if (bound_) {
        Reset();
    }
    bound_ = true;
    int index = 1;
    for (auto &arg : bindArgs) {
        auto action = ACTIONS[arg.value.index()];
        if (action == nullptr) {
            LOG_ERROR("not support the type %{public}zu", arg.value.index());
            return E_INVALID_ARGS;
        }
        auto errCode = action(stmt_, index, arg.value);
        if (errCode != SQLITE_OK) {
            LOG_ERROR("Bind has error: %{public}d, sql: %{public}s", errCode, sql_.c_str());
            return SQLiteError::ErrNo(errCode);
        }
        index++;
    }

    return E_OK;
}

int SqliteStatement::IsValid(int index) const
{
    if (stmt_ == nullptr) {
        LOG_ERROR("statement already close.");
        return E_ALREADY_CLOSED;
    }

    if (index >= columnCount_) {
        LOG_ERROR("index (%{public}d) >= columnCount (%{public}d)", index, columnCount_);
        return E_COLUMN_OUT_RANGE;
    }
    return E_OK;
}

int SqliteStatement::Prepare(const std::string &sql)
{
    if (stmt_ == nullptr) {
        return E_ERROR;
    }
    auto db = sqlite3_db_handle(stmt_);
    return Prepare(db, sql);
}

int SqliteStatement::Bind(const std::vector<ValueObject> &args)
{
    int count = static_cast<int>(args.size());
    std::vector<ValueObject> abindArgs;

    if (count == 0) {
        return E_OK;
    }
    // Obtains the bound parameter set.
    if ((numParameters_ != 0) && (count <= numParameters_)) {
        for (const auto &i : args) {
            abindArgs.push_back(i);
        }

        for (int i = count; i < numParameters_; i++) { // TD: when count <> numParameters
            ValueObject val;
            abindArgs.push_back(val);
        }
    }

    if (count > numParameters_) {
        LOG_ERROR("bind args count(%{public}d) > numParameters(%{public}d), sql: %{public}s", count, numParameters_,
            sql_.c_str());
        return E_INVALID_BIND_ARGS_COUNT;
    }

    return BindArgs(abindArgs);
}

int SqliteStatement::Step()
{
    return sqlite3_step(stmt_);
}

int SqliteStatement::Reset()
{
    if (stmt_ == nullptr) {
        return E_OK;
    }

    int errCode = sqlite3_reset(stmt_);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("reset ret is %{public}d", errCode);
        return SQLiteError::ErrNo(errCode);
    }

    errCode = sqlite3_clear_bindings(stmt_);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("clear_bindings ret is %{public}d", errCode);
        return SQLiteError::ErrNo(errCode);
    }
    return E_OK;
}

int SqliteStatement::Finalize()
{
    if (stmt_ == nullptr) {
        return E_OK;
    }

    int errCode = sqlite3_finalize(stmt_);
    stmt_ = nullptr;
    sql_ = "";
    readOnly_ = false;
    columnCount_ = -1;
    numParameters_ = 0;
    types_ = std::vector<int32_t>();
    if (errCode != SQLITE_OK) {
        LOG_ERROR("finalize ret is %{public}d", errCode);
        return SQLiteError::ErrNo(errCode);
    }
    return E_OK;
}

int SqliteStatement::Execute(const std::vector<ValueObject> &args)
{
    int count = static_cast<int>(args.size());
    if (count != numParameters_) {
        LOG_ERROR("bind args count(%{public}d) > numParameters(%{public}d), sql is %{public}s", count, numParameters_,
            sql_.c_str());
        return E_INVALID_BIND_ARGS_COUNT;
    }

    if (conn_ != nullptr) {
        if (!conn_->IsWriter() && !ReadOnly()) {
            return E_EXECUTE_WRITE_IN_READ_CONNECTION;
        }

        auto errCode = conn_->LimitWalSize();
        if (errCode != E_OK) {
            return errCode;
        }
    }

    auto errCode = BindArgs(args);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = sqlite3_step(stmt_);
    if (errCode != SQLITE_DONE && errCode != SQLITE_ROW) {
        LOG_ERROR("sqlite3_step failed %{public}d, sql is %{public}s", errCode, sql_.c_str());
        return SQLiteError::ErrNo(errCode);
    }
    return E_OK;
}

std::pair<int, ValueObject> SqliteStatement::ExecuteForValue(const std::vector<ValueObject> &args)
{
    auto errCode = Execute(args);
    if (errCode == E_OK) {
        return GetColumn(0);
    }
    return { errCode, ValueObject() };
}

int SqliteStatement::Changes() const
{
    if (stmt_ == nullptr) {
        return -1;
    }
    auto db = sqlite3_db_handle(stmt_);
    return sqlite3_changes(db);
}

int64_t SqliteStatement::LastInsertRowId() const
{
    if (stmt_ == nullptr) {
        return -1;
    }
    auto db = sqlite3_db_handle(stmt_);
    return sqlite3_last_insert_rowid(db);
}

int32_t SqliteStatement::GetColumnCount() const
{
    return columnCount_;
}

std::pair<int32_t, std::string> SqliteStatement::GetColumnName(int index) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return { ret, "" };
    }

    const char *name = sqlite3_column_name(stmt_, index);
    if (name == nullptr) {
        LOG_ERROR("column_name is null.");
        return { E_ERROR, "" };
    }
    return { E_OK, std::string(name) };
}

std::pair<int32_t, int32_t> SqliteStatement::GetColumnType(int index) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return { ret, SQLITE_NULL };
    }

    int type = sqlite3_column_type(stmt_, index);
    if (type != SQLITE_BLOB) {
        return { E_OK, type };
    }
    if (types_[index] != 0) {
        return { E_OK, types_[index] };
    }

    const char *decl = sqlite3_column_decltype(stmt_, index);
    if (decl == nullptr) {
        LOG_ERROR("invalid type %{public}d.", type);
        return { E_ERROR, SQLITE_NULL };
    }

    auto declType = SqliteUtils::StrToUpper(std::string(decl));
    if (declType == ValueObject::DeclType<ValueObject::Asset>()) {
        types_[index] = COLUMN_TYPE_ASSET;
    } else if (declType == ValueObject::DeclType<ValueObject::Assets>()) {
        types_[index] = COLUMN_TYPE_ASSETS;
    } else if (declType == ValueObject::DeclType<ValueObject::FloatVector>()) {
        types_[index] = COLUMN_TYPE_FLOATS;
    } else if (declType == ValueObject::DeclType<ValueObject::BigInt>()) {
        types_[index] = COLUMN_TYPE_BIGINT;
    } else {
        types_[index] = SQLITE_BLOB;
    }

    return { E_OK, types_[index] };
}

std::pair<int32_t, size_t> SqliteStatement::GetSize(int index) const
{
    auto [errCode, type] = GetColumnType(index);
    if (errCode != E_OK) {
        return { errCode, 0 };
    }

    if (type == SQLITE_TEXT || type == SQLITE_BLOB || type == SQLITE_NULL) {
        auto size = static_cast<size_t>(sqlite3_column_bytes(stmt_, index));
        return { E_OK, size };
    }
    return { E_INVALID_COLUMN_TYPE, 0 };
}

std::pair<int32_t, ValueObject> SqliteStatement::GetColumn(int index) const
{
    auto [errCode, type] = GetColumnType(index);
    if (errCode != E_OK) {
        return { errCode, ValueObject() };
    }

    switch (type) {
        case SQLITE_FLOAT:
            return { E_OK, ValueObject(sqlite3_column_double(stmt_, index)) };
        case SQLITE_INTEGER:
            return { E_OK, ValueObject(static_cast<int64_t>(sqlite3_column_int64(stmt_, index))) };
        case SQLITE_TEXT: {
            int size = sqlite3_column_bytes(stmt_, index);
            auto text = reinterpret_cast<const char *>(sqlite3_column_text(stmt_, index));
            return { E_OK, ValueObject(text == nullptr ? std::string("") : std::string(text, size)) };
        }
        case SQLITE_NULL:
            return { E_OK, ValueObject() };
        default:
            break;
    }
    return { E_OK, GetValueFromBlob(index, type) };
}

ValueObject SqliteStatement::GetValueFromBlob(int32_t index, int32_t type) const
{
    int size = sqlite3_column_bytes(stmt_, index);
    auto blob = static_cast<const uint8_t *>(sqlite3_column_blob(stmt_, index));
    if (blob == nullptr || size <= 0) {
        return ValueObject();
    }
    switch (type) {
        case COLUMN_TYPE_ASSET: {
            Asset asset;
            RawDataParser::ParserRawData(blob, size, asset);
            return ValueObject(std::move(asset));
        }
        case COLUMN_TYPE_ASSETS: {
            Assets assets;
            RawDataParser::ParserRawData(blob, size, assets);
            return ValueObject(std::move(assets));
        }
        case COLUMN_TYPE_FLOATS: {
            Floats floats;
            RawDataParser::ParserRawData(blob, size, floats);
            return ValueObject(std::move(floats));
        }
        case COLUMN_TYPE_BIGINT: {
            BigInt bigint;
            RawDataParser::ParserRawData(blob, size, bigint);
            return ValueObject(std::move(bigint));
        }
        default:
            break;
    }
    return ValueObject(std::vector<uint8_t>(blob, blob + size));
}

bool SqliteStatement::ReadOnly() const
{
    return readOnly_;
}

bool SqliteStatement::SupportBlockInfo() const
{
    auto db = sqlite3_db_handle(stmt_);
    return (sqlite3_db_config(db, SQLITE_USE_SHAREDBLOCK) == SQLITE_OK);
}

int32_t SqliteStatement::FillBlockInfo(SharedBlockInfo *info) const
{
    if (info == nullptr) {
        return E_ERROR;
    }
    int32_t errCode = E_OK;
    if (SupportBlockInfo()) {
        errCode = FillSharedBlockOpt(info, stmt_);
    } else {
        errCode = FillSharedBlock(info, stmt_);
    }
    if (errCode != E_OK) {
        return errCode;
    }
    if (!ResetStatement(info, stmt_)) {
        LOG_ERROR("ResetStatement Failed.");
        return E_ERROR;
    }
    return E_OK;
}

int32_t SqliteStatement::BindNil(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    return sqlite3_bind_null(stat, index);
}

int32_t SqliteStatement::BindInteger(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<int64_t>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_int64(stat, index, *val);
}

int32_t SqliteStatement::BindDouble(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<double>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_double(stat, index, *val);
}

int32_t SqliteStatement::BindText(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<std::string>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_text(stat, index, val->c_str(), val->length(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindBool(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<bool>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_int64(stat, index, *val ? 1 : 0);
}

int32_t SqliteStatement::BindBlob(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<std::vector<uint8_t>>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_blob(stat, index, static_cast<const void *>((*val).data()), (*val).size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindAsset(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<Asset>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void *>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindAssets(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<Assets>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void *>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindFloats(sqlite3_stmt *stat, int index, const ValueObject::Type &object)
{
    auto val = std::get_if<Floats>(&object);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void *>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindBigInt(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<BigInt>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void *>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int SqliteStatement::ModifyLockStatus(const std::string &table, const std::vector<std::vector<uint8_t>> &hashKeys,
    bool isLock)
{
    ::DistributedDB::DBStatus ret;
    auto db = sqlite3_db_handle(stmt_);
    if (db == nullptr) {
        return E_ERROR;
    }
    if (isLock) {
        ret = Lock(table, hashKeys, db);
    } else {
        ret = UnLock(table, hashKeys, db);
    }
    if (ret == ::DistributedDB::DBStatus::OK) {
        return E_OK;
    }
    if (ret == ::DistributedDB::DBStatus::WAIT_COMPENSATED_SYNC) {
        return E_WAIT_COMPENSATED_SYNC;
    }
    if (ret == ::DistributedDB::DBStatus::NOT_FOUND) {
        return E_NO_ROW_IN_QUERY;
    }
    LOG_ERROR("Lock/Unlock failed, err is %{public}d.", ret);
    return E_ERROR;
}
} // namespace NativeRdb
} // namespace OHOS
