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
#define LOG_TAG "StepResultSet"
#include "step_result_set.h"

#include <unistd.h>

#include "logger.h"
#include "rdb_errno.h"
#include "sqlite3sym.h"
#include "sqlite_connection_pool.h"
#include "sqlite_errno.h"
#include "sqlite_statement.h"
#include "sqlite_utils.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
StepResultSet::StepResultSet(
    std::shared_ptr<SqliteConnectionPool> pool, const std::string &sql_, const std::vector<ValueObject> &selectionArgs)
    : AbsResultSet(), args_(std::move(selectionArgs)), sql_(sql_), rowCount_(INIT_POS), isAfterLast_(false),
      isStarted_(false)
{
    conn_ = pool->AcquireRef(true);
    if (conn_ == nullptr) {
        return;
    }

    auto errCode = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("step resultset ret %{public}d", errCode);
    }
}

StepResultSet::~StepResultSet()
{
    Close();
}

/**
 * Obtain session and prepare precompile statement for step query
 */
int StepResultSet::PrepareStep()
{
    if (sqliteStatement_ != nullptr) {
        return E_OK;
    }

    if (conn_ == nullptr) {
        return E_ALREADY_CLOSED;
    }

    auto type = SqliteUtils::GetSqlStatementType(sql_);
    if (type != SqliteUtils::STATEMENT_SELECT && type != SqliteUtils::STATEMENT_OTHER) {
        LOG_ERROR("not a select sql_!");
        return E_NOT_SELECT ;
    }

    auto [errCode, statement] = conn_->CreateStatement(sql_, conn_);
    if (statement == nullptr || errCode != E_OK) {
        return E_STATEMENT_NOT_PREPARED;
    }

    errCode = statement->Bind(args_);
    if (errCode != E_OK) {
        LOG_ERROR("Bind arg faild! Ret is %{public}d", errCode);
        statement->Reset();
        statement = nullptr;
        return errCode;
    }

    sqliteStatement_ = std::move(statement);
    if (sqliteStatement_ == nullptr) {
        LOG_ERROR("sqliteStatement_ is nullptr");
    }
    return E_OK;
}

int StepResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    if (!columnNames_.empty()) {
        columnNames = columnNames_;
        return E_OK;
    }

    int errorCode = PrepareStep();
    if (errorCode != E_OK) {
        return errorCode;
    }

    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("Statement is nullptr");
        return E_ALREADY_CLOSED;
    }

    auto columnCount = statement->GetColumnCount();

    columnNames.clear();
    for (int i = 0; i < columnCount; i++) {
        auto [errCode, columnName] = statement->GetColumnName(i);
        if (errCode) {
            columnNames.clear();
            LOG_ERROR("GetColumnName ret %{public}d", errCode);
            return errCode;
        }
        columnNames.push_back(columnName);
    }

    return E_OK;
}

int StepResultSet::GetColumnType(int columnIndex, ColumnType &columnType)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (rowPos_ == INIT_POS || isAfterLast_) {
        LOG_ERROR("query not executed.");
        return E_NOT_INIT;
    }
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("Statement is nullptr");
        return E_ALREADY_CLOSED;
    }

    auto [errCode, sqliteType] = statement->GetColumnType(columnIndex);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnType ret %{public}d", errCode);
        return errCode;
    }

    switch (sqliteType) {
        case SQLITE_INTEGER:
            columnType = ColumnType::TYPE_INTEGER;
            break;
        case SQLITE_FLOAT:
            columnType = ColumnType::TYPE_FLOAT;
            break;
        case SQLITE_BLOB:
            columnType = ColumnType::TYPE_BLOB;
            break;
        case SqliteStatement::COLUMN_TYPE_ASSET:
            columnType = ColumnType::TYPE_ASSET;
            break;
        case SqliteStatement::COLUMN_TYPE_ASSETS:
            columnType = ColumnType::TYPE_ASSETS;
            break;
        case SqliteStatement::COLUMN_TYPE_FLOATS:
            columnType = ColumnType::TYPE_FLOAT32_ARRAY;
            break;
        case SqliteStatement::COLUMN_TYPE_BIGINT:
            columnType = ColumnType::TYPE_BIGINT;
            break;
        case SQLITE_NULL:
            columnType = ColumnType::TYPE_NULL;
            break;
        default:
            columnType = ColumnType::TYPE_STRING;
    }

    return E_OK;
}

int StepResultSet::GetRowCount(int &count)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (rowCount_ != INIT_POS) {
        count = rowCount_;
        return E_OK;
    }
    int oldPosition = 0;
    // Get the start position of the query result
    GetRowIndex(oldPosition);

    while (GoToNextRow() == E_OK) {
    }
    count = rowCount_;
    // Reset the start position of the query result
    if (oldPosition != INIT_POS) {
        GoToRow(oldPosition);
    } else {
        Reset();
        isStarted_ = false;
    }
    return E_OK;
}

/**
 * Moves the result set to a specified position
 */
int StepResultSet::GoToRow(int position)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (position < 0) {
        LOG_ERROR("position %{public}d.", position);
        return E_ERROR;
    }
    if (position == rowPos_) {
        return E_OK;
    }
    if (position < rowPos_) {
        Reset();
        return GoToRow(position);
    }
    while (position != rowPos_) {
        int errCode = GoToNextRow();
        if (errCode != E_OK) {
            LOG_ERROR("GoToNextRow ret %{public}d", errCode);
            return errCode;
        }
    }

    return E_OK;
}

/**
 * Move the result set to the next row
 */
int StepResultSet::GoToNextRow()
{
    if (isClosed_) {
        LOG_ERROR("resultSet closed");
        return E_ALREADY_CLOSED;
    }

    int errCode = PrepareStep();
    if (errCode != E_OK) {
        return errCode;
    }

    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("Statement is nullptr");
        return E_ALREADY_CLOSED;
    }

    int retryCount = 0;
    errCode = statement->Step();

    while (errCode == SQLITE_LOCKED || errCode == SQLITE_BUSY) {
        // The table is locked, retry
        if (retryCount > STEP_QUERY_RETRY_MAX_TIMES) {
            LOG_ERROR("Step in busy ret is %{public}d", errCode);
            return E_STEP_RESULT_QUERY_EXCEEDED;
        } else {
            // Sleep to give the thread holding the lock a chance to finish
            usleep(STEP_QUERY_RETRY_INTERVAL);
            errCode = statement->Step();
            retryCount++;
        }
    }

    if (errCode == SQLITE_ROW) {
        rowPos_++;
        isStarted_ = true;
        return E_OK;
    } else if (errCode == SQLITE_DONE) {
        if (!isAfterLast_ && rowCount_ != EMPTY_ROW_COUNT) {
            rowCount_ = rowPos_ + 1;
        }
        isAfterLast_ = rowCount_ != EMPTY_ROW_COUNT;
        isStarted_ = true;
        FinishStep();
        rowPos_ = rowCount_;
        return E_NO_MORE_ROWS;
    } else {
        FinishStep();
        rowPos_ = rowCount_;
        return SQLiteError::ErrNo(errCode);
    }
}

int StepResultSet::Close()
{
    if (isClosed_) {
        return E_OK;
    }
    isClosed_ = true;
    conn_ = nullptr;
    sqliteStatement_ = nullptr;
    auto args = std::move(args_);
    auto columnNames = std::move(columnNames_);
    return FinishStep();
}

/**
 * Release resource of step result set, this method can be called more than once
 */
int StepResultSet::FinishStep()
{
    auto statement = GetStatement();
    if (statement != nullptr) {
        statement->Reset();
        sqliteStatement_ = nullptr;
    }
    rowPos_ = INIT_POS;
    return E_OK;
}

/**
 * Reset the statement
 */
void StepResultSet::Reset()
{
    FinishStep();
    isAfterLast_ = false;
}

/**
 * Checks whether the result set is positioned after the last row
 */
int StepResultSet::IsEnded(bool &result)
{
    result = isAfterLast_;
    return E_OK;
}

/**
 * Checks whether the result set is moved
 */
int StepResultSet::IsStarted(bool &result) const
{
    result = isStarted_;
    return E_OK;
}

/**
 * Check whether the result set is in the first row
 */
int StepResultSet::IsAtFirstRow(bool &result) const
{
    result = (rowPos_ == 0) && (rowCount_ != 0);
    return E_OK;
}

int StepResultSet::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    ValueObject valueObject;
    int errorCode = Get(columnIndex, valueObject);
    if (errorCode != E_OK) {
        return errorCode;
    }
    blob.resize(0);
    int type = valueObject.GetType();
    if (type == ValueObject::TYPE_BLOB) {
        blob = std::get<std::vector<uint8_t>>(valueObject.value);
        return E_OK;
    } else if (type == ValueObject::TYPE_STRING) {
        auto temp = std::get<std::string>(valueObject.value);
        blob.assign(temp.begin(), temp.end());
        return E_OK;
    } else if (type == ValueObject::TYPE_NULL) {
        return E_OK;
    }
    LOG_ERROR("type invalid col:%{public}d, type:%{public}d!", columnIndex, type);
    return E_INVALID_OBJECT_TYPE;
}

int StepResultSet::GetString(int columnIndex, std::string &value)
{
    ValueObject valueObject;
    int errorCode = Get(columnIndex, valueObject);
    if (errorCode != E_OK) {
        return errorCode;
    }
    int type = valueObject.GetType();
    if (type == ValueObject::TYPE_INT) {
        auto temp = std::get<int64_t>(valueObject.value);
        value = std::to_string(temp);
    } else if (type == ValueObject::TYPE_DOUBLE) {
        double temp = std::get<double>(valueObject.value);
        std::ostringstream os;
        if (os << temp) {
            value = os.str();
        }
    } else if (type == ValueObject::TYPE_STRING) {
        value = std::get<std::string>(valueObject.value);
    } else if (type == ValueObject::TYPE_BLOB) {
        return E_INVALID_COLUMN_TYPE;
    } else {
        return E_ERROR;
    }
    return E_OK;
}

int StepResultSet::GetInt(int columnIndex, int &value)
{
    int64_t temp = 0;
    int errCode = GetLong(columnIndex, temp);
    if (errCode != E_OK) {
        return errCode;
    }
    value = int32_t(temp);
    return E_OK;
}

int StepResultSet::GetLong(int columnIndex, int64_t &value)
{
    ValueObject valueObject;
    int errorCode = Get(columnIndex, valueObject);
    if (errorCode != E_OK) {
        return errorCode;
    }
    value = 0L;
    int type = valueObject.GetType();
    if (type == ValueObject::TYPE_INT) {
        value = std::get<int64_t>(valueObject.value);
    } else if (type == ValueObject::TYPE_DOUBLE) {
        value = int64_t(std::get<double>(valueObject.value));
    } else if (type == ValueObject::TYPE_STRING) {
        auto temp = std::get<std::string>(valueObject.value);
        value = temp.empty() ? 0L : (int64_t)strtoll(temp.c_str(), nullptr, 0);
    } else if (type == ValueObject::TYPE_ASSETS || type == ValueObject::TYPE_ASSET) {
        LOG_ERROR("type invalid col:%{public}d, type:%{public}d!", columnIndex, type);
        return E_INVALID_OBJECT_TYPE;
    } else {
        return E_ERROR;
    }
    return E_OK;
}

int StepResultSet::GetDouble(int columnIndex, double &value)
{
    ValueObject valueObject;
    int errorCode = Get(columnIndex, valueObject);
    if (errorCode != E_OK) {
        return errorCode;
    }
    value = 0.0L;
    int type = valueObject.GetType();
    if (type == ValueObject::TYPE_INT) {
        value = double(std::get<int64_t>(valueObject.value));
    } else if (type == ValueObject::TYPE_DOUBLE) {
        value = std::get<double>(valueObject.value);
    } else if (type == ValueObject::TYPE_STRING) {
        auto temp = std::get<std::string>(valueObject.value);
        value = temp.empty() ? 0.0 : (double)strtod(temp.c_str(), nullptr);
    } else if (type == ValueObject::TYPE_ASSETS || type == ValueObject::TYPE_ASSET) {
        LOG_ERROR("type invalid col:%{public}d, type:%{public}d!", columnIndex, type);
        return E_INVALID_OBJECT_TYPE;
    } else {
        return E_ERROR;
    }

    return E_OK;
}

int StepResultSet::GetAsset(int32_t col, ValueObject::Asset &value)
{
    ValueObject valueObject;
    int errorCode = Get(col, valueObject);
    if (errorCode != E_OK) {
        return errorCode;
    }

    if (valueObject.GetType() == ValueObject::TYPE_NULL) {
        return E_NULL_OBJECT;
    }

    if (valueObject.GetType() != ValueObject::TYPE_ASSET) {
        LOG_ERROR("the type is not assets, type is %{public}d, col is %{public}d!", valueObject.GetType(), col);
        return E_INVALID_OBJECT_TYPE;
    }
    value = valueObject;
    return E_OK;
}

int StepResultSet::GetAssets(int32_t col, ValueObject::Assets &value)
{
    ValueObject valueObject;
    int errorCode = Get(col, valueObject);
    if (errorCode != E_OK) {
        return errorCode;
    }

    if (valueObject.GetType() == ValueObject::TYPE_NULL) {
        return E_NULL_OBJECT;
    }

    if (valueObject.GetType() != ValueObject::TYPE_ASSETS) {
        LOG_ERROR("the type is not assets, type is %{public}d, col is %{public}d!", valueObject.GetType(), col);
        return E_INVALID_OBJECT_TYPE;
    }
    value = valueObject;
    return E_OK;
}

int StepResultSet::Get(int32_t col, ValueObject &value)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    return GetValue(col, value);
}

int StepResultSet::GetSize(int columnIndex, size_t &size)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (rowPos_ == INIT_POS || isAfterLast_) {
        size = 0;
        return E_NOT_INIT;
    }

    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("Statement is nullptr");
        return E_ALREADY_CLOSED;
    }
    auto errCode = E_ERROR;
    std::tie(errCode, size) = statement->GetSize(columnIndex);
    return errCode;
}

int StepResultSet::IsColumnNull(int columnIndex, bool &isNull)
{
    ColumnType columnType;
    int errCode = GetColumnType(columnIndex, columnType);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    isNull = (columnType == ColumnType::TYPE_NULL);
    return E_OK;
}

/**
 * Check whether the result set is over
 */
bool StepResultSet::IsClosed() const
{
    return isClosed_;
}

template<typename T>
int StepResultSet::GetValue(int32_t col, T &value)
{
    auto [errCode, object] = GetValueObject(col, ValueObject::TYPE_INDEX<decltype(value)>);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    value = static_cast<T>(object);
    return E_OK;
}

std::pair<int, ValueObject> StepResultSet::GetValueObject(int32_t col, size_t index)
{
    if (rowPos_ == INIT_POS || isAfterLast_) {
        return { E_NOT_INIT, ValueObject() };
    }
    auto statement = GetStatement();
    if (statement == nullptr) {
        return { E_ALREADY_CLOSED, ValueObject() };
    }
    auto [ret, value] = statement->GetColumn(col);
    if (index < ValueObject::TYPE_MAX && value.value.index() != index) {
        return { E_INVALID_COLUMN_TYPE, ValueObject() };
    }
    return { ret, std::move(value) };
}

std::shared_ptr<Statement> StepResultSet::GetStatement()
{
    if (isClosed_ || conn_ == nullptr) {
        return nullptr;
    }

    return sqliteStatement_;
}
} // namespace NativeRdb
} // namespace OHOS