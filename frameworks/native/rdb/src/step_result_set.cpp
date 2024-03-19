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

#include "step_result_set.h"

#include <unistd.h>

#include "logger.h"
#include "rdb_errno.h"
#include "sqlite3sym.h"
#include "sqlite_errno.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

StepResultSet::StepResultSet(std::shared_ptr<SqliteConnectionPool> pool, const std::string& sql_,
    const std::vector<ValueObject>& selectionArgs)
    : sqliteStatement_(nullptr), args_(std::move(selectionArgs)), sql_(sql_), rowCount_(INIT_POS), isAfterLast_(false)
{
    auto connection = pool->AcquireConnection(true);
    if (connection == nullptr) {
        return;
    }
    conn_ = pool->AcquireByID(connection->GetId());
    if (conn_ == nullptr) {
        conn_ = connection;
    }

    int errCode = PrepareStep();
    if (errCode) {
        LOG_ERROR("step resultset ret %{public}d", errCode);
    }
}

StepResultSet::~StepResultSet()
{
    Close();
}

int StepResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    if (!columnNames_.empty()) {
        columnNames = columnNames_;
        return E_OK;
    }

    if (isClosed_) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    int errCode = PrepareStep();
    if (errCode) {
        LOG_ERROR("get all column names Step ret %{public}d", errCode);
        return errCode;
    }
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }
    int columnCount = 0;
    errCode = statement->GetColumnCount(columnCount);
    if (errCode) {
        LOG_ERROR("GetColumnCount ret %{public}d", errCode);
        return errCode;
    }

    columnNames.clear();
    for (int i = 0; i < columnCount; i++) {
        std::string columnName;
        errCode = statement->GetColumnName(i, columnName);
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
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        LOG_ERROR("query not executed.");
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    int sqliteType;
    int errCode = statement->GetColumnType(columnIndex, sqliteType);
    if (errCode) {
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
    GoToRow(oldPosition);

    return E_OK;
}

/**
 * Moves the result set to a specified position
 */
int StepResultSet::GoToRow(int position)
{
    // If the moved position is less than zero, reset the result and return an error
    if (position < 0) {
        LOG_DEBUG("position %{public}d.", position);
        Reset();
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
        if (errCode) {
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
        return E_STEP_RESULT_CLOSED;
    }

    int errCode = PrepareStep();
    if (errCode) {
        LOG_ERROR("go to nextrow step ret %{public}d", errCode);
        return errCode;
    }

    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
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
        return E_OK;
    } else if (errCode == SQLITE_DONE) {
        isAfterLast_ = true;
        rowCount_ = rowPos_ + 1;
        FinishStep();
        rowPos_ = rowCount_;
        return E_STEP_RESULT_IS_AFTER_LAST;
    } else {
        LOG_ERROR("step ret is %{public}d", errCode);
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

    auto args = std::move(args_);
    sqliteStatement_ = nullptr;
    conn_ = nullptr;
    auto columnNames = std::move(columnNames_);
    return FinishStep();
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
        return E_STEP_RESULT_CLOSED;
    }

    if (SqliteUtils::GetSqlStatementType(sql_) != SqliteUtils::STATEMENT_SELECT) {
        LOG_ERROR("not a select sql_!");
        return E_EXECUTE_IN_STEP_QUERY;
    }

    auto statement = SqliteStatement::CreateStatement(conn_, sql_);
    if (statement == nullptr) {
        return E_STATEMENT_NOT_PREPARED;
    }

    int errCode = statement->BindArguments(args_);
    if (errCode != E_OK) {
        LOG_ERROR("Bind arg faild! Ret is %{public}d", errCode);
        statement->ResetStatementAndClearBindings();
        statement = nullptr;
        return errCode;
    }
    sqliteStatement_ = std::move(statement);
    return E_OK;
}

/**
 * Release resource of step result set, this method can be called more than once
 */
int StepResultSet::FinishStep()
{
    auto statement = GetStatement();
    if (statement != nullptr) {
        statement->ResetStatementAndClearBindings();
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
    result = (rowPos_ != INIT_POS);
    return E_OK;
}

/**
 * Check whether the result set is in the first row
 */
int StepResultSet::IsAtFirstRow(bool &result) const
{
    result = (rowPos_ == 0);
    return E_OK;
}

int StepResultSet::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        LOG_ERROR("query not executed.");
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    return statement->GetColumnBlob(columnIndex, blob);
}

int StepResultSet::GetString(int columnIndex, std::string &value)
{
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    int errCode = statement->GetColumnString(columnIndex, value);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int StepResultSet::GetInt(int columnIndex, int &value)
{
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    int64_t columnValue;
    int errCode = statement->GetColumnLong(columnIndex, columnValue);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    value = static_cast<int>(columnValue);
    return E_OK;
}

int StepResultSet::GetLong(int columnIndex, int64_t &value)
{
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    int errCode = statement->GetColumnLong(columnIndex, value);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int StepResultSet::GetDouble(int columnIndex, double &value)
{
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    int errCode = statement->GetColumnDouble(columnIndex, value);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int StepResultSet::GetAsset(int32_t col, ValueObject::Asset &value)
{
    return GetValue(col, value);
}

int StepResultSet::GetAssets(int32_t col, ValueObject::Assets &value)
{
    return GetValue(col, value);
}

int StepResultSet::Get(int32_t col, ValueObject &value)
{
    return GetValue(col, value);
}

int StepResultSet::GetModifyTime(std::string &modifyTime)
{
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    auto index = std::find(columnNames_.begin(), columnNames_.end(), "modifyTime");
    int errCode = statement->GetColumnString(index - columnNames_.begin(), modifyTime);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int StepResultSet::GetSize(int columnIndex, size_t &size)
{
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        size = 0;
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    return statement->GetSize(columnIndex, size);
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
    value = object;
    return E_OK;
}

std::pair<int, ValueObject> StepResultSet::GetValueObject(int32_t col, size_t index)
{
    auto statement = GetStatement();
    if (statement == nullptr) {
        return { E_STEP_RESULT_CLOSED, ValueObject() };
    }

    if (rowPos_ == INIT_POS) {
        return { E_STEP_RESULT_QUERY_NOT_EXECUTED, ValueObject() };
    }

    ValueObject value;
    auto ret = statement->GetColumn(col, value);
    if (index < ValueObject::TYPE_MAX && value.value.index() != index) {
        return { E_INVALID_COLUMN_TYPE, ValueObject() };
    }
    return { ret, std::move(value) };
}

std::shared_ptr<SqliteStatement> StepResultSet::GetStatement()
{
    if (isClosed_ || conn_ == nullptr) {
        return nullptr;
    }

    return sqliteStatement_;
}
} // namespace NativeRdb
} // namespace OHOS