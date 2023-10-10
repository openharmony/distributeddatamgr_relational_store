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
#include "rdb_trace.h"
#include "sqlite3sym.h"
#include "rdb_sql_utils.h"
#include "sqlite_errno.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

StepResultSet::StepResultSet(std::shared_ptr<RdbStoreImpl> rdb, SqliteConnectionPool *connectionPool,
    const std::string &sql, const std::vector<ValueObject> &selectionArgs)
    : rdb_(rdb), connectionPool_(connectionPool), sql_(sql), args_(std::move(selectionArgs)), isAfterLast_(false),
      rowCount_(INIT_POS), sqliteStatement_(nullptr)
{
    PrepareStep();
}

StepResultSet::~StepResultSet()
{
    Close();
    rdb_.reset();
}

int StepResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    if (!columnNames_.empty()) {
        columnNames = columnNames_;
        return E_OK;
    }

    if (isClosed) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    int errCode = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("PrepareStep ret %{public}d", errCode);
        return errCode;
    }

    int columnCount = 0;
    errCode = sqliteStatement_->GetColumnCount(columnCount);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnCount ret %{public}d", errCode);
        return errCode;
    }

    columnNames.clear();
    for (int i = 0; i < columnCount; i++) {
        std::string columnName;
        errCode = sqliteStatement_->GetColumnName(i, columnName);
        if (errCode != E_OK) {
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
    if (isClosed) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        LOG_ERROR("query not executed.");
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    int sqliteType;
    if (sqliteStatement_ == nullptr) {
       return E_CON_OVER_LIMIT;
    }
    int errCode = sqliteStatement_->GetColumnType(columnIndex, sqliteType);
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
    if (isClosed) {
        LOG_ERROR("resultSet closed");
        return E_STEP_RESULT_CLOSED;
    }

    int errCode = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("PrepareStep ret %{public}d", errCode);
        return errCode;
    }

    int retryCount = 0;
    errCode = sqliteStatement_->Step();

    while (errCode == SQLITE_LOCKED || errCode == SQLITE_BUSY) {
        // The table is locked, retry
        if (retryCount > STEP_QUERY_RETRY_MAX_TIMES) {
            LOG_ERROR("Step in busy ret is %{public}d", errCode);
            return E_STEP_RESULT_QUERY_EXCEEDED;
        } else {
            // Sleep to give the thread holding the lock a chance to finish
            usleep(STEP_QUERY_RETRY_INTERVAL);
            errCode = sqliteStatement_->Step();
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
    if (isClosed) {
        return E_OK;
    }
    isClosed = true;
    int errCode = FinishStep();

    if (sqliteStatement_ != nullptr) {
        sqliteStatement_->ResetStatementAndClearBindings();
        sqliteStatement_ = nullptr;
    }
    return errCode;
}

/**
 * Obtain session and prepare precompile statement for step query
 */
int StepResultSet::PrepareStep()
{
    if (sqliteStatement_ != nullptr) {
        return E_OK;
    }

    if (SqliteUtils::GetSqlStatementType(sql_) != SqliteUtils::STATEMENT_SELECT) {
        LOG_ERROR("not a select sql!");
        return E_EXECUTE_IN_STEP_QUERY;
    }

    int errCode;
    SqliteConnection *connection = connectionPool_->AcquireConnection(true);
    sqliteStatement_ = connection->StepQueryPrepare(errCode, sql_, args_);
    connectionPool_->ReleaseConnection(connection);
    if (sqliteStatement_ == nullptr) {
        LOG_ERROR("BeginStepQuery ret is %{public}d", errCode);
        return errCode;
    }

    return E_OK;
}

/**
 * Release resource of step result set, this method can be called more than once
 */
int StepResultSet::FinishStep()
{
    if (sqliteStatement_ == nullptr) {
        return E_OK;
    }

    rowPos_ = INIT_POS;

    return E_OK;
}

/**
 * Reset the statement
 */
void StepResultSet::Reset()
{
    if (sqliteStatement_ != nullptr) {
        sqlite3_reset(sqliteStatement_->GetSql3Stmt());
    }
    rowPos_ = INIT_POS;
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
    if (isClosed) {
        return E_STEP_RESULT_CLOSED;
    }
    if (rowPos_ == INIT_POS) {
        LOG_ERROR("query not executed.");
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    return sqliteStatement_->GetColumnBlob(columnIndex, blob);
}

int StepResultSet::GetString(int columnIndex, std::string &value)
{
    if (isClosed) {
        return E_STEP_RESULT_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    int errCode = sqliteStatement_->GetColumnString(columnIndex, value);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int StepResultSet::GetInt(int columnIndex, int &value)
{
    if (isClosed) {
        return E_STEP_RESULT_CLOSED;
    }
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    int64_t columnValue;
    int errCode = sqliteStatement_->GetColumnLong(columnIndex, columnValue);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    value = static_cast<int>(columnValue);
    return E_OK;
}

int StepResultSet::GetLong(int columnIndex, int64_t &value)
{
    if (isClosed) {
        return E_STEP_RESULT_CLOSED;
    }
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    int errCode = sqliteStatement_->GetColumnLong(columnIndex, value);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int StepResultSet::GetDouble(int columnIndex, double &value)
{
    if (isClosed) {
        return E_STEP_RESULT_CLOSED;
    }
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    int errCode = sqliteStatement_->GetColumnDouble(columnIndex, value);
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
    if (isClosed) {
        return E_STEP_RESULT_CLOSED;
    }
    if (rowPos_ == INIT_POS) {
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }
    auto index = std::find(columnNames_.begin(), columnNames_.end(), "modifyTime");
    int errCode = sqliteStatement_->GetColumnString(index - columnNames_.begin(), modifyTime);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int StepResultSet::GetSize(int columnIndex, size_t &size)
{
    if (rowPos_ == INIT_POS) {
        size = 0;
        return E_STEP_RESULT_QUERY_NOT_EXECUTED;
    }

    return sqliteStatement_->GetSize(columnIndex, size);
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
    return isClosed;
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
    if (isClosed) {
        return { E_STEP_RESULT_CLOSED, ValueObject() };
    }

    if (rowPos_ == INIT_POS) {
        return { E_STEP_RESULT_QUERY_NOT_EXECUTED, ValueObject() };
    }

    ValueObject value;
    auto ret = sqliteStatement_->GetColumn(col, value);
    if (index < ValueObject::TYPE_MAX && value.value.index() != index) {
        return { E_INVALID_COLUMN_TYPE, ValueObject() };
    }
    return { ret, std::move(value) };
}
} // namespace NativeRdb
} // namespace OHOS