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
#define LOG_TAG "RdSharedResultSet"
#include "rd_result_set.h"
#include "step_result_set.h"
#include <unistd.h>
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_sql_utils.h"
#include "rdb_trace.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

RdSharedResultSet::RdSharedResultSet(std::shared_ptr<RdbConnectionPool> connectionPool, const std::string &sql,
    const std::vector<ValueObject>& selectionArgs)
    : statement_(nullptr), args_(std::move(selectionArgs)), sql_(sql),
      rdConnectionPool_(std::move(connectionPool)), rowCount_(INIT_POS), isAfterLast_(false)
{
    int errCode = PrepareStep();
    if (errCode) {
        LOG_ERROR("step resultset ret %{public}d", errCode);
    }
}

RdSharedResultSet::RdSharedResultSet(std::shared_ptr<RdbConnectionPool> connectionPool, const std::string &sql_,
    const std::vector<ValueObject>& selectionArgs, int rowCount)
    : statement_(nullptr), args_(std::move(selectionArgs)), sql_(sql_),
      rdConnectionPool_(std::move(connectionPool)), rowCount_(rowCount), isAfterLast_(false)
{
}

RdSharedResultSet::~RdSharedResultSet()
{
    Close();
}

std::pair<int, std::vector<std::string>> RdSharedResultSet::GetColumnNames()
{
    if (isClosed_) {
        LOG_ERROR("fail, result set has been closed, ret %{public}d, sql %{public}s", E_ALREADY_CLOSED, sql_.c_str());
        return { E_ALREADY_CLOSED, {} };
    }
    std::vector<std::string> columnNames;
    int errCode = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("get all column names Step ret %{public}d", errCode);
        return { errCode, {} };
    }
    auto [statement, connection] = GetStatement();
    if (statement == nullptr) {
        return { E_ALREADY_CLOSED, {} };
    }
    bool needReset = false;
    if (rowPos_ == INIT_POS) {
        errCode = statement->Step();
        if (errCode != E_OK && errCode != E_NO_MORE_ROWS) {
            return { errCode, {} };
        }
        needReset = true;
    }
    int columnCount = 0;
    errCode = statement->GetColumnCount(columnCount);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnCount errCode is %{public}d", errCode);
        return { errCode, {} };
    }
    columnNames.clear();
    for (int i = 0; i < columnCount; i++) {
        std::string columnName;
        errCode = statement->GetColumnName(i, columnName);
        if (errCode != E_OK) {
            columnNames.clear();
            LOG_ERROR("GetColumnName errCode is %{public}d", errCode);
            return { errCode, {} };
        }
        columnNames.push_back(columnName);
    }
    if (needReset) {
        rowPos_ = INIT_POS;
        errCode = statement->ResetStatementAndClearBindings();
    }

    return { errCode, std::move(columnNames) };
}

int RdSharedResultSet::GetColumnType(int columnIndex, ColumnType &columnType)
{
    auto [statement, connection] = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("the resultSet is closed");
        return E_ALREADY_CLOSED;
    }
    if (rowPos_ == INIT_POS) {
        LOG_ERROR("query not executed.");
        return E_ROW_OUT_RANGE;
    }
    int outputType;
    int errCode = statement->GetColumnType(columnIndex, outputType);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnType errCode is %{public}d", errCode);
        return errCode;
    }
    columnType = static_cast<ColumnType>(outputType);
    return E_OK;
}

int RdSharedResultSet::GetRowCount(int &count)
{
    if (rowCount_ != INIT_POS) {
        count = rowCount_;
        return E_OK;
    }
    int oldPosition = 0;
    // Get the start position of the query result
    GetRowIndex(oldPosition);
    int ret = E_OK;
    while (ret == E_OK) {
        ret = GoToNextRow();
        if (ret != E_OK) {
            break;
        }
    }
    count = rowCount_;
    // Reset the start position of the query result
    GoToRow(oldPosition);
    return E_OK;
}

int RdSharedResultSet::GoToRow(int position)
{
    // If the moved position is less than zero, reset the result and return an error
    if (position < 0) {
        LOG_DEBUG("position is %{public}d", position);
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
            LOG_ERROR("GoToNextRow errCode is %{public}d", errCode);
            return errCode;
        }
    }
    return E_OK;
}

int RdSharedResultSet::GoToNextRow()
{
    if (isClosed_) {
        LOG_ERROR("the resultSet is closed");
        return E_ALREADY_CLOSED;
    }
    int errCode = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("go to next row step errCode is %{public}d", errCode);
        return errCode;
    }
    auto [statement, conn] = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("the resultSet is closed");
        return E_ALREADY_CLOSED;
    }
    errCode = statement->Step();
    if (errCode == E_OK) {
        rowPos_++;
        return E_OK;
    } else if (errCode == E_NO_MORE_ROWS) {
        isAfterLast_ = true;
        RdSharedResultSet::rowCount_ = rowPos_ + 1;
        RdSharedResultSet::FinishStep();
        rowPos_ = RdSharedResultSet::rowCount_;
        return E_NO_MORE_ROWS;
    } else {
        LOG_ERROR("step errCode is %{public}d", errCode);
        RdSharedResultSet::FinishStep();
        rowPos_ = RdSharedResultSet::rowCount_;
        return errCode;
    }
}

int RdSharedResultSet::PrepareStep()
{
    if (statement_ != nullptr) {
        LOG_INFO("statement_ is not nullptr");
        return E_OK;
    }
    if (SqliteUtils::GetSqlStatementType(sql_) != SqliteUtils::STATEMENT_SELECT) {
        LOG_ERROR("not a select sql_!");
        return E_NOT_SELECT;
    }

    auto pool = rdConnectionPool_;
    if (pool == nullptr) {
        return E_ALREADY_CLOSED;
    }

    auto connection = pool->AcquireConnection(true, 0);
    if (connection == nullptr) {
        LOG_ERROR("rdConnectionPool_ AcquireConnection failed!");
        return E_DATABASE_BUSY;
    }
    auto statement = RdStatement::CreateStatement(std::static_pointer_cast<RdConnection>(connection), sql_);
    if (statement == nullptr) {
        return E_STATEMENT_NOT_PREPARED;
    }
    int errCode = statement->Prepare(std::static_pointer_cast<RdConnection>(connection)->GetDbHandle(), sql_);
    if (errCode != E_OK) {
        LOG_ERROR("Prepare arg faild! Ret is %{public}d", errCode);
        statement = nullptr;
        return errCode;
    }
    errCode = statement->BindArguments(args_);
    if (errCode != E_OK) {
        LOG_ERROR("Bind arg faild! Ret is %{public}d", errCode);
        statement->ResetStatementAndClearBindings();
        statement = nullptr;
        return errCode;
    }
    statement_ = std::move(statement);
    conn_ = connection;
    return E_OK;
}

int RdSharedResultSet::Close()
{
    if (isClosed_) {
        return E_OK;
    }
    auto args = std::move(args_);
    statement_ = nullptr;
    isClosed_ = true;
    return FinishStep();
}

/**
 * Release resource of step result set, this method can be called more than once
 */
int RdSharedResultSet::FinishStep()
{
    auto [statement, connection] = GetStatement();
    if (statement != nullptr) {
        statement->ResetStatementAndClearBindings();
        statement_ = nullptr;
        if (statement_ != nullptr) {
            statement_ = nullptr;
        }
        if (conn_ != nullptr) {
            rdConnectionPool_->ReleaseConnection(conn_);
            conn_ = nullptr;
        }
        if (connection != nullptr) {
            connection = nullptr;
        }
    }
    rowPos_ = INIT_POS;
    return E_OK;
}

/**
 * Reset the statement
 */
void RdSharedResultSet::Reset()
{
    FinishStep();
    isAfterLast_ = false;
}


/**
 * Checks whether the result set is positioned after the last row
 */
int RdSharedResultSet::IsEnded(bool &result)
{
    result = isAfterLast_;
    return E_OK;
}

/**
 * Checks whether the result set is moved
 */
int RdSharedResultSet::IsStarted(bool &result) const
{
    result = (rowPos_ != INIT_POS);
    return E_OK;
}

/**
 * Check whether the result set is in the first row
 */
int RdSharedResultSet::IsAtFirstRow(bool &result) const
{
    result = (rowPos_ == 0);
    return E_OK;
}

int RdSharedResultSet::Get(int32_t col, ValueObject &value)
{
    return GetValue(col, value);
}

int RdSharedResultSet::GetSize(int columnIndex, size_t &size)
{
    auto [statement, conn] = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("resultSet closed");
        return E_ALREADY_CLOSED;
    }

    if (rowPos_ == INIT_POS) {
        size = 0;
        return E_ROW_OUT_RANGE;
    }

    return statement->GetSize(columnIndex, size);
}

template<typename T>
int RdSharedResultSet::GetValue(int32_t col, T &value)
{
    auto [errCode, object] = GetValueObject(col, ValueObject::TYPE_INDEX<decltype(value)>);
    if (errCode != E_OK) {
        LOG_ERROR("ret is %{public}d", errCode);
        return errCode;
    }
    value = object;
    return E_OK;
}

std::pair<int, ValueObject> RdSharedResultSet::GetValueObject(int32_t col, size_t index)
{
    auto [statement, conn] = GetStatement();
    if (statement == nullptr) {
        return { E_ALREADY_CLOSED, ValueObject() };
    }

    if (rowPos_ == INIT_POS) {
        return { E_ROW_OUT_RANGE, ValueObject() };
    }

    ValueObject value;
    auto ret = statement->GetColumn(col, value);
    if (index < ValueObject::TYPE_MAX && value.value.index() != index) {
        return { E_INVALID_COLUMN_TYPE, ValueObject() };
    }
    return { ret, std::move(value) };
}

std::pair<std::shared_ptr<RdbStatement>, std::shared_ptr<RdbConnection>> RdSharedResultSet::GetStatement()
{
    if (isClosed_) {
        return { nullptr, nullptr };
    }
    return {statement_, conn_};
}
} // namespace NativeRdb
} // namespace OHOS
