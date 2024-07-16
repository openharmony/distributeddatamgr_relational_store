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
#include "connection_pool.h"
#include "sqlite_errno.h"
#include "sqlite_statement.h"
#include "sqlite_utils.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
StepResultSet::StepResultSet(std::shared_ptr<ConnectionPool> pool, const std::string &sql,
    const std::vector<ValueObject> &args)
    : AbsResultSet(), sql_(sql), args_(std::move(args))
{
    conn_ = pool->AcquireRef(true);
    if (conn_ == nullptr) {
        isClosed_ = true;
        return;
    }

    auto errCode = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("step resultset ret %{public}d", errCode);
    }
    rowCount_ = InitRowCount();
}

StepResultSet::~StepResultSet()
{
    Close();
}

int StepResultSet::InitRowCount()
{
    auto statement = GetStatement();
    if (statement == nullptr) {
        return NO_COUNT;
    }
    int32_t count = NO_COUNT;
    int32_t status = E_OK;
    int32_t retry = 0;
    do {
        status = statement->Step();
        if (status == E_SQLITE_BUSY || status == E_SQLITE_LOCKED) {
            retry++;
            usleep(STEP_QUERY_RETRY_INTERVAL);
            continue;
        }
        count++;
    } while (status == E_OK ||
             ((status == E_SQLITE_BUSY || status == E_SQLITE_LOCKED) && retry < STEP_QUERY_RETRY_MAX_TIMES));
    if (status != E_NO_MORE_ROWS) {
        count = NO_COUNT;
    }
    statement->Reset();
    return count;
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
    if (type == SqliteUtils::STATEMENT_ERROR) {
        LOG_ERROR("invalid sql_ %{public}s!", sql_.c_str());
        return E_INVALID_ARGS;
    }

    auto [errCode, statement] = conn_->CreateStatement(sql_, conn_);
    if (statement == nullptr || errCode != E_OK) {
        return E_STATEMENT_NOT_PREPARED;
    }

    if (!statement->ReadOnly()) {
        LOG_ERROR("failed, %{public}s is not query sql!", SqliteUtils::Anonymous(sql_).c_str());
        return E_NOT_SELECT;
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

std::pair<int, std::vector<std::string>> StepResultSet::GetColumnNames()
{
    int errCode = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("get all column names Step ret %{public}d", errCode);
        return { errCode, {} };
    }

    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("Statement is nullptr");
        return { E_ALREADY_CLOSED, {} };
    }
    auto colCount = statement->GetColumnCount();
    std::vector<std::string> names;
    for (int i = 0; i < colCount; i++) {
        auto [code, colName] = statement->GetColumnName(i);
        if (code) {
            LOG_ERROR("GetColumnName ret %{public}d", code);
            return { code, {} };
        }
        names.push_back(colName);
    }

    return { E_OK, std::move(names) };
}

int StepResultSet::GetColumnType(int columnIndex, ColumnType &columnType)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (rowPos_ == INIT_POS || IsEnded().second) {
        LOG_ERROR("query not executed.");
        return E_ROW_OUT_RANGE;
    }
    auto statement = GetStatement();
    if (statement == nullptr) {
        LOG_ERROR("Statement is nullptr");
        return E_ALREADY_CLOSED;
    }

    auto [errCode, outPutType] = statement->GetColumnType(columnIndex);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnType ret %{public}d", errCode);
        return errCode;
    }
    columnType = static_cast<ColumnType>(outPutType);
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

    if (position >= rowCount_ || position < 0) {
        rowPos_ = (position >= rowCount_ && rowCount_ != 0) ? rowCount_ : rowPos_;
        LOG_ERROR("position[%{public}d] rowCount[%{public}d] rowPos_[%{public}d]!", position, rowCount_, rowPos_);
        return E_ROW_OUT_RANGE;
    }

    if (position < rowPos_) {
        Reset();
        return GoToRow(position);
    }
    while (position != rowPos_) {
        int errCode = GoToNextRow();
        if (errCode != E_OK) {
            LOG_WARN("GoToNextRow ret %{public}d", errCode);
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

    while (errCode == E_SQLITE_LOCKED || errCode == E_SQLITE_BUSY) {
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

    if (errCode == E_OK) {
        rowPos_++;
        return E_OK;
    } else if (errCode == E_NO_MORE_ROWS) {
        rowPos_ = rowCount_ != 0 ? rowCount_ : rowPos_;
        return E_ROW_OUT_RANGE;
    } else {
        Reset();
        rowPos_ = rowCount_;
        return errCode;
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
    Reset();
    return E_OK;
}

/**
 * Reset the statement
 */
int StepResultSet::Reset()
{
    rowPos_ = INIT_POS;
    auto statement = GetStatement();
    if (statement != nullptr) {
        return statement->Reset();
    }
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
    if (rowPos_ == INIT_POS || IsEnded().second) {
        size = 0;
        return E_ROW_OUT_RANGE;
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
    if (rowPos_ == INIT_POS || IsEnded().second) {
        return { E_ROW_OUT_RANGE, ValueObject() };
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