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

#include "sqlite_shared_result_set.h"

#include <rdb_errno.h>

#include <algorithm>
#include <memory>

#include "logger.h"
#include "rdb_sql_utils.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

SqliteSharedResultSet::SqliteSharedResultSet(std::shared_ptr<RdbStoreImpl> store, SqliteConnectionPool *connectionPool,
    std::string path, std::string sql, const std::vector<std::string> &bindArgs)
    : AbsSharedResultSet(path), store_(store), connectionPool_(connectionPool), resultSetBlockCapacity(0),
      isOnlyFillResultSetBlock(false), qrySql(sql), selectionArgVec(bindArgs), rowNum(NO_COUNT)
{
}

SqliteSharedResultSet::~SqliteSharedResultSet() {
}

std::shared_ptr<SqliteStatement> SqliteSharedResultSet::PrepareStep(SqliteConnection* connection, int &errCode)
{
    if (SqliteUtils::GetSqlStatementType(qrySql) != SqliteUtils::STATEMENT_SELECT) {
        LOG_ERROR("StoreSession BeginStepQuery fail : not select sql !");
        errCode = E_EXECUTE_IN_STEP_QUERY;
        return nullptr;
    }

    std::shared_ptr<SqliteStatement> sqliteStatement = connection->BeginStepQuery(errCode,
        qrySql, selectionArgVec);
    if (sqliteStatement == nullptr) {
        connection->EndStepQuery();
    }

    return sqliteStatement;
}

int SqliteSharedResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    if (!columnNames_.empty()) {
        columnNames = columnNames_;
        return E_OK;
    }

    if (isClosed) {
        return E_STEP_RESULT_CLOSED;
    }

    SqliteConnection *connection = connectionPool_->AcquireConnection(true);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = E_OK;
    std::shared_ptr<SqliteStatement> sqliteStatement = PrepareStep(connection, errCode);
    if (sqliteStatement == nullptr) {
        connectionPool_->ReleaseConnection(connection);
        return errCode;
    }

    int columnCount = 0;
    // Get the total number of columns
    errCode = sqliteStatement->GetColumnCount(columnCount);
    if (errCode) {
        connectionPool_->ReleaseConnection(connection);
        return errCode;
    }
    
    std::lock_guard<std::mutex> lock(columnNamesLock_);
    for (int i = 0; i < columnCount; i++) {
        std::string columnName;
        errCode = sqliteStatement->GetColumnName(i, columnName);
        if (errCode) {
            connectionPool_->ReleaseConnection(connection);
            columnNames_.clear();
            return errCode;
        }
        columnNames_.push_back(columnName);
    }

    columnNames = columnNames_;
    columnCount_ = static_cast<int>(columnNames_.size());
    connection->EndStepQuery();
    connectionPool_->ReleaseConnection(connection);

    return E_OK;
}

int SqliteSharedResultSet::GetRowCount(int &count)
{
    if (rowNum != NO_COUNT) {
        count = rowNum;
        return E_OK;
    }

    if (isClosed) {
        return E_STEP_RESULT_CLOSED;
    }

    FillSharedBlock(0);
    count = rowNum;
    return E_OK;
}

int SqliteSharedResultSet::Close()
{
    AbsSharedResultSet::Close();
    return E_OK;
}

bool SqliteSharedResultSet::OnGo(int oldPosition, int newPosition)
{
    if (GetBlock() == nullptr) {
        FillSharedBlock(newPosition);
        return true;
    }
    if ((uint32_t)newPosition < GetBlock()->GetStartPos() || (uint32_t)newPosition >= GetBlock()->GetLastPos() ||
        oldPosition == rowNum) {
        FillSharedBlock(newPosition);
    }
    return true;
}

/**
 * Calculate a proper start position to fill the block.
 */
int SqliteSharedResultSet::PickFillBlockStartPosition(int resultSetPosition, int blockCapacity) const
{
    return std::max(resultSetPosition - blockCapacity / PICK_POS, 0);
}

void SqliteSharedResultSet::FillSharedBlock(int requiredPos)
{
    ClearBlock();

    std::vector<ValueObject> bindArgs;
    size_t size = selectionArgVec.size();
    bindArgs.reserve(size);
    for (size_t i = 0; i < size; i++) {
        ValueObject vauObj(selectionArgVec[i]);
        bindArgs.push_back(vauObj);
    }

    SqliteConnection* connection = connectionPool_->AcquireConnection(true);
    if (connection == nullptr) {
        return;
    }

    if (rowNum == NO_COUNT) {
        connection->ExecuteForSharedBlock(rowNum, qrySql, bindArgs, GetBlock(), requiredPos, requiredPos, true);
        resultSetBlockCapacity = static_cast<int>(GetBlock()->GetRowNum());
        if (resultSetBlockCapacity > 0) {
            GetBlock()->SetStartPos(requiredPos);
            GetBlock()->SetBlockPos(0);
            GetBlock()->SetLastPos(requiredPos + resultSetBlockCapacity);
        }
    } else {
        int blockRowNum = rowNum;
        int startPos =
            isOnlyFillResultSetBlock ? requiredPos : PickFillBlockStartPosition(requiredPos, resultSetBlockCapacity);
        connection->ExecuteForSharedBlock(blockRowNum, qrySql, bindArgs, GetBlock(), startPos, requiredPos, false);
        int currentBlockCapacity = static_cast<int>(GetBlock()->GetRowNum());
        GetBlock()->SetStartPos((uint32_t)startPos);
        GetBlock()->SetBlockPos(requiredPos - startPos);
        GetBlock()->SetLastPos(startPos + currentBlockCapacity);
        LOG_INFO("requiredPos= %{public}d, startPos_= %{public}" PRIu32 ", lastPos_= %{public}" PRIu32
            ", blockPos_= %{public}" PRIu32 ".",
            requiredPos, GetBlock()->GetStartPos(), GetBlock()->GetLastPos(), GetBlock()->GetBlockPos());
    }
    connectionPool_->ReleaseConnection(connection);
}

void SqliteSharedResultSet::SetBlock(AppDataFwk::SharedBlock *block)
{
    AbsSharedResultSet::SetBlock(block);
    rowNum = NO_COUNT;
}

/**
 * If isOnlyFillResultSetBlockInput is true, use the input requiredPos to fill the block, otherwise pick the value
 * from requirePos and resultSetBlockCapacity.
 */
void SqliteSharedResultSet::SetFillBlockForwardOnly(bool isOnlyFillResultSetBlockInput)
{
    isOnlyFillResultSetBlock = isOnlyFillResultSetBlockInput;
}

void SqliteSharedResultSet::Finalize()
{
    Close();
}
} // namespace NativeRdb
} // namespace OHOS