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

#include "logger.h"
#include "rdb_sql_utils.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

SqliteSharedResultSet::SqliteSharedResultSet(std::shared_ptr<SqliteConnectionPool> connectionPool, std::string path,
    std::string sql, const std::vector<ValueObject>& bindArgs)
    : AbsSharedResultSet(path), connectionPool_(connectionPool), resultSetBlockCapacity_(0), rowNum_(NO_COUNT),
      qrySql_(sql), bindArgs_(std::move(bindArgs)), isOnlyFillResultSetBlock_(false)
{
}

SqliteSharedResultSet::~SqliteSharedResultSet() {
}

std::shared_ptr<SqliteStatement> SqliteSharedResultSet::PrepareStep(
    std::shared_ptr<SqliteConnection> connection, int &errCode)
{
    if (SqliteUtils::GetSqlStatementType(qrySql_) != SqliteUtils::STATEMENT_SELECT) {
        LOG_ERROR("StoreSession BeginStepQuery fail : not select sql !");
        errCode = E_EXECUTE_IN_STEP_QUERY;
        return nullptr;
    }

    std::shared_ptr<SqliteStatement> sqliteStatement = connection->BeginStepQuery(errCode,
        qrySql_, bindArgs_);
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

    if (isClosed_) {
        return E_STEP_RESULT_CLOSED;
    }
    auto pool = connectionPool_.lock();
    if (pool == nullptr) {
        return E_STEP_RESULT_CLOSED;
    }

    auto connection = pool->AcquireConnection(true);
    if (connection == nullptr) {
        return E_CON_OVER_LIMIT;
    }

    int errCode = E_OK;
    std::shared_ptr<SqliteStatement> sqliteStatement = PrepareStep(connection, errCode);
    if (sqliteStatement == nullptr) {
        return errCode;
    }

    int columnCount = 0;
    // Get the total number of columns
    errCode = sqliteStatement->GetColumnCount(columnCount);
    if (errCode != E_OK) {
        return errCode;
    }
    
    std::lock_guard<std::mutex> lock(columnNamesLock_);
    for (int i = 0; i < columnCount; i++) {
        std::string columnName;
        errCode = sqliteStatement->GetColumnName(i, columnName);
        if (errCode) {
            columnNames_.clear();
            return errCode;
        }
        columnNames_.push_back(columnName);
    }

    columnNames = columnNames_;
    columnCount_ = static_cast<int>(columnNames_.size());
    connection->EndStepQuery();
    return E_OK;
}

int SqliteSharedResultSet::GetRowCount(int &count)
{
    if (rowNum_ != NO_COUNT) {
        count = rowNum_;
        return E_OK;
    }

    if (isClosed_) {
        return E_STEP_RESULT_CLOSED;
    }

    FillSharedBlock(0);
    count = rowNum_;
    return E_OK;
}

int SqliteSharedResultSet::Close()
{
    AbsSharedResultSet::Close();
    auto qrySql = std::move(qrySql_);
    auto bindArgs = std::move(bindArgs_);
    auto columnNames = std::move(columnNames_);
    return E_OK;
}

bool SqliteSharedResultSet::OnGo(int oldPosition, int newPosition)
{
    if (GetBlock() == nullptr) {
        FillSharedBlock(newPosition);
        return true;
    }
    if ((uint32_t)newPosition < GetBlock()->GetStartPos() || (uint32_t)newPosition >= GetBlock()->GetLastPos() ||
        oldPosition == rowNum_) {
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
    auto pool = connectionPool_.lock();
    if (pool == nullptr) {
        return;
    }
    auto connection = pool->AcquireConnection(true);
    if (connection == nullptr) {
        return;
    }
    AppDataFwk::SharedBlock *sharedBlock = GetBlock();
    if (sharedBlock == nullptr) {
        LOG_ERROR("FillSharedBlock GetBlock failed.");
        return;
    }
    if (rowNum_ == NO_COUNT) {
        auto errCode = connection->ExecuteForSharedBlock(rowNum_, qrySql_, bindArgs_,
            sharedBlock, requiredPos, requiredPos, true);
        if (errCode != E_OK) {
            return;
        }
        resultSetBlockCapacity_ = static_cast<int>(sharedBlock->GetRowNum());
    } else {
        int blockRowNum = rowNum_;
        int startPos =
            isOnlyFillResultSetBlock_ ? requiredPos : PickFillBlockStartPosition(requiredPos, resultSetBlockCapacity_);
        connection->ExecuteForSharedBlock(blockRowNum, qrySql_, bindArgs_, sharedBlock, startPos, requiredPos, false);
        resultSetBlockCapacity_ = sharedBlock->GetRowNum();
        LOG_INFO("blockRowNum=%{public}d, requiredPos= %{public}d, startPos_= %{public}" PRIu32
                 ", lastPos_= %{public}" PRIu32 ", blockPos_= %{public}" PRIu32 ".",
            blockRowNum, requiredPos, sharedBlock->GetStartPos(), sharedBlock->GetLastPos(),
            sharedBlock->GetBlockPos());
    }
}

void SqliteSharedResultSet::SetBlock(AppDataFwk::SharedBlock *block)
{
    AbsSharedResultSet::SetBlock(block);
    rowNum_ = NO_COUNT;
}

/**
 * If isOnlyFillResultSetBlockInput is true, use the input requiredPos to fill the block, otherwise pick the value
 * from requirePos and resultSetBlockCapacity_.
 */
void SqliteSharedResultSet::SetFillBlockForwardOnly(bool isOnlyFillResultSetBlockInput)
{
    isOnlyFillResultSetBlock_ = isOnlyFillResultSetBlockInput;
}

void SqliteSharedResultSet::Finalize()
{
    Close();
}
} // namespace NativeRdb
} // namespace OHOS