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
#define LOG_TAG "SqliteSharedResultSet"
#include "sqlite_shared_result_set.h"

#include <rdb_errno.h>

#include "logger.h"
#include "rdb_sql_utils.h"
#include "share_block.h"
#include "shared_block_serializer_info.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

SqliteSharedResultSet::SqliteSharedResultSet(std::shared_ptr<SqliteConnectionPool> pool, std::string path,
    std::string sql, const std::vector<ValueObject>& bindArgs)
    : AbsSharedResultSet(std::move(path)), resultSetBlockCapacity_(0), rowNum_(NO_COUNT), qrySql_(std::move(sql)),
      bindArgs_(std::move(bindArgs)), isOnlyFillResultSetBlock_(false)
{
    auto connection = pool->AcquireConnection(true);
    if (connection == nullptr) {
        return;
    }
    conn_ = pool->AcquireByID(connection->GetId());
    if (conn_ == nullptr) {
        conn_ = connection;
    }
}

SqliteSharedResultSet::~SqliteSharedResultSet() {}

std::pair<std::shared_ptr<SqliteStatement>, int> SqliteSharedResultSet::PrepareStep()
{
    if (SqliteUtils::GetSqlStatementType(qrySql_) != SqliteUtils::STATEMENT_SELECT) {
        LOG_ERROR("StoreSession BeginStepQuery fail : not select sql !");
        return {nullptr, E_EXECUTE_IN_STEP_QUERY};
    }
    auto statement = SqliteStatement::CreateStatement(conn_, qrySql_);
    if (statement == nullptr) {
        return {nullptr, E_ERROR};
    }
    auto errCode = statement->BindArguments(bindArgs_);
    if (errCode != E_OK) {
        LOG_ERROR("Bind arg faild! Ret is %{public}d", errCode);
        statement->ResetStatementAndClearBindings();
        statement = nullptr;
        return {nullptr, E_ERROR};
    }
    return {statement, E_OK};
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

    auto [statement, errCode] = PrepareStep();
    if (statement == nullptr) {
        return errCode;
    }

    int columnCount = 0;
    // Get the total number of columns
    errCode = statement->GetColumnCount(columnCount);
    if (errCode != E_OK) {
        return errCode;
    }

    std::lock_guard<std::mutex> lock(columnNamesLock_);
    for (int i = 0; i < columnCount; i++) {
        std::string columnName;
        errCode = statement->GetColumnName(i, columnName);
        if (errCode) {
            columnNames_.clear();
            return errCode;
        }
        columnNames_.push_back(columnName);
    }

    columnNames = columnNames_;
    columnCount_ = static_cast<int>(columnNames_.size());
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

    FillBlock(0);
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
        FillBlock(newPosition);
        return true;
    }
    if ((uint32_t)newPosition < GetBlock()->GetStartPos() || (uint32_t)newPosition >= GetBlock()->GetLastPos() ||
        oldPosition == rowNum_) {
        FillBlock(newPosition);
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

void SqliteSharedResultSet::FillBlock(int requiredPos)
{
    auto block = GetBlock();
    if (block == nullptr) {
        LOG_ERROR("FillSharedBlock GetBlock failed.");
        return;
    }
    ClearBlock();
    if (block == nullptr) {
        LOG_ERROR("GetBlock failed.");
        return;
    }

    if (rowNum_ == NO_COUNT) {
        auto [errCode, rowNum] = ExecuteForSharedBlock(block, requiredPos, requiredPos, true);
        if (errCode != E_OK) {
            return;
        }
        resultSetBlockCapacity_ = static_cast<int>(block->GetRowNum());
        rowNum_ = rowNum;
    } else {
        int blockRowNum = rowNum_;
        int startPos =
            isOnlyFillResultSetBlock_ ? requiredPos : PickFillBlockStartPosition(requiredPos, resultSetBlockCapacity_);
        ExecuteForSharedBlock(block, startPos, requiredPos, false);
        resultSetBlockCapacity_ = block->GetRowNum();
        LOG_INFO("blockRowNum=%{public}d, requiredPos= %{public}d, startPos_= %{public}" PRIu32
                 ", lastPos_= %{public}" PRIu32 ", blockPos_= %{public}" PRIu32 ".",
            blockRowNum, requiredPos, block->GetStartPos(), block->GetLastPos(),
                 block->GetBlockPos());
    }
}
/**
 * Executes a statement and populates the specified with a range of results.
 */
std::pair<int, int32_t> SqliteSharedResultSet::ExecuteForSharedBlock(AppDataFwk::SharedBlock* block, int start,
    int required, bool needCount)
{
    int32_t rowNum = NO_COUNT;
    if (block == nullptr) {
        LOG_ERROR("ExecuteForSharedBlock:sharedBlock is null.");
        return { E_ERROR, rowNum };
    }

    auto [statement, errCode] = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("PrepareStep error = %{public}d ", errCode);
        return { errCode, rowNum };
    }

    auto code = block->Clear();
    if (code != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        LOG_ERROR("Clear %{public}d.", code);
        return { E_ERROR, rowNum };
    }

    SharedBlockInfo blockInfo(block, statement->GetSql3Stmt());
    blockInfo.requiredPos = required;
    statement->GetColumnCount(blockInfo.columnNum);
    blockInfo.isCountAllRows = needCount;
    blockInfo.startPos = start;
    code = block->SetColumnNum(blockInfo.columnNum);
    if (code != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        LOG_ERROR("SetColumnNum %{public}d.", code);
        return { E_ERROR, rowNum };
    }

    if (statement->SupportSharedBlock()) {
        FillSharedBlockOpt(&blockInfo);
    } else {
        FillSharedBlock(&blockInfo);
    }

    if (!ResetStatement(&blockInfo)) {
        LOG_ERROR("ResetStatement Failed.");
        return { E_ERROR, rowNum };
    }
    block->SetStartPos(blockInfo.startPos);
    block->SetBlockPos(required - blockInfo.startPos);
    block->SetLastPos(blockInfo.startPos + block->GetRowNum());
    if (needCount) {
        rowNum = static_cast<int>(GetCombinedData(blockInfo.startPos, blockInfo.totalRows));
    }
    errCode = statement->ResetStatementAndClearBindings();
    return { errCode, rowNum };
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