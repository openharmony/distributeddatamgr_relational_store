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

#include <cstdint>
#include <memory>
#include <mutex>
#include <tuple>

#include "logger.h"
#include "rdb_sql_utils.h"
#include "result_set.h"
#include "share_block.h"
#include "sqlite_connection.h"
#include "sqlite_statement.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
SqliteSharedResultSet::SqliteSharedResultSet(std::shared_ptr<SqliteConnectionPool> pool, std::string path,
    std::string sql, const std::vector<ValueObject>& bindArgs)
    : AbsSharedResultSet(path), isOnlyFillBlock_(false), blockCapacity_(0), rowNum_(NO_COUNT),
      qrySql_(sql), bindArgs_(std::move(bindArgs))
{
    conn_ = pool->AcquireRef(true);
}
std::pair<std::shared_ptr<Statement>, int> SqliteSharedResultSet::PrepareStep()
{
    auto type = SqliteUtils::GetSqlStatementType(qrySql_);
    if (type != SqliteUtils::STATEMENT_SELECT && type != SqliteUtils::STATEMENT_OTHER) {
        LOG_ERROR("StoreSession BeginStepQuery fail : not select sql !");
        return {nullptr, E_NOT_SELECT};
    }
    if (conn_ == nullptr) {
        LOG_ERROR("Already close");
        return {nullptr, E_ALREADY_CLOSED};
    }
    auto [errCode, statement] = conn_->CreateStatement(qrySql_, conn_);
    if (statement == nullptr || errCode != E_OK) {
        return { nullptr, E_ERROR };
    }
    errCode = statement->Bind(bindArgs_);
    if (errCode != E_OK) {
        LOG_ERROR("Bind arg faild! Ret is %{public}d", errCode);
        statement->Reset();
        statement = nullptr;
        return { nullptr, E_ERROR };
    }
    return { statement, E_OK };
}

SqliteSharedResultSet::~SqliteSharedResultSet() {}

std::pair<int, std::vector<std::string>> SqliteSharedResultSet::GetColumnNames()
{
    if (isClosed_) {
        LOG_ERROR("fail, result set has been closed, ret %{public}d, sql %{public}s",
            E_ALREADY_CLOSED, qrySql_.c_str());
        return { E_ALREADY_CLOSED, {} };
    }

    auto [statement, errCode] = PrepareStep();
    if (statement == nullptr) {
        return { errCode, {} };
    }

    // Get the total number of columns
    auto columnCount = statement->GetColumnCount();
    std::vector<std::string> colNames;
    for (int i = 0; i < columnCount; i++) {
        auto [ret, name] = statement->GetColumnName(i);
        if (ret != E_OK) {
            return { ret, {} };
        }
        colNames.push_back(name);
    }

    return { E_OK, std::move(colNames) };
}

int SqliteSharedResultSet::GetRowCount(int &count)
{
    if (rowNum_ != NO_COUNT) {
        count = rowNum_;
        return E_OK;
    }

    if (isClosed_) {
        LOG_ERROR("fail, result set has been closed, ret %{public}d, sql %{public}s",
            E_ALREADY_CLOSED, qrySql_.c_str());
        return E_ALREADY_CLOSED;
    }

    auto errCode = FillBlock(0);
    count = rowNum_;

    if (count == 0) {
        rowNum_ = NO_COUNT;
        errCode = FillBlock(0);
        count = rowNum_;
    }
    return errCode;
}

int SqliteSharedResultSet::Close()
{
    AbsSharedResultSet::Close();
    conn_ = nullptr;
    auto qrySql = std::move(qrySql_);
    auto bindArgs = std::move(bindArgs_);
    auto columnNames = std::move(columnNames_);
    return E_OK;
}

int SqliteSharedResultSet::OnGo(int oldPosition, int newPosition)
{
    if (isClosed_) {
        LOG_ERROR("fail, result set has been closed, ret %{public}d, sql %{public}s",
            E_ALREADY_CLOSED, qrySql_.c_str());
        return E_ALREADY_CLOSED;
    }
    auto errCode = E_ERROR;
    if (GetBlock() == nullptr) {
        return FillBlock(newPosition);
    }
    if ((uint32_t)newPosition < GetBlock()->GetStartPos() || (uint32_t)newPosition >= GetBlock()->GetLastPos()
        || oldPosition == rowNum_) {
        errCode = FillBlock(newPosition);
    }
    return errCode;
}

/**
 * Calculate a proper start position to fill the block.
 */
int SqliteSharedResultSet::PickFillBlockStartPosition(int resultSetPosition, int blockCapacity) const
{
    return std::max(resultSetPosition - blockCapacity / PICK_POS, 0);
}

int SqliteSharedResultSet::FillBlock(int requiredPos)
{
    auto block = GetBlock();
    if (block == nullptr) {
        LOG_ERROR("FillSharedBlock GetBlock failed.");
        return E_ERROR;
    }
    ClearBlock();
    if (rowNum_ == NO_COUNT) {
        auto [errCode, rowNum] = ExecuteForSharedBlock(block.get(), requiredPos, requiredPos, true);
        if (errCode != E_OK) {
            return errCode;
        }
        blockCapacity_ = static_cast<int>(block->GetRowNum());
        rowNum_ = rowNum;
    } else {
        int startPos = isOnlyFillBlock_ ? requiredPos : PickFillBlockStartPosition(requiredPos, blockCapacity_);
        auto [errCode, rowNum] = ExecuteForSharedBlock(block.get(), startPos, requiredPos, false);
        if (errCode != E_OK) {
            return errCode;
        }
        blockCapacity_ = block->GetRowNum();
        LOG_INFO("blockRowNum=%{public}d, requiredPos= %{public}d, startPos_= %{public}" PRIu32
                 ", lastPos_= %{public}" PRIu32 ", blockPos_= %{public}" PRIu32 ".",
            rowNum_, requiredPos, block->GetStartPos(), block->GetLastPos(), block->GetBlockPos());
    }
    return E_OK;
}

void SqliteSharedResultSet::SetBlock(AppDataFwk::SharedBlock *block)
{
    AbsSharedResultSet::SetBlock(block);
    rowNum_ = NO_COUNT;
}

/**
 * If isOnlyFillResultSetBlockInput is true, use the input requiredPos to fill the block, otherwise pick the value
 * from requirePos and blockCapacity_.
 */
void SqliteSharedResultSet::SetFillBlockForwardOnly(bool isOnlyFillResultSetBlockInput)
{
    isOnlyFillBlock_ = isOnlyFillResultSetBlockInput;
}

void SqliteSharedResultSet::Finalize()
{
    Close();
}
/**
 * Executes a statement and populates the specified with a range of results.
 */
std::pair<int, int32_t> SqliteSharedResultSet::ExecuteForSharedBlock(AppDataFwk::SharedBlock* block, int start,
    int required, bool needCount)
{
    int32_t rowNum = NO_COUNT;
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

    SharedBlockInfo blockInfo(block);
    blockInfo.requiredPos = required;
    blockInfo.columnNum = statement->GetColumnCount();
    blockInfo.isCountAllRows = needCount;
    blockInfo.startPos = start;
    code = block->SetColumnNum(blockInfo.columnNum);
    if (code != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        LOG_ERROR("SetColumnNum %{public}d.", code);
        return { E_ERROR, rowNum };
    }

    code = statement->FillBlockInfo(&blockInfo);
    if (code != E_OK) {
        LOG_ERROR("Fill shared block failed, ret is %{public}d", code);
        return { code, rowNum };
    }

    block->SetStartPos(blockInfo.startPos);
    block->SetBlockPos(required - blockInfo.startPos);
    block->SetLastPos(blockInfo.startPos + block->GetRowNum());
    if (needCount) {
        rowNum = static_cast<int>(GetCombinedData(blockInfo.startPos, blockInfo.totalRows));
    }
    return { statement->Reset(), rowNum };
}
} // namespace NativeRdb
} // namespace OHOS