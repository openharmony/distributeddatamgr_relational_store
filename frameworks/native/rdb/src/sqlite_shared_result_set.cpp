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
    std::string sql, const std::vector<ValueObject> &bindArgs)
    : AbsSharedResultSet(path), resultSetBlockCapacity_(0), rowNum_(NO_COUNT), qrySql_(sql),
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
    auto statement = conn_->CreateStatement(qrySql_, conn_);
    if (statement == nullptr) {
        return { nullptr, E_ERROR };
    }
    auto errCode = statement->Bind(bindArgs_);
    if (errCode != E_OK) {
        LOG_ERROR("Bind arg faild! Ret is %{public}d", errCode);
        statement->Reset();
        statement = nullptr;
        return { nullptr, E_ERROR };
    }
    return { statement, E_OK };
}

SqliteSharedResultSet::~SqliteSharedResultSet() {}

int SqliteSharedResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }

    auto [statement, errCode] = PrepareStep();
    if (statement == nullptr) {
        return errCode;
    }

    // Get the total number of columns
    auto columnCount = statement->GetColumnCount();
    for (int i = 0; i < columnCount; i++) {
        auto [ret, name] = statement->GetColumnName(i);
        if (ret != E_OK) {
            columnNames.clear();
            return ret;
        }
        columnNames.push_back(name);
    }

    return E_OK;
}

int SqliteSharedResultSet::GetRowCount(int &count)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (rowNum_ != NO_COUNT) {
        count = rowNum_;
        return E_OK;
    }

    if (isClosed_) {
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
    auto qrySql = std::move(qrySql_);
    auto bindArgs = std::move(bindArgs_);
    auto columnNames = std::move(columnNames_);
    return E_OK;
}

int SqliteSharedResultSet::OnGo(int oldPosition, int newPosition)
{
    if (isClosed_) {
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
    auto sharedBlock = GetBlock();
    if (sharedBlock == nullptr) {
        LOG_ERROR("FillSharedBlock GetBlock failed.");
        return E_ERROR;
    }
    ClearBlock();
    if (rowNum_ == NO_COUNT) {
        auto [errCode, rowNum] = ExecuteForSharedBlock(sharedBlock, requiredPos, requiredPos, true);
        if (errCode != E_OK) {
            return errCode;
        }
        resultSetBlockCapacity_ = static_cast<int>(sharedBlock->GetRowNum());
        rowNum_ = rowNum;
    } else {
        int startPos = isOnlyFillResultSetBlock_ ? requiredPos
                                                 : PickFillBlockStartPosition(requiredPos, resultSetBlockCapacity_);
        auto [errCode, rowNum] = ExecuteForSharedBlock(sharedBlock, startPos, requiredPos, false);
        if (errCode != E_OK) {
            return errCode;
        }
        resultSetBlockCapacity_ = sharedBlock->GetRowNum();
        LOG_INFO("blockRowNum=%{public}d, requiredPos= %{public}d, startPos_= %{public}" PRIu32
                 ", lastPos_= %{public}" PRIu32 ", blockPos_= %{public}" PRIu32 ".",
            rowNum_, requiredPos, sharedBlock->GetStartPos(), sharedBlock->GetLastPos(), sharedBlock->GetBlockPos());
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

std::pair<int, int32_t> SqliteSharedResultSet::ExecuteForSharedBlock(AppDataFwk::SharedBlock* sharedBlock, int start,
    int required, bool needCount)
{
    int32_t rowNum = NO_COUNT;
    if (sharedBlock == nullptr) {
        LOG_ERROR("ExecuteForSharedBlock:sharedBlock is null.");
        return { E_ERROR, rowNum };
    }

    auto [statement, errCode] = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("PrepareStep error = %{public}d ", errCode);
        return { errCode, rowNum };
    }

    auto code = sharedBlock->Clear();
    if (code != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        LOG_ERROR("Clear %{public}d.", code);
        return { E_ERROR, rowNum };
    }

    SharedBlockInfo blockInfo(sharedBlock, nullptr);
    statement->FillBlockInfo(&blockInfo);
    blockInfo.requiredPos = required;
    blockInfo.columnNum = statement->GetColumnCount();
    blockInfo.isCountAllRows = needCount;
    blockInfo.startPos = start;
    code = sharedBlock->SetColumnNum(blockInfo.columnNum);
    if (code != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        LOG_ERROR("SetColumnNum %{public}d.", code);
        return { E_ERROR, rowNum };
    }
    if (statement->SupportBlockInfo()) {
        code = FillSharedBlockOpt(&blockInfo);
    } else {
        code = FillSharedBlock(&blockInfo);
    }
    if (code != E_OK) {
        LOG_ERROR("Fill shared block failed, ret is %{public}d", code);
        return { code, rowNum };
    }

    if (!ResetStatement(&blockInfo)) {
        LOG_ERROR("ResetStatement Failed.");
        return { E_ERROR, rowNum };
    }
    sharedBlock->SetStartPos(blockInfo.startPos);
    sharedBlock->SetBlockPos(required - blockInfo.startPos);
    sharedBlock->SetLastPos(blockInfo.startPos + sharedBlock->GetRowNum());
    if (needCount) {
        rowNum = static_cast<int>(GetCombinedData(blockInfo.startPos, blockInfo.totalRows));
    }
    return { statement->Reset(), rowNum };
}
} // namespace NativeRdb
} // namespace OHOS