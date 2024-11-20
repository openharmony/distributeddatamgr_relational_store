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

#include <cinttypes>
#include <cstdint>
#include <memory>
#include <mutex>
#include <tuple>

#include "logger.h"
#include "rdb_sql_statistic.h"
#include "rdb_sql_utils.h"
#include "result_set.h"
#include "share_block.h"
#include "sqlite_connection.h"
#include "sqlite_errno.h"
#include "sqlite_statement.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
constexpr int64_t TIME_OUT = 1500;
SqliteSharedResultSet::SqliteSharedResultSet(
    Time start, Conn conn, std::string sql, const Values &args, const std::string &path)
    : AbsSharedResultSet(path), conn_(std::move(conn)), qrySql_(std::move(sql)), bindArgs_(args)
{
    if (conn_ == nullptr) {
        isClosed_ = true;
        return;
    }

    auto prepareBegin = steady_clock::now();
    auto [statement, errCode] = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("step resultset ret %{public}d", errCode);
        return;
    }
    statement_ = statement;
    auto countBegin = steady_clock::now();
    rowCount_ = InitRowCount();
    auto endTime = steady_clock::now();
    int64_t totalCost = duration_cast<milliseconds>(endTime - start).count();
    if (totalCost >= TIME_OUT) {
        int64_t acquireCost = duration_cast<milliseconds>(prepareBegin - start).count();
        int64_t prepareCost = duration_cast<milliseconds>(countBegin - prepareBegin).count();
        int64_t countCost = duration_cast<milliseconds>(endTime - countBegin).count();
        LOG_WARN("total[%{public}" PRId64 "]<%{public}" PRId64 ",%{public}" PRId64 ",%{public}" PRId64
                 "> rowCount[%{public}d] sql[%{public}s] path[%{public}s]",
            totalCost, acquireCost, prepareCost, countCost, rowCount_, qrySql_.c_str(),
            SqliteUtils::Anonymous(path).c_str());
    }
}

int SqliteSharedResultSet::InitRowCount()
{
    if (statement_ == nullptr) {
        return NO_COUNT;
    }
    int32_t count = NO_COUNT;
    int32_t status = E_OK;
    int32_t retry = 0;
    do {
        status = statement_->Step();
        if (status == E_SQLITE_BUSY || status == E_SQLITE_LOCKED) {
            retry++;
            usleep(RETRY_INTERVAL);
            continue;
        }
        count++;
    } while (status == E_OK || ((status == E_SQLITE_BUSY || status == E_SQLITE_LOCKED) && retry < MAX_RETRY_TIMES));
    if (status != E_NO_MORE_ROWS) {
        lastErr_ = status;
        count = NO_COUNT;
    }
    statement_->Reset();
    return count;
}

std::pair<std::shared_ptr<Statement>, int> SqliteSharedResultSet::PrepareStep()
{
    if (conn_ == nullptr) {
        LOG_ERROR("Already close.");
        lastErr_ = E_ALREADY_CLOSED;
        return { nullptr, E_ALREADY_CLOSED };
    }

    if (statement_ != nullptr) {
        return { statement_, E_OK };
    }

    auto type = SqliteUtils::GetSqlStatementType(qrySql_);
    if (type == SqliteUtils::STATEMENT_ERROR) {
        LOG_ERROR("invalid sql_ %{public}s!", qrySql_.c_str());
        lastErr_ = E_INVALID_ARGS;
        return { nullptr, E_INVALID_ARGS };
    }

    auto [errCode, statement] = conn_->CreateStatement(qrySql_, conn_);
    if (statement == nullptr) {
        lastErr_ = errCode;
        return { statement, errCode };
    }

    if (!statement->ReadOnly()) {
        LOG_ERROR("failed, %{public}s is not query sql!", SqliteUtils::Anonymous(qrySql_).c_str());
        lastErr_ = E_NOT_SELECT;
        return { nullptr, E_NOT_SELECT };
    }

    errCode = statement->Bind(bindArgs_);
    if (errCode != E_OK) {
        LOG_ERROR("Bind arg faild! Ret is %{public}d", errCode);
        statement->Reset();
        statement = nullptr;
        lastErr_ = errCode;
        return { nullptr, errCode };
    }
    return { statement, E_OK };
}

SqliteSharedResultSet::~SqliteSharedResultSet() {}

std::pair<int, std::vector<std::string>> SqliteSharedResultSet::GetColumnNames()
{
    if (isClosed_) {
        LOG_ERROR(
            "fail, result set has been closed, ret %{public}d, sql %{public}s", E_ALREADY_CLOSED, qrySql_.c_str());
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

int SqliteSharedResultSet::Close()
{
    AbsSharedResultSet::Close();
    statement_ = nullptr;
    conn_ = nullptr;
    rowCount_ = NO_COUNT;
    auto qrySql = std::move(qrySql_);
    auto bindArgs = std::move(bindArgs_);
    return E_OK;
}

int SqliteSharedResultSet::OnGo(int oldPosition, int newPosition)
{
    if (isClosed_) {
        LOG_ERROR(
            "fail, result set has been closed, ret %{public}d, sql %{public}s", E_ALREADY_CLOSED, qrySql_.c_str());
        return E_ALREADY_CLOSED;
    }
    if (GetBlock() == nullptr) {
        return E_ERROR;
    }
    if ((uint32_t)newPosition < GetBlock()->GetStartPos() || (uint32_t)newPosition >= GetBlock()->GetLastPos() ||
        oldPosition == rowCount_) {
        return FillBlock(newPosition);
    }
    return E_OK;
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
    int startPos = isOnlyFillBlock_ ? requiredPos : PickFillBlockStartPosition(requiredPos, blockCapacity_);
    auto errCode = ExecuteForSharedBlock(block.get(), startPos, requiredPos);
    if (errCode != E_OK) {
        return errCode;
    }
    blockCapacity_ = block->GetRowNum();
    if ((block->GetStartPos() == block->GetLastPos() && (uint32_t)rowCount_ != block->GetStartPos()) ||
        ((uint32_t)requiredPos < block->GetStartPos() || block->GetLastPos() <= (uint32_t)requiredPos) ||
        block->GetStartPos() > 0) {
        LOG_WARN("blockRowNum=%{public}d, requiredPos= %{public}d, startPos_= %{public}" PRIu32
                 ", lastPos_= %{public}" PRIu32 ", blockPos_= %{public}" PRIu32 ".",
            rowCount_, requiredPos, block->GetStartPos(), block->GetLastPos(), block->GetBlockPos());
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
int32_t SqliteSharedResultSet::ExecuteForSharedBlock(AppDataFwk::SharedBlock *block, int start, int required)
{
    auto [statement, errCode] = PrepareStep();
    if (errCode != E_OK) {
        LOG_ERROR("PrepareStep error = %{public}d ", errCode);
        return errCode;
    }

    auto code = block->Clear();
    if (code != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        LOG_ERROR("Clear %{public}d.", code);
        return E_ERROR;
    }

    SharedBlockInfo blockInfo(block);
    blockInfo.requiredPos = required;
    blockInfo.columnNum = statement->GetColumnCount();
    blockInfo.isCountAllRows = false;
    blockInfo.startPos = start;
    code = block->SetColumnNum(blockInfo.columnNum);
    if (code != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        LOG_ERROR("SetColumnNum %{public}d.", code);
        return E_ERROR;
    }
    errCode = statement->FillBlockInfo(&blockInfo);
    if (errCode != E_OK) {
        LOG_ERROR("Fill shared block failed, ret is %{public}d", errCode);
        return errCode;
    }

    block->SetStartPos(blockInfo.startPos);
    block->SetBlockPos(required - blockInfo.startPos);
    block->SetLastPos(blockInfo.startPos + block->GetRowNum());
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS