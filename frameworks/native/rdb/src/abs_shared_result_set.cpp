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
#define LOG_TAG "AbsSharedResultSet"
#include "abs_shared_result_set.h"

#include <securec.h>

#include <algorithm>
#include <codecvt>
#include <iostream>
#include <sstream>
#include <string>

#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "rdb_trace.h"
#include "shared_block.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Block = AppDataFwk::SharedBlock;

AbsSharedResultSet::AbsSharedResultSet(std::string name) : sharedBlock_(nullptr), sharedBlockName_(std::move(name))
{
}

AbsSharedResultSet::AbsSharedResultSet()
{
}

AbsSharedResultSet::~AbsSharedResultSet()
{
    ClosedBlock();
}

int AbsSharedResultSet::GetRowCount(int &count)
{
    return E_OK;
}

int32_t AbsSharedResultSet::OnGo(int oldRowIndex, int newRowIndex)
{
    return E_OK;
}

/**
 * Get current shared block
 */
std::shared_ptr<AppDataFwk::SharedBlock> AbsSharedResultSet::GetBlock()
{
    std::lock_guard<decltype(globalMtx_)> lockGuard(globalMtx_);
    if (sharedBlock_ != nullptr || isClosed_) {
        return sharedBlock_;
    }
    AppDataFwk::SharedBlock *block = nullptr;
    AppDataFwk::SharedBlock::Create(sharedBlockName_, DEFAULT_BLOCK_SIZE, block);
    sharedBlock_ = std::shared_ptr<AppDataFwk::SharedBlock>(block);
    return sharedBlock_;
}

int AbsSharedResultSet::GetColumnType(int columnIndex, ColumnType &columnType)
{
    auto block = GetBlock();
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    Block::CellUnit* cellUnit = block->GetCellUnit(block->GetBlockPos(), (uint32_t)columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetColumnType cellUnit is null!");
        return E_ERROR;
    }
    columnType = (ColumnType)cellUnit->type;
    return E_OK;
}

int AbsSharedResultSet::GoToRow(int position)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (position == rowPos_) {
        return E_OK;
    }

    if (position < 0) {
        LOG_ERROR("Invalid position %{public}d!", position);
        return E_ERROR;
    }

    int rowCnt = 0;
    auto ret = GetRowCount(rowCnt);
    if (ret != E_OK || rowCnt == 0) {
        LOG_ERROR("GetRowCount ret is %{public}d, rowCount is %{public}d", ret, rowCnt);
        return ret == E_OK ? E_ERROR : ret;
    }

    if (position >= rowCnt) {
        rowPos_ = rowCnt;
        return E_ROW_OUT_RANGE;
    }

    if (rowPos_ <= INIT_POS) {
        rowPos_ = 0;
    }

    auto block = GetBlock();
    if (block == nullptr || (uint32_t)position < block->GetStartPos() ||
        (uint32_t)position >= block->GetLastPos() || rowPos_ == rowCnt) {
        ret = OnGo(rowPos_, position);
    } else {
        uint32_t blockPos = block->GetBlockPos();
        if (position > rowPos_) {
            blockPos += (uint32_t)(position - rowPos_);
        } else {
            uint32_t offset = (uint32_t)(rowPos_ - position);
            if (blockPos >= offset) {
                blockPos -= offset;
            } else {
                LOG_ERROR("GoToRow failed of position= %{public}d, rowPos= %{public}d", position, rowPos_);
                return E_ERROR;
            }
        }
        block->SetBlockPos(blockPos);
    }

    if (ret == E_OK) {
        rowPos_ = position;
    }
    return ret;
}

int AbsSharedResultSet::GetString(int columnIndex, std::string &value)
{
    return AbsResultSet::GetString(columnIndex, value);
}

int AbsSharedResultSet::Get(int32_t col, ValueObject& value)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto block = GetBlock();
    int errorCode = CheckState(col);
    if (errorCode != E_OK || block == nullptr) {
        return errorCode;
    }

    auto *cellUnit = block->GetCellUnit(block->GetBlockPos(), col);
    if (cellUnit == nullptr) {
        LOG_ERROR("cellUnit is null, col is %{public}d!", col);
        return E_ERROR;
    }

    switch (cellUnit->type) {
        case AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL:
            break;
        case AppDataFwk::SharedBlock::CELL_UNIT_TYPE_INTEGER:
            value = cellUnit->cell.longValue;
            break;
        case AppDataFwk::SharedBlock::CELL_UNIT_TYPE_FLOAT:
            value = cellUnit->cell.doubleValue;
            break;
        case AppDataFwk::SharedBlock::CELL_UNIT_TYPE_STRING:
            value = cellUnit->GetString(block.get());
            break;
        case AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB:
            value = cellUnit->GetBlob(block.get());
            break;
        default:
            return GetCustomerValue(col, value, block.get());
    }
    return E_OK;
}

int AbsSharedResultSet::GetSize(int columnIndex, size_t &size)
{
    size = 0;
    auto block = GetBlock();
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }

    auto *cellUnit = block->GetCellUnit(GetBlock()->GetBlockPos(), columnIndex);
    if (cellUnit == nullptr) {
        LOG_ERROR("cellUnit is null!");
        return E_ERROR;
    }

    int type = cellUnit->type;
    if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_STRING
        || type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB
        || type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        size = cellUnit->cell.stringOrBlobValue.size;
        return E_OK;
    }

    return E_INVALID_OBJECT_TYPE;
}

int AbsSharedResultSet::Close()
{
    if (!isClosed_) {
        AbsResultSet::Close();
        ClosedBlock();
        auto name = std::move(sharedBlockName_);
    }
    return E_OK;
}

/**
 * Allocates a new shared block to an {@link AbsSharedResultSet}
 */
void AbsSharedResultSet::SetBlock(AppDataFwk::SharedBlock *block)
{
    std::lock_guard<decltype(globalMtx_)> lockGuard(globalMtx_);
    if (sharedBlock_.get() != block) {
        sharedBlock_ = std::shared_ptr<AppDataFwk::SharedBlock>(block);
    }
}

/**
 * Checks whether an {@code AbsSharedResultSet} object contains shared blocks
 */
bool AbsSharedResultSet::HasBlock()
{
    return GetBlock() != nullptr;
}

/**
 * Closes a shared block that is not empty in this {@code AbsSharedResultSet} object
 */
void AbsSharedResultSet::ClosedBlock()
{
    std::lock_guard<decltype(globalMtx_)> lockGuard(globalMtx_);
    sharedBlock_ = nullptr;
}

void AbsSharedResultSet::ClearBlock()
{
    auto block = GetBlock();
    if (block != nullptr) {
        block->Clear();
    }
}

void AbsSharedResultSet::Finalize()
{
    Close();
}

int AbsSharedResultSet::GetCustomerValue(int index, ValueObject& value, AppDataFwk::SharedBlock *block)
{
    auto *cellUnit = block->GetCellUnit(block->GetBlockPos(), index);
    if (cellUnit == nullptr) {
        LOG_ERROR("cellUnit is null, col is %{public}d!", index);
        return E_ERROR;
    }

    size_t size = cellUnit->cell.stringOrBlobValue.size;
    auto data = cellUnit->GetRawData(block);
    switch (cellUnit->type) {
        case AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET: {
            ValueObject::Asset asset;
            RawDataParser::ParserRawData(data, size, asset);
            value = std::move(asset);
            break;
        }
        case AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS: {
            ValueObject::Assets assets;
            RawDataParser::ParserRawData(data, size, assets);
            value = std::move(assets);
            break;
        }
        case AppDataFwk::SharedBlock::CELL_UNIT_TYPE_FLOATS: {
            ValueObject::FloatVector floats;
            RawDataParser::ParserRawData(data, size, floats);
            value = std::move(floats);
            break;
        }
        case AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BIGINT: {
            ValueObject::BigInt bigInt;
            RawDataParser::ParserRawData(data, size, bigInt);
            value = std::move(bigInt);
            break;
        }
        default:
            LOG_ERROR("invalid type is %{public}d, col is %{public}d!", cellUnit->type, index);
            return E_INVALID_OBJECT_TYPE;
    }
    return E_OK;
}

/**
 * Check current status
 */
int AbsSharedResultSet::CheckState(int columnIndex)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }
    if (GetBlock() == nullptr) {
        LOG_ERROR("sharedBlock is null!");
        return E_ERROR;
    }
    int count = 0;
    GetRowCount(count);
    if (rowPos_ < 0 || rowPos_ >= count) {
        return E_ROW_OUT_RANGE;
    }
    
    GetColumnCount(count);
    if (columnIndex >= count || columnIndex < 0) {
        return E_COLUMN_OUT_RANGE;
    }

    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
