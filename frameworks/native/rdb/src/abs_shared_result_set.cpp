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
using SharedBlock = AppDataFwk::SharedBlock;
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
    return AbsResultSet::GetRowCount(count);
}

int32_t AbsSharedResultSet::OnGo(int oldRowIndex, int newRowIndex)
{
    return E_OK;
}

/**
 * Get current shared block
 */
std::shared_ptr<SharedBlock> AbsSharedResultSet::GetBlock()
{
    std::lock_guard<decltype(globalMtx_)> lockGuard(globalMtx_);
    if (sharedBlock_ != nullptr || isClosed_ || lowMem_) {
        return sharedBlock_;
    }
    SharedBlock *block = nullptr;
    auto errcode = SharedBlock::Create(sharedBlockName_, DEFAULT_BLOCK_SIZE, block);
    if (errcode != SharedBlock::SHARED_BLOCK_OK) {
        lowMem_ = true;
        return nullptr;
    }
    sharedBlock_ = std::shared_ptr<SharedBlock>(block);
    return sharedBlock_;
}

int AbsSharedResultSet::GetColumnType(int columnIndex, ColumnType &columnType)
{
    auto block = GetBlock();
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    SharedBlock::CellUnit *cellUnit = block->GetCellUnit(block->GetBlockPos(), (uint32_t)columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetColumnType cellUnit is null!");
        return E_ERROR;
    }
    columnType = (ColumnType)cellUnit->type;
    return E_OK;
}

int AbsSharedResultSet::UpdateBlockPos(int position, int rowCnt)
{
    auto block = GetBlock();
    auto ret = OnGo(rowPos_, position);
    if (ret == E_OK) {
        uint32_t startPos = block->GetStartPos();
        uint32_t blockPos = block->GetBlockPos();
        if (static_cast<uint32_t>(position) != startPos + blockPos) {
            block->SetBlockPos(position - startPos);
        }
    }
    return ret;
}

int AbsSharedResultSet::GoToRow(int position)
{
    if (isClosed_) {
        return E_ALREADY_CLOSED;
    }

    int rowCnt = 0;
    auto ret = GetRowCount(rowCnt);
    if (ret != E_OK) {
        LOG_ERROR("GetRowCount ret is %{public}d, rowCount is %{public}d", ret, rowCnt);
        return ret;
    }

    if (position >= rowCnt || position < 0) {
        rowPos_ = (position >= rowCnt && rowCnt != 0) ? rowCnt : rowPos_;
        LOG_DEBUG("position[%{public}d] rowCnt[%{public}d] rowPos[%{public}d]!", position, rowCnt, rowPos_);
        return E_ROW_OUT_RANGE;
    }

    if (position == rowPos_) {
        return E_OK;
    }

    ret = UpdateBlockPos(position, rowCnt);
    if (ret == E_OK) {
        rowPos_ = position;
    }
    return ret;
}

int AbsSharedResultSet::GetString(int columnIndex, std::string &value)
{
    return AbsResultSet::GetString(columnIndex, value);
}

int AbsSharedResultSet::Get(int32_t col, ValueObject &value)
{
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
        case SharedBlock::CELL_UNIT_TYPE_NULL:
            break;
        case SharedBlock::CELL_UNIT_TYPE_INTEGER:
            value = cellUnit->cell.longValue;
            break;
        case SharedBlock::CELL_UNIT_TYPE_FLOAT:
            value = cellUnit->cell.doubleValue;
            break;
        case SharedBlock::CELL_UNIT_TYPE_STRING:
            value = cellUnit->GetString(block.get());
            break;
        case SharedBlock::CELL_UNIT_TYPE_BLOB:
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
    if (type == SharedBlock::CELL_UNIT_TYPE_STRING
        || type == SharedBlock::CELL_UNIT_TYPE_BLOB
        || type == SharedBlock::CELL_UNIT_TYPE_NULL) {
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
void AbsSharedResultSet::SetBlock(SharedBlock *block)
{
    std::lock_guard<decltype(globalMtx_)> lockGuard(globalMtx_);
    if (sharedBlock_.get() != block) {
        sharedBlock_ = std::shared_ptr<SharedBlock>(block);
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

int AbsSharedResultSet::GetCustomerValue(int index, ValueObject &value, SharedBlock *block)
{
    auto *cellUnit = block->GetCellUnit(block->GetBlockPos(), index);
    if (cellUnit == nullptr) {
        LOG_ERROR("cellUnit is null, col is %{public}d!", index);
        return E_ERROR;
    }

    size_t size = cellUnit->cell.stringOrBlobValue.size;
    auto data = cellUnit->GetRawData(block);
    switch (cellUnit->type) {
        case SharedBlock::CELL_UNIT_TYPE_ASSET: {
            ValueObject::Asset asset;
            RawDataParser::ParserRawData(data, size, asset);
            value = std::move(asset);
            break;
        }
        case SharedBlock::CELL_UNIT_TYPE_ASSETS: {
            ValueObject::Assets assets;
            RawDataParser::ParserRawData(data, size, assets);
            value = std::move(assets);
            break;
        }
        case SharedBlock::CELL_UNIT_TYPE_FLOATS: {
            ValueObject::FloatVector floats;
            RawDataParser::ParserRawData(data, size, floats);
            value = std::move(floats);
            break;
        }
        case SharedBlock::CELL_UNIT_TYPE_BIGINT: {
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
