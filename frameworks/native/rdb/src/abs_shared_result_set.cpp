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

AbsSharedResultSet::AbsSharedResultSet(std::string name) : sharedBlock_(nullptr), sharedBlockName_(name)
{
}

AbsSharedResultSet::AbsSharedResultSet()
{
}

AbsSharedResultSet::~AbsSharedResultSet()
{
    ClosedBlock();
}

int AbsSharedResultSet::GetAllColumnNames(std::vector<std::string> &columnNames)
{
    return E_OK;
}

int AbsSharedResultSet::GetRowCount(int &count)
{
    return E_OK;
}

bool AbsSharedResultSet::OnGo(int oldRowIndex, int newRowIndex)
{
    return true;
}

void AbsSharedResultSet::FillBlock(int startRowIndex, AppDataFwk::SharedBlock *block)
{
    return;
}

/**
 * Get current shared block
 */
AppDataFwk::SharedBlock *AbsSharedResultSet::GetBlock()
{
    if (sharedBlock_ != nullptr) {
        return sharedBlock_;
    }
    AppDataFwk::SharedBlock::Create(sharedBlockName_, DEFAULT_BLOCK_SIZE, sharedBlock_);
    return sharedBlock_;
}

int AbsSharedResultSet::GetColumnType(int columnIndex, ColumnType &columnType)
{
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit =
        GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), (uint32_t)columnIndex);
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
    if (position == rowPos_) {
        return E_OK;
    }

    if (position < 0) {
        LOG_ERROR("Invalid position %{public}d!", position);
        return E_ERROR;
    }

    int rowCnt = 0;
    GetRowCount(rowCnt);
    if (rowCnt == 0) {
        LOG_DEBUG("No data!");
        return E_ERROR;
    }

    if (position >= rowCnt) {
        rowPos_ = rowCnt;
        return E_ERROR;
    }

    if (rowPos_ <= INIT_POS) {
        rowPos_ = 0;
    }

    bool result = true;
    if (GetBlock() == nullptr || (uint32_t)position < GetBlock()->GetStartPos() ||
        (uint32_t)position >= GetBlock()->GetLastPos() || rowPos_ == rowCnt) {
        result = OnGo(rowPos_, position);
    } else {
        uint32_t blockPos = GetBlock()->GetBlockPos();
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
        GetBlock()->SetBlockPos(blockPos);
    }

    if (result) {
        rowPos_ = position;
        return E_OK;
    }
    return E_ERROR;
}

int AbsSharedResultSet::GetBlob(int columnIndex, std::vector<uint8_t> &value)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }

    AppDataFwk::SharedBlock::CellUnit *cellUnit = GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetBlob cellUnit is null!");
        return E_ERROR;
    }

    value.resize(0);
    int type = cellUnit->type;
    if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB
        || type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_STRING) {
        size_t size;
        const auto *blob = static_cast<const uint8_t *>(GetBlock()->GetCellUnitValueBlob(cellUnit, &size));
        if (size == 0 || blob == nullptr) {
            LOG_WARN("blob data is empty!");
        } else {
            value.resize(size);
            value.assign(blob, blob + size);
        }
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_INTEGER) {
        LOG_ERROR("AbsSharedResultSet::GetBlob AppDataFwk::SharedBlock::CELL_UNIT_TYPE_INTEGER!");
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        LOG_ERROR("AbsSharedResultSet::GetBlob AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL!");
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_FLOAT) {
        LOG_ERROR("AbsSharedResultSet::GetBlob AppDataFwk::SharedBlock::CELL_UNIT_TYPE_FLOAT!");
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET) {
        LOG_ERROR("AbsSharedResultSet::GetBlob AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET!");
        return E_INVALID_OBJECT_TYPE;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS) {
        LOG_ERROR("AbsSharedResultSet::GetBlob AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS!");
        return E_INVALID_OBJECT_TYPE;
    } else {
        LOG_ERROR("AbsSharedResultSet::GetBlob AppDataFwk::SharedBlock::nothing !");
        return E_INVALID_OBJECT_TYPE;
    }
}

int AbsSharedResultSet::GetString(int columnIndex, std::string &value)
{
    DISTRIBUTED_DATA_HITRACE("AbsSharedResultSet::GetString");
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit = GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetString cellUnit is null!");
        return E_ERROR;
    }
    int type = cellUnit->type;
    if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_STRING) {
        size_t sizeIncludingNull;
        const char *tempValue = GetBlock()->GetCellUnitValueString(cellUnit, &sizeIncludingNull);
        if ((sizeIncludingNull <= 1) || (tempValue == nullptr)) {
            value = "";
            return E_OK;
        }
        value = tempValue;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_INTEGER) {
        int64_t tempValue = cellUnit->cell.longValue;
        value = std::to_string(tempValue);
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_FLOAT) {
        double tempValue = cellUnit->cell.doubleValue;
        std::ostringstream os;
        if (os << tempValue)
            value = os.str();
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB) {
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET) {
        LOG_ERROR("AbsSharedResultSet::GetString AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET !");
        return E_INVALID_OBJECT_TYPE;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS) {
        LOG_ERROR("AbsSharedResultSet::GetString AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS !");
        return E_INVALID_OBJECT_TYPE;
    } else {
        LOG_ERROR("AbsSharedResultSet::GetString is failed!");
        return E_ERROR;
    }
}

int AbsSharedResultSet::GetInt(int columnIndex, int &value)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit = GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetInt cellUnit is null!");
        return E_ERROR;
    }
    value = (int)cellUnit->cell.longValue;
    return E_OK;
}

int AbsSharedResultSet::GetLong(int columnIndex, int64_t &value)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit = GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetLong cellUnit is null!");
        return E_ERROR;
    }

    int type = cellUnit->type;

    if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_INTEGER) {
        value = cellUnit->cell.longValue;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_STRING) {
        size_t sizeIncludingNull;
        const char *tempValue = GetBlock()->GetCellUnitValueString(cellUnit, &sizeIncludingNull);
        value = ((sizeIncludingNull > 1) && (tempValue != nullptr)) ? int64_t(strtoll(tempValue, nullptr, 0)) : 0L;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_FLOAT) {
        value = (int64_t)cellUnit->cell.doubleValue;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        value = 0L;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB) {
        value = 0L;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET) {
        LOG_ERROR("AbsSharedResultSet::GetLong AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET !");
        return E_INVALID_OBJECT_TYPE;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS) {
        LOG_ERROR("AbsSharedResultSet::GetLong AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS !");
        return E_INVALID_OBJECT_TYPE;
    } else {
        LOG_ERROR("AbsSharedResultSet::GetLong Nothing !");
        return E_INVALID_OBJECT_TYPE;
    }
}

int AbsSharedResultSet::GetDouble(int columnIndex, double &value)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit = GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetDouble cellUnit is null!");
        return E_ERROR;
    }
    int type = cellUnit->type;
    if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_FLOAT) {
        value = cellUnit->cell.doubleValue;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_STRING) {
        size_t sizeIncludingNull;
        const char *tempValue = GetBlock()->GetCellUnitValueString(cellUnit, &sizeIncludingNull);
        value = ((sizeIncludingNull > 1) && (tempValue != nullptr)) ? strtod(tempValue, nullptr) : 0.0;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_INTEGER) {
        value = cellUnit->cell.longValue;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        LOG_ERROR("AbsSharedResultSet::GetDouble AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL!");
        value = 0.0;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB) {
        LOG_ERROR("AbsSharedResultSet::GetDouble AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB!");
        value = 0.0;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET) {
        LOG_ERROR("AbsSharedResultSet::GetDouble AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET!");
        return E_INVALID_OBJECT_TYPE;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS) {
        LOG_ERROR("AbsSharedResultSet::GetDouble AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS!");
        return E_INVALID_OBJECT_TYPE;
    } else {
        LOG_ERROR("AbsSharedResultSet::GetDouble AppDataFwk::SharedBlock::nothing !");
        value = 0.0;
        return E_INVALID_OBJECT_TYPE;
    }
}

int AbsSharedResultSet::GetAsset(int32_t col, ValueObject::Asset &value)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errorCode = CheckState(col);
    if (errorCode != E_OK) {
        return errorCode;
    }

    AppDataFwk::SharedBlock::CellUnit *cellUnit = GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), col);
    if (!cellUnit) {
        LOG_ERROR("GetAsset cellUnit is null!");
        return E_ERROR;
    }

    if (cellUnit->type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        LOG_ERROR("GetAsset the type of cell is null !");
        return E_NULL_OBJECT;
    }
    
    if (cellUnit->type != AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSET) {
        LOG_ERROR("GetAssets the type of cell is not assets, type is %{public}d, col is %{public}d!", cellUnit->type,
            col);
        return E_INVALID_OBJECT_TYPE;
    }

    size_t size = 0;
    auto data = reinterpret_cast<const uint8_t *>(GetBlock()->GetCellUnitValueBlob(cellUnit, &size));
    ValueObject::Asset asset;
    RawDataParser::ParserRawData(data, size, asset);
    value = std::move(asset);
    return E_OK;
}

int AbsSharedResultSet::GetAssets(int32_t col, ValueObject::Assets &value)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int errorCode = CheckState(col);
    if (errorCode != E_OK) {
        return errorCode;
    }

    auto *cellUnit = GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), col);
    if (!cellUnit) {
        LOG_ERROR("GetAssets cellUnit is null!");
        return E_ERROR;
    }

    if (cellUnit->type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        LOG_ERROR("GetAssets the type of cell is null !");
        return E_NULL_OBJECT;
    }

    if (cellUnit->type != AppDataFwk::SharedBlock::CELL_UNIT_TYPE_ASSETS) {
        LOG_ERROR("GetAssets the type of cell is not assets, type is %{public}d, col is %{public}d!", cellUnit->type,
            col);
        return E_INVALID_OBJECT_TYPE;
    }

    size_t size = 0;
    auto data = reinterpret_cast<const uint8_t *>(GetBlock()->GetCellUnitValueBlob(cellUnit, &size));
    ValueObject::Assets assets;
    RawDataParser::ParserRawData(data, size, assets);
    value = std::move(assets);
    return E_OK;
}

int AbsSharedResultSet::GetSize(int columnIndex, size_t &size)
{
    size = 0;
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }

    AppDataFwk::SharedBlock::CellUnit *cellUnit = GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), columnIndex);
    if (cellUnit == nullptr) {
        LOG_ERROR("cellUnit is null!");
        return E_ERROR;
    }

    int type = cellUnit->type;
    if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_STRING
        || type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB
        || type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        GetBlock()->GetCellUnitValueBlob(cellUnit, &size);
        return E_OK;
    }

    return E_INVALID_OBJECT_TYPE;
}

int AbsSharedResultSet::IsColumnNull(int columnIndex, bool &isNull)
{
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit = GetBlock()->GetCellUnit(GetBlock()->GetBlockPos(), columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::IsColumnNull cellUnit is null!");
        return E_ERROR;
    }
    if (cellUnit->type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        isNull = true;
        return E_OK;
    }
    isNull = false;
    return E_OK;
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
    if (GetBlock() != block) {
        ClosedBlock();
        sharedBlock_ = block;
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
    if (sharedBlock_ != nullptr) {
        delete sharedBlock_;
        sharedBlock_ = nullptr;
    }
}

void AbsSharedResultSet::ClearBlock()
{
    if (GetBlock() != nullptr) {
        GetBlock()->Clear();
    }
}

void AbsSharedResultSet::Finalize()
{
    Close();
}

/**
 * Check current status
 */
int AbsSharedResultSet::CheckState(int columnIndex)
{
    if (GetBlock() == nullptr) {
        LOG_ERROR("AbsSharedResultSet::CheckState sharedBlock is null!");
        return E_ERROR;
    }
    int count = 0;
    GetRowCount(count);
    if (rowPos_ < 0 || rowPos_ >= count) {
        return E_INVALID_STATEMENT;
    }
    
    GetColumnCount(count);
    if (columnIndex >= count || columnIndex < 0) {
        return E_INVALID_COLUMN_INDEX;
    }

    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
