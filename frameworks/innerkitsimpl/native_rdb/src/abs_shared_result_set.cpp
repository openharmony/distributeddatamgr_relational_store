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

#include <algorithm>
#include <iostream>
#include <string>
#include <codecvt>
#include <sstream>
#include <securec.h>

#include "logger.h"
#include "parcel.h"
#include "string_ex.h"
#include "rdb_errno.h"
#include "shared_block.h"

namespace OHOS {
namespace NativeRdb {
AbsSharedResultSet::AbsSharedResultSet(std::string name)
{
    AppDataFwk::SharedBlock::Create(name, DEFAULT_BLOCK_SIZE, &sharedBlock);
}
AbsSharedResultSet::~AbsSharedResultSet() {}

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
AppDataFwk::SharedBlock* AbsSharedResultSet::GetBlock() const
{
    return sharedBlock;
}

int AbsSharedResultSet::GetColumnTypeForIndex(int columnIndex, ColumnType &columnType)
{
    AppDataFwk::SharedBlock::CellUnit *cellUnit = sharedBlock->GetCellUnit((uint32_t)rowPos, (uint32_t)columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetColumnTypeForIndex cellUnit is null!");
        return E_ERROR;
    }
    columnType = (ColumnType)cellUnit->type;
    return E_OK;
}

int AbsSharedResultSet::GoToRow(int position)
{
    int rowCnt = 0;
    GetRowCount(rowCnt);
    if (position >= rowCnt) {
        rowPos = rowCnt;
        return E_ERROR;
    }
    if (position < 0) {
        rowPos = INIT_POS;
        return E_ERROR;
    }
    if (position == rowPos) {
        return E_OK;
    }
    bool result = OnGo(rowPos, position);
    if (!result) {
        rowPos = INIT_POS;
        return E_ERROR;
    } else {
        rowPos = position;
        return E_OK;
    }
}

int AbsSharedResultSet::GetBlob(int columnIndex, std::vector<uint8_t> &blob)
{
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }

    AppDataFwk::SharedBlock::CellUnit *cellUnit = sharedBlock->GetCellUnit(rowPos, columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetBlob cellUnit is null!");
        return E_ERROR;
    }

    size_t size;
    const void *value = sharedBlock->GetCellUnitValueBlob(cellUnit, &size);
    const auto *tempValue = static_cast<const uint8_t *>(value);
    auto *pVau = const_cast<uint8_t *>(tempValue);
    if (pVau != nullptr) {
        LOG_ERROR("AbsSharedResultSet::GetBlob cellUnit is not null!");
    }
    uint8_t *pTempVau = pVau;
    size_t tempSize = size / sizeof(*pVau);

    for (; pTempVau < (pVau + tempSize); pTempVau++) {
        blob.push_back(*pTempVau);
    }
    return 0;
}

int AbsSharedResultSet::GetString(int columnIndex, std::string &value)
{
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit = sharedBlock->GetCellUnit(rowPos, columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetString cellUnit is null!");
        return E_ERROR;
    }
    int type = cellUnit->type;
    if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_STRING) {
        size_t sizeIncludingNull;
        const char *tempValue = sharedBlock->GetCellUnitValueString(cellUnit, &sizeIncludingNull);
        if ((sizeIncludingNull <= 1) || (tempValue == nullptr)) {
            value = "";
            return E_ERROR;
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
        LOG_ERROR("AbsSharedResultSet::AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL!");
        return E_ERROR;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB) {
        LOG_ERROR("AbsSharedResultSet::AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB!");
        return E_ERROR;
    } else {
        LOG_ERROR("AbsSharedResultSet::GetString is failed!");
        return E_ERROR;
    }
}

int AbsSharedResultSet::GetInt(int columnIndex, int &value)
{
    AppDataFwk::SharedBlock::CellUnit *cellUnit = sharedBlock->GetCellUnit(rowPos, columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::GetInt cellUnit is null!");
        return E_ERROR;
    }
    value = (int)cellUnit->cell.longValue;
    return E_OK;
}

int AbsSharedResultSet::GetLong(int columnIndex, int64_t &value)
{
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit = sharedBlock->GetCellUnit(rowPos, columnIndex);
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
        const char *tempValue = sharedBlock->GetCellUnitValueString(cellUnit, &sizeIncludingNull);
        value = ((sizeIncludingNull > 1) && (tempValue != nullptr)) ? long(strtoll(tempValue, nullptr, 0)) : 0L;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_FLOAT) {
        value = (int64_t)cellUnit->cell.doubleValue;
        LOG_ERROR("AbsSharedResultSet::GetLong AppDataFwk::SharedBlock::CELL_UNIT_TYPE_FLOAT !");
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        LOG_ERROR("AbsSharedResultSet::GetLong AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL !");
        value = 0L;
        return E_OK;
    } else if (type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB) {
        LOG_ERROR("AbsSharedResultSet::GetLong AppDataFwk::SharedBlock::CELL_UNIT_TYPE_BLOB !");
        value = 0L;
        return E_OK;
    } else {
        LOG_ERROR("AbsSharedResultSet::GetLong Nothing !");
        return E_INVALID_OBJECT_TYPE;
    }
}

int AbsSharedResultSet::GetDouble(int columnIndex, double &value)
{
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit = sharedBlock->GetCellUnit(rowPos, columnIndex);
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
        const char *tempValue = sharedBlock->GetCellUnitValueString(cellUnit, &sizeIncludingNull);
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
    } else {
        LOG_ERROR("AbsSharedResultSet::GetDouble AppDataFwk::SharedBlock::nothing !");
        value = 0.0;
        return E_INVALID_OBJECT_TYPE;
    }
}

int AbsSharedResultSet::IsColumnNull(int columnIndex, bool &isNull)
{
    int errorCode = CheckState(columnIndex);
    if (errorCode != E_OK) {
        return errorCode;
    }
    AppDataFwk::SharedBlock::CellUnit *cellUnit = sharedBlock->GetCellUnit(rowPos, columnIndex);
    if (!cellUnit) {
        LOG_ERROR("AbsSharedResultSet::IsColumnNull cellUnit is null!");
        return E_ERROR;
    }
    if (cellUnit->type == AppDataFwk::SharedBlock::CELL_UNIT_TYPE_NULL) {
        isNull = true;
        return E_OK;
    }
    isNull = false;
    return E_ERROR;
}

int AbsSharedResultSet::Close()
{
    AbsResultSet::Close();
    ClosedBlock();
    return E_OK;
}

/**
 * Allocates a new shared block to an {@link AbsSharedResultSet}
 */
void AbsSharedResultSet::SetBlock(AppDataFwk::SharedBlock *block)
{
    if (this->sharedBlock != block) {
        ClosedBlock();
        this->sharedBlock = block;
    }
}

/**
 * Checks whether an {@code AbsSharedResultSet} object contains shared blocks
 */
bool AbsSharedResultSet::HasBlock() const
{
    return this->sharedBlock != nullptr;
}

/**
 * Closes a shared block that is not empty in this {@code AbsSharedResultSet} object
 */
void AbsSharedResultSet::ClosedBlock()
{
    if (this->sharedBlock != nullptr) {
        delete sharedBlock;
        sharedBlock = nullptr;
    }
}

void AbsSharedResultSet::ClearBlock()
{
    if (this->sharedBlock != nullptr) {
        sharedBlock->Clear();
    }
}

void AbsSharedResultSet::Finalize()
{
    if (this->sharedBlock != nullptr) {
        Close();
    }
}

/**
 * Check current status
 */
int AbsSharedResultSet::CheckState(int columnIndex)
{
    if (sharedBlock == nullptr) {
        LOG_ERROR("AbsSharedResultSet::CheckState sharedBlock is null!");
        return E_ERROR;
    }
    int cnt = 0;
    GetColumnCount(cnt);
    if (columnIndex >= cnt || columnIndex < 0) {
        return E_INVALID_COLUMN_INDEX;
    }
    int rowCnt = 0;
    GetRowCount(rowCnt);
    if (rowPos < 0 || rowPos >= rowCnt) {
        return E_INVALID_STATEMENT;
    }
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
