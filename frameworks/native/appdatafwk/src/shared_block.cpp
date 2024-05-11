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
#define LOG_TAG "SharedBlock"
#include "shared_block.h"

#include <ashmem.h>
#include <fcntl.h>
#include <securec.h>
#include <sys/mman.h>
#include <unistd.h>

#include <codecvt>
#include <iostream>

#include "logger.h"
#include "string_ex.h"

namespace OHOS {
namespace AppDataFwk {
using namespace OHOS::Rdb;
std::atomic<int64_t> identifier {0};

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
SharedBlock::SharedBlock(const std::string &name, sptr<Ashmem> ashmem, size_t size, bool readOnly)
    : mName(name), ashmem_(ashmem), mSize(size), mReadOnly(readOnly), mHeader(nullptr)
{
}

SharedBlock::~SharedBlock()
{
    if (ashmem_ != nullptr) {
        ashmem_->UnmapAshmem();
        ashmem_->CloseAshmem();
    }
}

bool SharedBlock::Init()
{
    mData = static_cast<uint8_t *>(const_cast<void *>(ashmem_->ReadFromAshmem(sizeof(SharedBlockHeader), 0)));
    mHeader = reinterpret_cast<SharedBlockHeader *>(mData);
    if (mHeader == nullptr) {
        return false;
    }
    return true;
}

int SharedBlock::CreateSharedBlock(const std::string &name, size_t size, sptr<Ashmem> ashmem,
    SharedBlock *&outSharedBlock)
{
    outSharedBlock = new SharedBlock(name, ashmem, size, false);
    if (outSharedBlock == nullptr) {
        LOG_ERROR("CreateSharedBlock: new SharedBlock error.");
        return SHARED_BLOCK_BAD_VALUE;
    }

    if (outSharedBlock->Init() == false) {
        delete outSharedBlock;
        LOG_ERROR("CreateSharedBlock: mHeader is null.");
        return SHARED_BLOCK_ASHMEM_ERROR;
    }
    return SHARED_BLOCK_OK;
}

int SharedBlock::Create(const std::string &name, size_t size, SharedBlock *&outSharedBlock)
{
    std::string ashmemPath;
    size_t lastSlashPos = name.find_last_of('/');
    ashmemPath = (lastSlashPos != std::string::npos) ? name.substr(lastSlashPos) : name;
    std::string ashmemName = "SharedBlock:" + ashmemPath + std::to_string(identifier.fetch_add(1));

    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(ashmemName.c_str(), size);
    if (ashmem == nullptr) {
        LOG_ERROR("SharedBlock: CreateAshmem function error.");
        return SHARED_BLOCK_ASHMEM_ERROR;
    }

    bool ret = ashmem->MapReadAndWriteAshmem();
    if (!ret) {
        LOG_ERROR("SharedBlock: MapReadAndWriteAshmem function error.");
        ashmem->CloseAshmem();
        return SHARED_BLOCK_SET_PORT_ERROR;
    }

    int result = CreateSharedBlock(name, size, ashmem, outSharedBlock);
    if (result == SHARED_BLOCK_OK) {
        return SHARED_BLOCK_OK;
    }
    ashmem->UnmapAshmem();
    ashmem->CloseAshmem();
    outSharedBlock = nullptr;
    return result;
}

int SharedBlock::WriteMessageParcel(MessageParcel &parcel)
{
    return parcel.WriteString16(OHOS::Str8ToStr16(mName)) && parcel.WriteAshmem(ashmem_);
}

int SharedBlock::ReadMessageParcel(MessageParcel &parcel, SharedBlock *&block)
{
    std::string name = OHOS::Str16ToStr8(parcel.ReadString16());
    sptr<Ashmem> ashmem = parcel.ReadAshmem();
    if (UNLIKELY(ashmem == nullptr)) {
        LOG_ERROR("ReadMessageParcel: No ashmem in the parcel.");
        return SHARED_BLOCK_BAD_VALUE;
    }
    bool ret = ashmem->MapReadAndWriteAshmem();
    if (UNLIKELY(!ret)) {
        LOG_ERROR("ReadMessageParcel: MapReadAndWriteAshmem function error.");
        ashmem->CloseAshmem();
        return SHARED_BLOCK_SET_PORT_ERROR;
    }
    block = new (std::nothrow) SharedBlock(name, ashmem, ashmem->GetAshmemSize(), true);
    if (UNLIKELY(block == nullptr)) {
        LOG_ERROR("ReadMessageParcel new SharedBlock error.");
        return SHARED_BLOCK_BAD_VALUE;
    }
    if (UNLIKELY(block->Init() == false)) {
        delete block;
        LOG_ERROR("ReadMessageParcel: mHeader is null.");
        return SHARED_BLOCK_ASHMEM_ERROR;
    }

    LOG_DEBUG("Created SharedBlock from parcel: unusedOffset=%{private}" PRIu32 ", "
              "rowNums=%{private}" PRIu32 ", columnNums=%{private}" PRIu32 ", mSize=%{private}d",
              block->mHeader->unusedOffset, block->mHeader->rowNums, block->mHeader->columnNums,
              static_cast<int>(block->mSize));

    return SHARED_BLOCK_OK;
}

int SharedBlock::Clear()
{
    if (UNLIKELY(mReadOnly)) {
        return SHARED_BLOCK_INVALID_OPERATION;
    }
    if (LIKELY(mHeader != nullptr)) {
        mHeader->unusedOffset = sizeof(SharedBlockHeader) + sizeof(RowGroupHeader);
        mHeader->rowNums = 0;
        mHeader->columnNums = 0;
        mHeader->startPos_ = 0;
        mHeader->lastPos_ = 0;
        mHeader->blockPos_ = 0;
        memset_s(mHeader->groupOffset, sizeof(mHeader->groupOffset), 0, sizeof(mHeader->groupOffset));
        mHeader->groupOffset[0] = sizeof(SharedBlockHeader);
        return SHARED_BLOCK_OK;
    }
    LOG_ERROR("SharedBlock::Clear mHeader is nullptr");
    return SHARED_BLOCK_BAD_VALUE;
}

int SharedBlock::SetColumnNum(uint32_t numColumns)
{
    if (UNLIKELY(mReadOnly)) {
        return SHARED_BLOCK_INVALID_OPERATION;
    }

    uint32_t cur = mHeader->columnNums;
    if ((cur > 0 || mHeader->rowNums > 0) && cur != numColumns) {
        LOG_ERROR("Trying to go from %{public}" PRIu32 " columns to %{public}" PRIu32 "", cur, numColumns);
        return SHARED_BLOCK_INVALID_OPERATION;
    }
    if (numColumns > COL_MAX_NUM) {
        LOG_ERROR("Trying to set %{public}" PRIu32 " columns out of size", numColumns);
        return SHARED_BLOCK_INVALID_OPERATION;
    }
    mHeader->columnNums = numColumns;
    return SHARED_BLOCK_OK;
}

int SharedBlock::AllocRow()
{
    /* Fill in the row offset */
    uint32_t *rowOffset = AllocRowOffset();
    if (UNLIKELY(rowOffset == nullptr)) {
        LOG_ERROR("SharedBlock::AllocRow() Failed in AllocRowOffset().");
        return SHARED_BLOCK_NO_MEMORY;
    }

    /* Allocate the units for the field directory */
    size_t fieldDirSize = mHeader->columnNums * sizeof(CellUnit);

    /* Aligned */
    uint32_t fieldDirOffset = Alloc(fieldDirSize);
    if (UNLIKELY(!fieldDirOffset)) {
        mHeader->rowNums--;
        LOG_INFO("Alloc the row size %{public}u failed, roll back row number %{public}u", fieldDirOffset,
            mHeader->rowNums);
        return SHARED_BLOCK_NO_MEMORY;
    }

    *rowOffset = fieldDirOffset;
    return SHARED_BLOCK_OK;
}

int SharedBlock::FreeLastRow()
{
    if (mHeader->rowNums > 0) {
        mHeader->rowNums--;
    }
    return SHARED_BLOCK_OK;
}

uint32_t SharedBlock::Alloc(size_t size)
{
    /* Number of unused offsets in the header */
    uint32_t offsetDigit = 3;
    uint32_t offset = mHeader->unusedOffset + ((~mHeader->unusedOffset + 1) & offsetDigit);
    uint32_t nextFreeOffset = offset + size;
    if (UNLIKELY(nextFreeOffset > mSize)) {
        LOG_ERROR("SharedBlock is full: requested allocation %{public}zu bytes,"
            " free space %{public}zu bytes, block size %{public}zu bytes",
            size, mSize - mHeader->unusedOffset, mSize);
        return 0;
    }
    mHeader->unusedOffset = nextFreeOffset;
    return offset;
}

uint32_t *SharedBlock::AllocRowOffset()
{
    uint32_t groupPos = mHeader->rowNums / ROW_NUM_IN_A_GROUP;
    if (UNLIKELY(groupPos >= GROUP_NUM)) {
        LOG_ERROR("rows is full. row number %{public}u, groupPos %{public}u", mHeader->rowNums, groupPos);
        return nullptr;
    }
    if (mHeader->groupOffset[groupPos] == 0) {
        mHeader->groupOffset[groupPos] = Alloc(sizeof(RowGroupHeader));
        if (UNLIKELY(mHeader->groupOffset[groupPos] == 0)) {
            LOG_ERROR("SharedBlock::AllocRowOffset() Failed to alloc group->nextGroupOffset "
                "when while loop.");
            return nullptr;
        }
    }

    uint32_t rowPos = mHeader->rowNums % ROW_NUM_IN_A_GROUP;
    RowGroupHeader *group = static_cast<RowGroupHeader *>(OffsetToPtr(mHeader->groupOffset[groupPos]));
    mHeader->rowNums += 1;
    return group->rowOffsets + rowPos;
}

SharedBlock::CellUnit *SharedBlock::GetCellUnit(uint32_t row, uint32_t column)
{
    if (UNLIKELY(row >= mHeader->rowNums || column >= mHeader->columnNums)) {
        LOG_ERROR("Failed to read row %{public}" PRIu32 ", column %{public}" PRIu32 " from a SharedBlock"
            " which has %{public}" PRIu32 " rows, %{public}" PRIu32 " columns.",
            row, column, mHeader->rowNums, mHeader->columnNums);
        return nullptr;
    }

    uint32_t groupPos = row / ROW_NUM_IN_A_GROUP;
    uint32_t rowPos = row % ROW_NUM_IN_A_GROUP;
    RowGroupHeader *group = reinterpret_cast<RowGroupHeader *>(mData + mHeader->groupOffset[groupPos]);
    return reinterpret_cast<CellUnit *>(mData + group->rowOffsets[rowPos]) + column;
}

int SharedBlock::PutBlob(uint32_t row, uint32_t column, const void *value, size_t size)
{
    return PutBlobOrString(row, column, value, size, CELL_UNIT_TYPE_BLOB);
}

int SharedBlock::PutString(uint32_t row, uint32_t column, const char *value, size_t sizeIncludingNull)
{
    return PutBlobOrString(row, column, value, sizeIncludingNull, CELL_UNIT_TYPE_STRING);
}

int SharedBlock::PutAsset(uint32_t row, uint32_t column, const void *value, size_t size)
{
    return PutBlobOrString(row, column, value, size, CELL_UNIT_TYPE_ASSET);
}

int SharedBlock::PutAssets(uint32_t row, uint32_t column, const void *value, size_t size)
{
    return PutBlobOrString(row, column, value, size, CELL_UNIT_TYPE_ASSETS);
}

int SharedBlock::PutFloats(uint32_t row, uint32_t column, const void* value, size_t size)
{
    return PutBlobOrString(row, column, value, size, CELL_UNIT_TYPE_FLOATS);
}

int SharedBlock::PutBigInt(uint32_t row, uint32_t column, const void* value, size_t size)
{
    return PutBlobOrString(row, column, value, size, CELL_UNIT_TYPE_BIGINT);
}

int SharedBlock::PutBlobOrString(uint32_t row, uint32_t column, const void *value, size_t size, int32_t type)
{
    if (UNLIKELY(row >= mHeader->rowNums || column >= mHeader->columnNums)) {
        LOG_ERROR("Failed to read row %{public}" PRIu32 ", column %{public}" PRIu32 " from a SharedBlock"
            " which has %{public}" PRIu32 " rows, %{public}" PRIu32 " columns.",
                row, column, mHeader->rowNums, mHeader->columnNums);
        return SHARED_BLOCK_BAD_VALUE;
    }
    uint32_t groupPos = row / ROW_NUM_IN_A_GROUP;
    uint32_t rowPos = row % ROW_NUM_IN_A_GROUP;
    RowGroupHeader *group = reinterpret_cast<RowGroupHeader *>(mData + mHeader->groupOffset[groupPos]);
    CellUnit *cellUnit = reinterpret_cast<CellUnit *>(mData + group->rowOffsets[rowPos]) + column;
    uint32_t offset = mHeader->unusedOffset;
    uint32_t end = offset + size;
    if (UNLIKELY(end > mSize)) {
        return SHARED_BLOCK_NO_MEMORY;
    }
    mHeader->unusedOffset = end;

    if (size != 0) {
        errno_t result = memcpy_s(mData + offset, size, value, size);
        if (UNLIKELY(result != EOK)) {
            return SHARED_BLOCK_NO_MEMORY;
        }
    }

    cellUnit->type = type;
    cellUnit->cell.stringOrBlobValue.offset = offset;
    cellUnit->cell.stringOrBlobValue.size = size;
    return SHARED_BLOCK_OK;
}

int SharedBlock::PutLong(uint32_t row, uint32_t column, int64_t value)
{
    if (UNLIKELY(row >= mHeader->rowNums || column >= mHeader->columnNums)) {
        LOG_ERROR("Failed to read row %{public}" PRIu32 ", column %{public}" PRIu32 " from a SharedBlock"
            " which has %{public}" PRIu32 " rows, %{public}" PRIu32 " columns.",
                row, column, mHeader->rowNums, mHeader->columnNums);
        return SHARED_BLOCK_BAD_VALUE;
    }

    uint32_t groupPos = row / ROW_NUM_IN_A_GROUP;
    uint32_t rowPos = row % ROW_NUM_IN_A_GROUP;
    RowGroupHeader *group = reinterpret_cast<RowGroupHeader *>(mData + mHeader->groupOffset[groupPos]);
    CellUnit *cellUnit = reinterpret_cast<CellUnit *>(mData + group->rowOffsets[rowPos]) + column;
    cellUnit->type = CELL_UNIT_TYPE_INTEGER;
    cellUnit->cell.longValue = value;
    return SHARED_BLOCK_OK;
}

int SharedBlock::PutDouble(uint32_t row, uint32_t column, double value)
{
    if (UNLIKELY(row >= mHeader->rowNums || column >= mHeader->columnNums)) {
        LOG_ERROR("Failed to read row %{public}" PRIu32 ", column %{public}" PRIu32 " from a SharedBlock"
                  " which has %{public}" PRIu32 " rows, %{public}" PRIu32 " columns.",
            row, column, mHeader->rowNums, mHeader->columnNums);
        return SHARED_BLOCK_BAD_VALUE;
    }

    uint32_t groupPos = row / ROW_NUM_IN_A_GROUP;
    uint32_t rowPos = row % ROW_NUM_IN_A_GROUP;
    RowGroupHeader *group = reinterpret_cast<RowGroupHeader *>(mData + mHeader->groupOffset[groupPos]);
    CellUnit *cellUnit = reinterpret_cast<CellUnit *>(mData + group->rowOffsets[rowPos]) + column;
    cellUnit->type = CELL_UNIT_TYPE_FLOAT;
    cellUnit->cell.doubleValue = value;
    return SHARED_BLOCK_OK;
}

int SharedBlock::PutNull(uint32_t row, uint32_t column)
{
    if (UNLIKELY(row >= mHeader->rowNums || column >= mHeader->columnNums)) {
        LOG_ERROR("Failed to read row %{public}" PRIu32 ", column %{public}" PRIu32 " from a SharedBlock"
                  " which has %{public}" PRIu32 " rows, %{public}" PRIu32 " columns.",
            row, column, mHeader->rowNums, mHeader->columnNums);
        return SHARED_BLOCK_BAD_VALUE;
    }

    uint32_t groupPos = row / ROW_NUM_IN_A_GROUP;
    uint32_t rowPos = row % ROW_NUM_IN_A_GROUP;
    RowGroupHeader *group = reinterpret_cast<RowGroupHeader *>(mData + mHeader->groupOffset[groupPos]);
    CellUnit *cellUnit = reinterpret_cast<CellUnit *>(mData + group->rowOffsets[rowPos]) + column;

    cellUnit->type = CELL_UNIT_TYPE_NULL;
    cellUnit->cell.stringOrBlobValue.offset = 0;
    cellUnit->cell.stringOrBlobValue.size = 0;
    return SHARED_BLOCK_OK;
}

size_t SharedBlock::SetRawData(const void *rawData, size_t size)
{
    if (UNLIKELY(size <= 0)) {
        LOG_ERROR("SharedBlock rawData is less than or equal to 0M");
        return SHARED_BLOCK_INVALID_OPERATION;
    }
    if (UNLIKELY(size > mSize)) {
        LOG_ERROR("SharedBlock size is %{public}zu, current byteArray size is %{public}zu", mSize, size);
        return SHARED_BLOCK_NO_MEMORY;
    }

    int result = memcpy_s(mHeader, mSize, rawData, size);
    if (UNLIKELY(result != 0)) {
        return SHARED_BLOCK_NO_MEMORY;
    }
    return SHARED_BLOCK_OK;
}

std::string SharedBlock::CellUnit::GetString(SharedBlock *block) const
{
    auto value = static_cast<char*>(block->OffsetToPtr(cell.stringOrBlobValue.offset, cell.stringOrBlobValue.size));
    if (cell.stringOrBlobValue.size < 1 || value == nullptr) {
        return "";
    }
    return value;
}

std::vector<uint8_t> SharedBlock::CellUnit::GetBlob(SharedBlock* block) const
{
    auto value = reinterpret_cast<uint8_t*>(block->OffsetToPtr(cell.stringOrBlobValue.offset,
        cell.stringOrBlobValue.size));
    return std::vector<uint8_t>(value, value + cell.stringOrBlobValue.size);
}

const uint8_t* SharedBlock::CellUnit::GetRawData(SharedBlock* block) const
{
    return static_cast<uint8_t*>(block->OffsetToPtr(cell.stringOrBlobValue.offset, cell.stringOrBlobValue.size));
}
} // namespace AppDataFwk
} // namespace OHOS
