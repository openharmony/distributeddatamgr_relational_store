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

#ifndef SHARED_BLOCK_H
#define SHARED_BLOCK_H

#include <cinttypes>

#include <string>
#include <ashmem.h>
#include "message_parcel.h"
#include "parcel.h"
#include "securec.h"
#include "rdb_visibility.h"

namespace OHOS {
namespace AppDataFwk {
/**
 * @brief The constant indicates the error is due to an invalid row record.
 */
static const uint32_t INVALID_ROW_RECORD = 0xFFFFFFFF;
/**
 * This class stores a set of rows from a database in a buffer,
 * which is used as the set of query result.
 */
class RDB_API_EXPORT SharedBlock {
public:
    /**
     * @brief Cell Unit types.
     */
    enum {
        /** Indicates the Cell Unit data type is NULL at the specified row and column.*/
        CELL_UNIT_TYPE_NULL = 0,
        /** Indicates the current Cell Unit data type is INT at the specified row and column.*/
        CELL_UNIT_TYPE_INTEGER = 1,
        /** Indicates the current Cell Unit data type is FLOAT at the specified row and column.*/
        CELL_UNIT_TYPE_FLOAT = 2,
        /** Indicates the current Cell Unit data type is STRING at the specified row and column.*/
        CELL_UNIT_TYPE_STRING = 3,
        /** Indicates the current Cell Unit data type is BLOB at the specified row and column.*/
        CELL_UNIT_TYPE_BLOB = 4,
    };

    /**
     * @brief SharedBlock error types.
     */
    enum {
        /** Indicates that the operation on SHARED BLOCK was successful.*/
        SHARED_BLOCK_OK = 0,
        /** Indicates that the result returned by the shared block operation is a bad value.*/
        SHARED_BLOCK_BAD_VALUE = 1,
        /** Indicates the current shared block space is not enough.*/
        SHARED_BLOCK_NO_MEMORY = 2,
        /** Indicates that the current operation on SHARED BLOCK is invalid.*/
        SHARED_BLOCK_INVALID_OPERATION = 3,
        /** Indicates that an ashmem error occurred in the operation of shared memory.*/
        SHARED_BLOCK_ASHMEM_ERROR = 4,
        /** Indicates that the set port error occurred in the operation of shared memory.*/
        SHARED_BLOCK_SET_PORT_ERROR = 5,
    };

    /**
     * Cell Unit
     * */
    struct CellUnit {
        int32_t type;
        union {
            double doubleValue;
            int64_t longValue;
            struct {
                uint32_t offset;
                uint32_t size;
            } stringOrBlobValue;
        } cell;
    } __attribute((packed));

    /**
     * @brief Constructor.
     */
    RDB_API_EXPORT SharedBlock(const std::string &name, sptr<Ashmem> ashmem, size_t size, bool readOnly);

    /**
     * @brief Destructor.
     */
    RDB_API_EXPORT ~SharedBlock();

    /**
     * @brief Init current shared block.
     */
    RDB_API_EXPORT bool Init();

    /**
     * @brief Create a shared block.
     */
    RDB_API_EXPORT static int Create(const std::string &name, size_t size, SharedBlock *&outSharedBlock);

    /**
     * @brief Clear current shared block.
     */
    RDB_API_EXPORT int Clear();

    /**
     * @brief Set a shared block column.
     */
    RDB_API_EXPORT int SetColumnNum(uint32_t numColumns);

    /**
     * @brief Allocate a row unit and its directory.
     */
    RDB_API_EXPORT int AllocRow();

    /**
     * @brief Release the value of the last row.
     */
    RDB_API_EXPORT int FreeLastRow();

    /**
     * @brief Put blob data to the shared block.
     */
    RDB_API_EXPORT int PutBlob(uint32_t row, uint32_t column, const void *value, size_t Size);

    /**
     * @brief Put string data to the shared block.
     */
    RDB_API_EXPORT int PutString(uint32_t row, uint32_t column, const char *value, size_t sizeIncludingNull);

    /**
     * @brief Put long data to the shared block.
     */
    RDB_API_EXPORT int PutLong(uint32_t row, uint32_t column, int64_t value);

    /**
     * @brief Put Double data to the shared block.
     */
    RDB_API_EXPORT int PutDouble(uint32_t row, uint32_t column, double value);

    /**
     * @brief Put Null data to the shared block.
     */
    RDB_API_EXPORT int PutNull(uint32_t row, uint32_t column);

    /**
     * @brief Obtains the cell unit at the specified row and column.
     */
    RDB_API_EXPORT CellUnit *GetCellUnit(uint32_t row, uint32_t column);

    /**
     * @brief Obtains string type data from cell unit.
     */
    RDB_API_EXPORT const char *GetCellUnitValueString(CellUnit *cellUnit, size_t *outSizeIncludingNull)
    {
        *outSizeIncludingNull = cellUnit->cell.stringOrBlobValue.size;
        return static_cast<char *>(
            OffsetToPtr(cellUnit->cell.stringOrBlobValue.offset, cellUnit->cell.stringOrBlobValue.size));
    }

    /**
     * @brief Obtains blob type data from cell unit.
     */
    RDB_API_EXPORT const void *GetCellUnitValueBlob(CellUnit *cellUnit, size_t *outSize)
    {
        *outSize = cellUnit->cell.stringOrBlobValue.size;
        return OffsetToPtr(cellUnit->cell.stringOrBlobValue.offset, cellUnit->cell.stringOrBlobValue.size);
    }

    /**
     * @brief Obtains the mHeader of the current result set.
     */
    RDB_API_EXPORT const void *GetHeader()
    {
        return mHeader;
    }

    /**
     * @brief Obtains size of the used byte in the block.
     */
    RDB_API_EXPORT size_t GetUsedBytes()
    {
        return mHeader->unusedOffset;
    }

    /**
     * @brief Obtains the name of the current result set.
     */
    RDB_API_EXPORT std::string Name()
    {
        return mName;
    }

    /**
     * @brief Obtains the size of the current result set.
     */
    RDB_API_EXPORT size_t Size()
    {
        return mSize;
    }

    /**
     * @brief Obtains the row number of the current result set.
     */
    RDB_API_EXPORT uint32_t GetRowNum()
    {
        return mHeader->rowNums;
    }

    /**
     * @brief Obtains the column number of the current result set.
     */
    RDB_API_EXPORT uint32_t GetColumnNum()
    {
        return mHeader->columnNums;
    }

    /**
     * @brief Write message to parcel.
     */
    RDB_API_EXPORT int WriteMessageParcel(MessageParcel &parcel);

    /**
     * @brief Read message to parcel.
     */
    RDB_API_EXPORT static int ReadMessageParcel(MessageParcel &parcel, SharedBlock *&block);

    /**
     * @brief Write raw data in block.
     */
    RDB_API_EXPORT size_t SetRawData(const void *rawData, size_t size);

    /**
     * @brief Obtains the fd of shared memory
     */
    RDB_API_EXPORT int GetFd()
    {
        if (ashmem_ == nullptr) {
            return -1;
        }
        return ashmem_->GetAshmemFd();
    }

    /**
     * @brief Obtains the start position of the current result set.
     */
    RDB_API_EXPORT uint32_t GetStartPos()
    {
        return mHeader->startPos_;
    }

    /**
     * @brief Obtains the last position of the current result set.
     */
    RDB_API_EXPORT uint32_t GetLastPos()
    {
        return mHeader->lastPos_;
    }

    /**
     * @brief Obtains the block position of the current result set.
     */
    RDB_API_EXPORT uint32_t GetBlockPos()
    {
        return mHeader->blockPos_;
    }

    /**
     * @brief Set the start position of the current result set.
     */
    RDB_API_EXPORT void SetStartPos(uint32_t startPos)
    {
        mHeader->startPos_ = startPos;
    }

    /**
     * @brief Set the last position of the current result set.
     */
    RDB_API_EXPORT void SetLastPos(uint32_t lastPos)
    {
        mHeader->lastPos_ = lastPos;
    }

    /**
     * @brief Set the block position of the current result set.
     */
    RDB_API_EXPORT void SetBlockPos(uint32_t blockPos)
    {
        mHeader->blockPos_ = blockPos;
    }

private:
    std::string mName;
    sptr<Ashmem> ashmem_;
    void *mData;
    size_t mSize;
    bool mReadOnly;
    static const size_t ROW_OFFSETS_NUM = 100;
    /**
    * Default setting for SQLITE_MAX_COLUMN is 2000.
    * We can set it at compile time to as large as 32767
    */
    static const size_t COL_MAX_NUM = 32767;

    struct SharedBlockHeader {
        /* Offset of the lowest unused byte in the block. */
        uint32_t unusedOffset;
        /* Offset of the first row group. */
        uint32_t firstRowGroupOffset;
        /* Row numbers of the row group block. */
        uint32_t rowNums;
        /* Column numbers of the row group block. */
        uint32_t columnNums;
        /* start position of the current block. */
        uint32_t startPos_;
        /* last position of the current block. */
        uint32_t lastPos_;
        /* current position of the current block. */
        uint32_t blockPos_;
    };

    struct RowGroupHeader {
        uint32_t rowOffsets[ROW_OFFSETS_NUM];
        uint32_t nextGroupOffset;
    };

    SharedBlockHeader *mHeader;

    /**
     * Allocate a portion of the block. Returns the offset of the allocation.
     * Returns 0 if there isn't enough space.
     */
    uint32_t Alloc(size_t size, bool aligned = false);

    uint32_t *GetRowOffset(uint32_t row);

    uint32_t *AllocRowOffset();

    int PutBlobOrString(uint32_t row, uint32_t column, const void *value, size_t size, int32_t type);

    static int CreateSharedBlock(const std::string &name, size_t size, sptr<Ashmem> ashmem,
        SharedBlock *&outSharedBlock);

    uint32_t OffsetFromPtr(void *ptr);

    void *OffsetToPtr(uint32_t offset, uint32_t bufferSize = 0);

    /**
     * Convert utf8 string to utf16.
     */
    static std::u16string ToUtf16(std::string str);

    /**
     * Convert utf16 string to utf8.
     */
    static std::string ToUtf8(std::u16string str16);
};
} // namespace AppDataFwk
} // namespace OHOS
#endif
