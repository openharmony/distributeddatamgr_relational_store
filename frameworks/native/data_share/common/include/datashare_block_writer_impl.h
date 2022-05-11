/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DATASHARE_BLOCK_WRITER_IMPL_H
#define DATASHARE_BLOCK_WRITER_IMPL_H

#include <string>
#include "shared_block.h"
#include "datashare_block_writer.h"

namespace OHOS {
namespace DataShare {
/**
 * This class stores a set of rows from a database in a buffer，
 * which is used as the set of query result.
 */
class DataShareBlockWriterImpl : public virtual DataShareBlockWriter {
public:
    /**
     * SharedBlock constructor.
     */
    DataShareBlockWriterImpl();

    /**
     * SharedBlock constructor.
     */
    DataShareBlockWriterImpl(const std::string &name, size_t size);

    /**
     * SharedBlock Deconstruction.
     */
    ~DataShareBlockWriterImpl();

    /**
     * Clear current shared block.
     */
    int Clear() override;

    /**
     * Set a shared block column.
     */
    int SetColumnNum(uint32_t numColumns) override;

    /**
     * Allocate a row unit and its directory.
     */
    int AllocRow() override;

    /**
     * Release the value of the last row.
     */
    int FreeLastRow() override;

    /**
     * Write blob data to the shared block.
     */
    int WriteBlob(uint32_t row, uint32_t column, const void *value, size_t Size) override;

    /**
     * Write string data to the shared block.
     */
    int WriteString(uint32_t row, uint32_t column, const char *value, size_t sizeIncludingNull) override;

    /**
     * Write long data to the shared block.
     */
    int WriteLong(uint32_t row, uint32_t column, int64_t value) override;

    /**
     * Write Double data to the shared block.
     */
    int WriteDouble(uint32_t row, uint32_t column, double value) override;

    /**
     * Write Null data to the shared block.
     */
    int WriteNull(uint32_t row, uint32_t column) override;

    /**
     * The mHeader of the current result set.
     */
    const void *GetHeader();

    /**
     * Size of the used byte in the block.
     */
    size_t GetUsedBytes() override;

    /**
     * The name of the current result set.
     */
    std::string Name() override;

    /**
     * The size of the current result set.
     */
    size_t Size() override;

    /**
     * The row number of the current result set.
     */
    uint32_t GetRowNum() override;

    /**
     * The column number of the current result set.
     */
    uint32_t GetColumnNum() override;

    /**
     * Write raw data in block.
     */
    size_t SetRawData(const void *rawData, size_t size) override;

    /**
     * The fd of shared memory
     */
    int GetFd();

    /**
     * Get Block
     */
    AppDataFwk::SharedBlock *GetBlock() const;

private:
    AppDataFwk::SharedBlock *shareBlock_;
};
} // namespace DataShare
} // namespace OHOS
#endif
