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

#ifndef DATASHARE_BLOCK_WRITER_H
#define DATASHARE_BLOCK_WRITER_H

#include <string>

namespace OHOS {
namespace DataShare {
/**
 * This class provides methods for writing DatasShare shared block.
 */
class DataShareBlockWriter {
public:
    /**
     * Allocate a row unit and its directory.
     */
    virtual int AllocRow() = 0;

    /**
     * Write blob data to the shared block.
     */
    virtual int WriteBlob(uint32_t row, uint32_t column, const void *value, size_t Size) = 0;

    /**
     * Write string data to the shared block.
     */
    virtual int WriteString(uint32_t row, uint32_t column, const char *value, size_t sizeIncludingNull) = 0;

    /**
     * Write long data to the shared block.
     */
    virtual int WriteLong(uint32_t row, uint32_t column, int64_t value) = 0;

    /**
     * Write Double data to the shared block.
     */
    virtual int WriteDouble(uint32_t row, uint32_t column, double value) = 0;

    /**
     * Write Null data to the shared block.
     */
    virtual int WriteNull(uint32_t row, uint32_t column) = 0;
};
} // namespace DataShare
} // namespace OHOS
#endif
