/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ABS_SHARED_BLOCK_H
#define ABS_SHARED_BLOCK_H
#include <cinttypes>
#include <cstddef>

#include "rdb_visibility.h"
namespace OHOS {
namespace AppDataFwk {
class API_EXPORT AbsSharedBlock {
public:
    enum {
        BLOCK_OK = 0,
        BLOCK_BAD_VALUE = 1,
    };
    virtual ~AbsSharedBlock() = default;
    virtual int Clear() = 0;
    virtual int SetColumnNum(uint32_t numColumns) = 0;
    virtual int AllocRow() = 0;
    virtual int FreeLastRow() = 0;
    virtual int PutBlob(uint32_t row, uint32_t column, const void *value, size_t Size) = 0;
    virtual int PutString(uint32_t row, uint32_t column, const char *value, size_t sizeIncludingNull) = 0;
    virtual int PutLong(uint32_t row, uint32_t column, int64_t value) = 0;
    virtual int PutDouble(uint32_t row, uint32_t column, double value) = 0;
    virtual int PutAsset(uint32_t row, uint32_t column, const void *value, size_t size) = 0;
    virtual int PutAssets(uint32_t row, uint32_t column, const void *value, size_t size) = 0;
    virtual int PutFloats(uint32_t row, uint32_t column, const void *value, size_t size) = 0;
    virtual int PutBigInt(uint32_t row, uint32_t column, const void *value, size_t size) = 0;
    virtual int PutNull(uint32_t row, uint32_t column) = 0;
};
} // namespace AppDataFwk
} // namespace OHOS
#endif
