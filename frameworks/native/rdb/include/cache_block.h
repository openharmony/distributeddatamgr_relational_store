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

#ifndef NATIVE_RDB_CACHE_BLOCK_H
#define NATIVE_RDB_CACHE_BLOCK_H

#include <cinttypes>
#include <cstdint>
#include <vector>

#include "abs_shared_block.h"
#include "rdb_visibility.h"
namespace OHOS {
namespace NativeRdb {
class ValuesBucket;
}
namespace AppDataFwk {
class CacheBlock : public AbsSharedBlock {
public:
    CacheBlock(int32_t maxCount, const std::vector<std::string> &columns);
    ~CacheBlock() override;
    int Clear() override;
    int SetColumnNum(uint32_t numColumns) override;
    int AllocRow() override;
    int FreeLastRow() override;
    int PutBlob(uint32_t row, uint32_t column, const void *value, size_t Size) override;
    int PutString(uint32_t row, uint32_t column, const char *value, size_t sizeIncludingNull) override;
    int PutLong(uint32_t row, uint32_t column, int64_t value) override;
    int PutDouble(uint32_t row, uint32_t column, double value) override;
    int PutAsset(uint32_t row, uint32_t column, const void *value, size_t size) override;
    int PutAssets(uint32_t row, uint32_t column, const void *value, size_t size) override;
    int PutFloats(uint32_t row, uint32_t column, const void *value, size_t size) override;
    int PutBigInt(uint32_t row, uint32_t column, const void *value, size_t size) override;
    int PutNull(uint32_t row, uint32_t column) override;
    bool HasException();
    std::vector<NativeRdb::ValuesBucket> StealRows();
private:
    std::vector<NativeRdb::ValuesBucket> rows_;
    const std::vector<std::string> columns_;
    const int32_t maxCount_;
    bool isFull_ = false;
    bool hasException_ = false;
};
} // namespace AppDataFwk
} // namespace OHOS
#endif
