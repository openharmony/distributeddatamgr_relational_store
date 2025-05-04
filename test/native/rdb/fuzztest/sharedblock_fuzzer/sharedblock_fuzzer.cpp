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
#include "sharedblock_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "ashmem.h"
#include "rd_statement.h"
#include "rdb_errno.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
#include "refbase.h"
#include "shared_block.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
static const size_t DEFAULT_BLOCK_SIZE = 1 * 1024 * 1024;
static const int MIN_BLOB_SIZE = 1;
static const int MAX_BLOB_SIZE = 200;
namespace OHOS {

void SharedBlockPutFuzz(std::shared_ptr<AppDataFwk::SharedBlock> sharedBlock, FuzzedDataProvider &provider)
{
    {
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        int64_t value = provider.ConsumeIntegral<int64_t>();
        sharedBlock->PutLong(row, column, value);
    }

    {
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        double value = provider.ConsumeFloatingPoint<double>();
        sharedBlock->PutDouble(row, column, value);
    }

    {
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        size_t size = provider.ConsumeIntegralInRange<size_t>(MIN_BLOB_SIZE, MAX_BLOB_SIZE);
        std::vector<uint8_t> value = provider.ConsumeBytes<uint8_t>(size);
        sharedBlock->PutAsset(row, column, value.data(), value.size());
    }

    {
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        size_t size = provider.ConsumeIntegralInRange<size_t>(MIN_BLOB_SIZE, MAX_BLOB_SIZE);
        std::vector<uint8_t> value = provider.ConsumeBytes<uint8_t>(size);
        sharedBlock->PutAssets(row, column, value.data(), value.size());
    }

    {
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        float item = provider.ConsumeFloatingPoint<float>();
        std::vector<float> value;
        value.push_back(item);
        sharedBlock->PutFloats(row, column, value.data(), value.size());
    }

    {
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        int value = provider.ConsumeIntegral<int>();
        ValueObject bigIntItem(value);
        std::vector<ValueObject> bigIntList;
        bigIntList.push_back(bigIntItem);
        sharedBlock->PutBigInt(row, column, bigIntList.data(), bigIntList.size());
    }
}

void SharedBlockFuzz(FuzzedDataProvider &provider)
{
    AppDataFwk::SharedBlock *block = nullptr;
    std::string sharedBlockName = "SharedBlockFuzzTestBlock";
    auto errcode = AppDataFwk::SharedBlock::Create(sharedBlockName, DEFAULT_BLOCK_SIZE, block);
    if (errcode != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        return;
    }
    std::shared_ptr<AppDataFwk::SharedBlock> sharedBlock = std::shared_ptr<AppDataFwk::SharedBlock>(block);

    // Prepare a dummy CellUnit
    AppDataFwk::SharedBlock::CellUnit cellUnit;
    cellUnit.type = provider.ConsumeIntegral<int32_t>(); // Arbitrary type
    cellUnit.cell.stringOrBlobValue.offset = provider.ConsumeIntegral<uint32_t>();
    cellUnit.cell.stringOrBlobValue.size = provider.ConsumeIntegral<uint32_t>();

    uint32_t numColumns = provider.ConsumeIntegral<int32_t>();
    sharedBlock->SetColumnNum(numColumns);
    sharedBlock->AllocRow();
    sharedBlock->FreeLastRow();

    {
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        size_t blobSize = provider.ConsumeIntegralInRange<size_t>(MIN_BLOB_SIZE, MAX_BLOB_SIZE);
        std::vector<uint8_t> blobData = provider.ConsumeBytes<uint8_t>(blobSize);
        sharedBlock->PutBlob(row, column, blobData.data(), blobData.size());
    }

    {
        size_t outSizeIncludingNull = 0;
        sharedBlock->GetCellUnitValueString(&cellUnit, &outSizeIncludingNull);
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        std::string value = provider.ConsumeRandomLengthString();
        size_t sizeIncludingNull = provider.ConsumeIntegral<size_t>();
        sharedBlock->PutString(row, column, value.c_str(), sizeIncludingNull);
    }
    SharedBlockPutFuzz(sharedBlock, provider);
    {
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        sharedBlock->PutNull(row, column);
    }

    {
        uint32_t row = provider.ConsumeIntegral<int32_t>();
        uint32_t column = provider.ConsumeIntegral<int32_t>();
        sharedBlock->GetCellUnit(row, column);
    }
    // Fuzz GetUsedBytes
    sharedBlock->GetUsedBytes();

    // Fuzz GetCellUnitValueBlob
    size_t blobSize = 0;
    sharedBlock->GetCellUnitValueBlob(&cellUnit, &blobSize);

    // Fuzz Size
    sharedBlock->Size();

    // Fuzz SetRawData
    std::vector<uint8_t> remaining_data = provider.ConsumeRemainingBytes<uint8_t>();
    sharedBlock->SetRawData(remaining_data.data(), remaining_data.size());
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::SharedBlockFuzz(provider);
    return 0;
}
