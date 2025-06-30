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
#include "abssharedresultset_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <string>
#include <vector>

#include "abs_shared_result_set.h"
#include "rdb_types.h"
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

namespace OHOS {
void FuzzGetString(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    std::string value;
    resultSet.GetString(columnIndex, value);
}

void FuzzGet(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    int32_t columnIndex = provider.ConsumeIntegral<int32_t>();
    ValueObject value;
    resultSet.Get(columnIndex, value);
}

void FuzzGetSize(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    size_t size;
    resultSet.GetSize(columnIndex, size);
}

void FuzzGetColumnType(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    ColumnType columnType;
    resultSet.GetColumnType(columnIndex, columnType);
}

void FuzzGoToRow(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    int position = provider.ConsumeIntegral<int>();
    resultSet.GoToRow(position);
}

void FuzzGetRowCount(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    int count;
    resultSet.GetRowCount(count);
}

void FuzzGetBlock(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    resultSet.GetBlock();
}

void FuzzOnGo(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    int oldRowIndex = provider.ConsumeIntegral<int>();
    int newRowIndex = provider.ConsumeIntegral<int>();
    resultSet.OnGo(oldRowIndex, newRowIndex);
}

void FuzzSetBlock(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    AppDataFwk::SharedBlock *block = nullptr;
    std::string sharedBlockName = "SharedBlockFuzzTestBlock";
    auto errcode = AppDataFwk::SharedBlock::Create(sharedBlockName, DEFAULT_BLOCK_SIZE, block);
    if (errcode != AppDataFwk::SharedBlock::SHARED_BLOCK_OK) {
        return;
    }
    resultSet.SetBlock(block);
}

void FuzzClose(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    resultSet.Close();
}

void FuzzHasBlock(FuzzedDataProvider &provider, AbsSharedResultSet &resultSet)
{
    resultSet.HasBlock();
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);

    // Create an instance of AbsSharedResultSet
    const int randomStringLength = 30;
    std::string tableName = provider.ConsumeRandomLengthString(randomStringLength);
    AbsSharedResultSet resultSet(tableName);

    // Fuzzing for GetString
    OHOS::FuzzGetString(provider, resultSet);

    // Fuzzing for Get
    OHOS::FuzzGet(provider, resultSet);

    // Fuzzing for GetSize
    OHOS::FuzzGetSize(provider, resultSet);

    // Fuzzing for GetColumnType
    OHOS::FuzzGetColumnType(provider, resultSet);

    // Fuzzing for GoToRow
    OHOS::FuzzGoToRow(provider, resultSet);

    // Fuzzing for GetRowCount
    OHOS::FuzzGetRowCount(provider, resultSet);

    // Fuzzing for GetBlock
    OHOS::FuzzGetBlock(provider, resultSet);

    // Fuzzing for OnGo
    OHOS::FuzzOnGo(provider, resultSet);

    // Fuzzing for SetBlock
    OHOS::FuzzSetBlock(provider, resultSet);

    // Fuzzing for Close
    OHOS::FuzzClose(provider, resultSet);

    // Fuzzing for HasBlock
    OHOS::FuzzHasBlock(provider, resultSet);

    return 0;
}
