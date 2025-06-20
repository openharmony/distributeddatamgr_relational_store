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
#include "cache_result_set_test_ut2fuzz.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <rdb_helper.h>
#include <rdb_store.h>
#include <rdb_store_config.h>
#include <securec.h>
#include <values_bucket.h>

#include <map>
#include <memory>
#include <string>

#include "big_integer.h"
#include "cache_result_set.h"
#include "connection_pool.h"
#include "rdb_errno.h"
#include "trans_db.h"
#include "value_object.h"

using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace OHOS {

void CreateValuesBuckets(FuzzedDataProvider &fdp, std::vector<ValuesBucket> &valuesBuckets)
{
    ValuesBucket valuesBucket;
    {
        std::string columnName = fdp.ConsumeRandomLengthString();
        std::string columnValue = fdp.ConsumeRandomLengthString();
        valuesBucket.PutString(columnName, columnValue);
    }
    {
        std::string columnName = fdp.ConsumeRandomLengthString();
        valuesBucket.PutInt(columnName, fdp.ConsumeIntegral<int>());
    }
    {
        std::string columnName = fdp.ConsumeRandomLengthString();
        valuesBucket.PutLong(columnName, fdp.ConsumeIntegral<int64_t>());
    }
    {
        std::string columnName = fdp.ConsumeRandomLengthString();
        double value = fdp.ConsumeFloatingPoint<float>();
        valuesBucket.PutDouble(columnName, value);
    }
    {
        uint32_t status = fdp.ConsumeIntegralInRange<uint32_t>(
            AssetValue::Status::STATUS_UNKNOWN, AssetValue::Status::STATUS_BUTT);
        AssetValue asset{
            .version = fdp.ConsumeIntegral<uint32_t>(),
            .status = status,
            .expiresTime = fdp.ConsumeIntegral<uint64_t>(),
            .id = fdp.ConsumeRandomLengthString(),
            .name = fdp.ConsumeRandomLengthString(),
            .uri = fdp.ConsumeRandomLengthString(),
            .createTime = fdp.ConsumeRandomLengthString(),
            .modifyTime = fdp.ConsumeRandomLengthString(),
            .size = fdp.ConsumeRandomLengthString(),
            .hash = fdp.ConsumeRandomLengthString(),
            .path = fdp.ConsumeRandomLengthString(),
        };
        ValueObject valueObject = ValueObject(asset);
        ValueObject::Asset value = ValueObject::Asset(valueObject);
        std::string columnName = fdp.ConsumeRandomLengthString();
        valuesBucket.Put(columnName, value);
    }
    valuesBuckets.push_back(std::move(valuesBucket));
}

void CacheResultSetTestGetRowCountTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    int count = fdp.ConsumeIntegral<int>();
    cacheResultSet.GetRowCount(count);
}

void CacheResultSetTestGetAllColumnNamesTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    std::vector<std::string> columnNamesTmp = {};
    cacheResultSet.GetAllColumnNames(columnNamesTmp);
}

void CacheResultSetTestGetStringTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    int columnIndex = fdp.ConsumeIntegral<int>();
    std::string value;
    cacheResultSet.GetString(columnIndex, value);
}

void CacheResultSetTestGetIntTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    int columnIndex = fdp.ConsumeIntegral<int>();
    int value = 0;
    cacheResultSet.GetInt(columnIndex, value);
}

void CacheResultSetTestGetLongTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    int columnIndex = fdp.ConsumeIntegral<int>();
    int64_t value = 0;
    cacheResultSet.GetLong(columnIndex, value);
}

void CacheResultSetTestGetDoubleTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    int columnIndex = fdp.ConsumeIntegral<int>();
    double value = 0;
    cacheResultSet.GetDouble(columnIndex, value);
}

void CacheResultSetTestGetAssetTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    int32_t columnIndex = fdp.ConsumeIntegral<int32_t>();
    ValueObject::Asset valueOut = {};
    cacheResultSet.GetAsset(columnIndex, valueOut);
}

void CacheResultSetTestGetTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    int32_t columnIndex = fdp.ConsumeIntegral<int32_t>();
    ValueObject value;
    cacheResultSet.Get(columnIndex, value);
    int res = 0;
    value.GetInt(res);
}

void CacheResultSetTestIsColumnNullTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int32_t columnIndex = fdp.ConsumeIntegral<int32_t>();
    bool isNull = fdp.ConsumeBool();
    cacheResultSet.IsColumnNull(columnIndex, isNull);
}

void CacheResultSetTestGetRowTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    RowEntity rowEntity;
    cacheResultSet.GetRow(rowEntity);
}

void CacheResultSetTestGoToRowTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int32_t columnIndex = fdp.ConsumeIntegral<int32_t>();
    cacheResultSet.GoToRow(columnIndex);
}

void CacheResultSetTestGetColumnTypeTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int32_t columnIndex = fdp.ConsumeIntegral<int32_t>();
    ColumnType columnType = ColumnType::TYPE_INTEGER;
    cacheResultSet.GetColumnType(columnIndex, columnType);
}

void CacheResultSetTestGetRowIndexTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int32_t columnIndex = fdp.ConsumeIntegral<int32_t>();
    cacheResultSet.GetRowIndex(columnIndex);
}

void CacheResultSetTestGoToTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int32_t offset = fdp.ConsumeIntegral<int32_t>();
    cacheResultSet.GoTo(offset);
    std::string value;
    cacheResultSet.GetString(fdp.ConsumeIntegral<int32_t>(), value);
    cacheResultSet.GoToRow(fdp.ConsumeIntegral<int32_t>());
    cacheResultSet.GetString(fdp.ConsumeIntegral<int32_t>(), value);
    cacheResultSet.GoTo(fdp.ConsumeIntegral<int32_t>());
}

void CacheResultSetTestGoToFirstRowTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    cacheResultSet.GoToFirstRow();
    int position = fdp.ConsumeIntegral<int32_t>();
    cacheResultSet.GetRowIndex(position);
}

void CacheResultSetTestGoToLastRowTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    cacheResultSet.GoToLastRow();
    int position = fdp.ConsumeIntegral<int32_t>();
    cacheResultSet.GetRowIndex(position);
}

void CacheResultSetTestGoToNextRowTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));
    cacheResultSet.GoToNextRow();
    int position = fdp.ConsumeIntegral<int32_t>();
    cacheResultSet.GetRowIndex(position);
}

void CacheResultSetTestGoToPreviousRowTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int offset = fdp.ConsumeIntegral<int32_t>();
    int position = fdp.ConsumeIntegral<int32_t>();
    cacheResultSet.GoToRow(position);
    cacheResultSet.GoTo(offset);
    cacheResultSet.GoToPreviousRow();
}

void CacheResultSetTestIsAtFirstRowTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    bool result = fdp.ConsumeBool();
    cacheResultSet.IsAtFirstRow(result);
    cacheResultSet.GoToNextRow();
    cacheResultSet.IsAtLastRow(result);
}

void CacheResultSetTestIsAtLastRowTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    bool result = fdp.ConsumeBool();
    cacheResultSet.IsAtLastRow(result);
    cacheResultSet.GoToNextRow();
    cacheResultSet.IsAtLastRow(result);
}

void CacheResultSetTestIsStartedTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    bool result = fdp.ConsumeBool();
    cacheResultSet.IsStarted(result);
}

void CacheResultSetTestIsEndedTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    bool result = fdp.ConsumeBool();
    cacheResultSet.IsEnded(result);
}

void CacheResultSetTestGetColumnCountTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int count = fdp.ConsumeIntegral<int32_t>();
    cacheResultSet.GetColumnCount(count);
}

void CacheResultSetTestGetColumnIndexTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    std::string columnName = fdp.ConsumeRandomLengthString();
    int columnIndex = 0;
    cacheResultSet.GetColumnIndex(columnName, columnIndex);
}

void CacheResultSetTestGetColumnNameTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    std::string columnName;
    const int index = 0;
    cacheResultSet.GetColumnName(index, columnName);
}

void CacheResultSetTestGetSizeTest001(FuzzedDataProvider &fdp)
{
    std::vector<ValuesBucket> valuesBuckets;
    CreateValuesBuckets(fdp, valuesBuckets);
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int32_t columnIndex = fdp.ConsumeIntegral<int32_t>();
    size_t size = 0;
    cacheResultSet.GetSize(columnIndex, size);
}


} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::CacheResultSetTestGetRowCountTest001(fdp);
    OHOS::CacheResultSetTestGetAllColumnNamesTest001(fdp);
    OHOS::CacheResultSetTestGetStringTest001(fdp);
    OHOS::CacheResultSetTestGetIntTest001(fdp);
    OHOS::CacheResultSetTestGetLongTest001(fdp);
    OHOS::CacheResultSetTestGetDoubleTest001(fdp);
    OHOS::CacheResultSetTestGetAssetTest001(fdp);
    OHOS::CacheResultSetTestGetTest001(fdp);
    OHOS::CacheResultSetTestIsColumnNullTest001(fdp);
    OHOS::CacheResultSetTestGetRowTest001(fdp);
    OHOS::CacheResultSetTestGetColumnTypeTest001(fdp);
    OHOS::CacheResultSetTestGetRowIndexTest001(fdp);
    OHOS::CacheResultSetTestGoToTest001(fdp);
    OHOS::CacheResultSetTestGoToFirstRowTest001(fdp);
    OHOS::CacheResultSetTestGoToLastRowTest001(fdp);
    OHOS::CacheResultSetTestGoToNextRowTest001(fdp);
    OHOS::CacheResultSetTestGoToPreviousRowTest001(fdp);
    OHOS::CacheResultSetTestIsAtFirstRowTest001(fdp);
    OHOS::CacheResultSetTestIsAtLastRowTest001(fdp);
    OHOS::CacheResultSetTestIsStartedTest001(fdp);
    OHOS::CacheResultSetTestIsEndedTest001(fdp);
    OHOS::CacheResultSetTestGetColumnCountTest001(fdp);
    OHOS::CacheResultSetTestGetColumnIndexTest001(fdp);
    OHOS::CacheResultSetTestGetColumnNameTest001(fdp);
    OHOS::CacheResultSetTestGetSizeTest001(fdp);
    return 0;
}
