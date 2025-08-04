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

#include "oh_cursor_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "oh_cursor.h"
#include "grd_api_manager.h"
#include "oh_value_object.h"
#include "rdb_errno.h"
#include "relational_store.h"
#include "relational_store_error_code.h"
#include "relational_store_impl.h"

#define COLUMN_INDEX_MIN 0
#define COLUMN_INDEX_MAX 10
static constexpr const char *RDB_TEST_PATH = "/data/storage/el2/database/com.ohos.example.distributedndk/entry/";

using namespace OHOS;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbNdk;

namespace OHOS {

OH_Cursor *GetOH_Cursor()
{
    OH_Rdb_Config config;
	config.dataBaseDir = RDB_TEST_PATH;
	config.storeName = "rdb_store_oh_cursor_fuzzer_test.db";
	config.bundleName = "com.ohos.example.distributedndk";
	config.moduleName = "";
	config.securityLevel = OH_Rdb_SecurityLevel::S1;
	config.isEncrypt = false;
	config.selfSize = sizeof(OH_Rdb_Config);
	config.area = RDB_SECURITY_AREA_EL1;
	int chmodValue = 0770;
    mkdir(config.dataBaseDir, chmodValue);
	
	int errCode = 0;
    char table[] = "test";
    static OH_Rdb_Store *ndkStore = OH_Rdb_GetOrOpen(&config, &errCode);

    char createTableSql[] = "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, "
                            "data3 FLOAT, data4 BLOB, data5 TEXT);";
    OH_Rdb_Execute(ndkStore, createTableSql);

    OH_VBucket *valueBucket = OH_Rdb_CreateValuesBucket();
    valueBucket->putInt64(valueBucket, "id", 1);
    valueBucket->putText(valueBucket, "data1", "zhangSan");
    // init row one data2 value 12800
    valueBucket->putInt64(valueBucket, "data2", 12800);
    // init row one data3 value 100.1
    valueBucket->putReal(valueBucket, "data3", 100.1);
    uint8_t arr[] = { 1, 2, 3, 4, 5 };
    int len = sizeof(arr) / sizeof(arr[0]);
    valueBucket->putBlob(valueBucket, "data4", arr, len);
    valueBucket->putText(valueBucket, "data5", "ABCDEFG");
    OH_Rdb_Insert(ndkStore, table, valueBucket);
	
    char querySql[] = "SELECT * FROM test";
    static OH_Cursor *cursor = OH_Rdb_ExecuteQuery(ndkStore, querySql);
    return cursor;
}


OH_ColumnType GetOH_ColumnType(FuzzedDataProvider &provider)
{
    int min = static_cast<int>(OH_ColumnType::TYPE_NULL);
    int max = static_cast<int>(OH_ColumnType::TYPE_UNLIMITED_INT);
    int enumInt = provider.ConsumeIntegralInRange<int>(min, max);
    OH_ColumnType type = static_cast<OH_ColumnType>(enumInt);
    return type;
}

void OH_Cursor_GetColumnCountFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int count = provider.ConsumeIntegral<int>();
    cursor->getColumnCount(cursor, &count);
}

void OH_Cursor_GetColumnTypeFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    OH_ColumnType columnType = GetOH_ColumnType(provider);
    cursor->getColumnType(cursor, columnIndex, &columnType);
}

void OH_Cursor_GetColumnIndexFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    std::string name = provider.ConsumeRandomLengthString();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    cursor->getColumnIndex(cursor, name.c_str(), &columnIndex);
}

void OH_Cursor_GetColumnNameFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    char name[10];
    const int length = 10;
    cursor->getColumnName(cursor, columnIndex, name, length);
}

void OH_Cursor_GetRowCountFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int count = provider.ConsumeIntegral<int>();
    cursor->getRowCount(cursor, &count);
}

void OH_Cursor_GoToNextRowFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    cursor->goToNextRow(cursor);
}

void OH_Cursor_GetSizeFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    size_t size = provider.ConsumeIntegral<size_t>();
    cursor->getSize(cursor, columnIndex, &size);
}

void OH_Cursor_GetTextFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    char value = provider.ConsumeIntegral<char>();
    int length = provider.ConsumeIntegral<int>();
    cursor->getText(cursor, columnIndex, &value, length);
}

void OH_Cursor_GetInt64Fuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    int64_t value = provider.ConsumeIntegral<int64_t>();
    cursor->getInt64(cursor, columnIndex, &value);
}

void OH_Cursor_GetRealFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    double value = provider.ConsumeFloatingPoint<double>();
    cursor->getReal(cursor, columnIndex, &value);
}

void OH_Cursor_GetBlobFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    unsigned char value = provider.ConsumeIntegral<unsigned char>();
    int length = provider.ConsumeIntegral<int>();
    cursor->getBlob(cursor, columnIndex, &value, length);
}

void OH_Cursor_IsNullFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    bool isNull = provider.ConsumeBool();
    cursor->isNull(cursor, columnIndex, &isNull);
}

void OH_Cursor_GetAssetFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    cursor->getAsset(cursor, columnIndex, asset);
}

void OH_Cursor_GetAssetsFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    Data_Asset *asset = OH_Data_Asset_CreateOne();
    if (asset == nullptr) {
        return;
    }
    uint32_t length = provider.ConsumeIntegral<uint32_t>();
    cursor->getAssets(cursor, columnIndex, &asset, &length);
}

void OH_Cursor_GetAssetsCountFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    uint32_t count = provider.ConsumeIntegral<uint32_t>();
    cursor->getAssetsCount(cursor, columnIndex, &count);
}

void OH_Cursor_GetFloatVectorCountFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    size_t length = provider.ConsumeIntegral<size_t>();
    OH_Cursor_GetFloatVectorCount(cursor, columnIndex, &length);
}

void OH_Cursor_GetFloatVectorFuzz(FuzzedDataProvider &provider)
{
    OH_Cursor *cursor = GetOH_Cursor();
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(COLUMN_INDEX_MIN, COLUMN_INDEX_MAX);
    float val = provider.ConsumeFloatingPoint<float>();
    size_t inLen = provider.ConsumeIntegral<size_t>();
    size_t outLen = provider.ConsumeIntegral<size_t>();
    OH_Cursor_GetFloatVector(cursor, columnIndex, &val, inLen, &outLen);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Run your code on data
    FuzzedDataProvider provider(data, size);
    OHOS::OH_Cursor_GetColumnCountFuzz(provider);
    OHOS::OH_Cursor_GetColumnTypeFuzz(provider);
    OHOS::OH_Cursor_GetColumnIndexFuzz(provider);
    OHOS::OH_Cursor_GetColumnNameFuzz(provider);
    OHOS::OH_Cursor_GetRowCountFuzz(provider);
    OHOS::OH_Cursor_GoToNextRowFuzz(provider);
    OHOS::OH_Cursor_GetSizeFuzz(provider);
    OHOS::OH_Cursor_GetTextFuzz(provider);
    OHOS::OH_Cursor_GetInt64Fuzz(provider);
    OHOS::OH_Cursor_GetRealFuzz(provider);
    OHOS::OH_Cursor_GetBlobFuzz(provider);
    OHOS::OH_Cursor_IsNullFuzz(provider);
    OHOS::OH_Cursor_GetAssetFuzz(provider);
    OHOS::OH_Cursor_GetAssetsFuzz(provider);
    OHOS::OH_Cursor_GetAssetsCountFuzz(provider);
    OHOS::OH_Cursor_GetFloatVectorCountFuzz(provider);
    OHOS::OH_Cursor_GetFloatVectorFuzz(provider);
    return 0;
}
