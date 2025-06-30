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
#include "absresultset_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <climits>
#include <string>
#include <vector>
#include "abs_result_set.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

// Define constants
#define MAX_STRING_LENGTH 50
#define MAX_VECTOR_SIZE 10

using namespace OHOS;
using namespace OHOS::NativeRdb;

namespace OHOS {

static const std::string RDB_PATH = "/data/test/absresultsetFuzzerTest.db";
static const std::string CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test "
                                             "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                             "name TEXT NOT NULL, age INTEGER, salary REAL, "
                                             "blobType BLOB)";

class AbsresultsetFuzzerTestCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int AbsresultsetFuzzerTestCallback::OnCreate(RdbStore &store)
{
    return store.ExecuteSql(CREATE_TABLE_TEST);
}

int AbsresultsetFuzzerTestCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

std::vector<ValueObject> ConsumeRandomLengthValueObjectVector(FuzzedDataProvider &provider)
{
    const int loopsMin = 0;
    const int loopsMax = 100;
    size_t loops = provider.ConsumeIntegralInRange<size_t>(loopsMin, loopsMax);
    std::vector<ValueObject> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t value = provider.ConsumeIntegral<int32_t>();
        ValueObject obj(value);
        columns.emplace_back(obj);
    }
    return columns;
}

std::vector<std::string> ConsumeRandomLengthStringVector(FuzzedDataProvider &provider)
{
    const int loopsMin = 0;
    const int loopsMax = 100;
    size_t loops = provider.ConsumeIntegralInRange<size_t>(loopsMin, loopsMax);
    std::vector<std::string> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t length = provider.ConsumeIntegral<int32_t>();
        auto bytes = provider.ConsumeBytes<char>(length);
        columns.emplace_back(bytes.begin(), bytes.end());
    }
    return columns;
}

void TestGetBlob(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    std::vector<uint8_t> blob;
    resultSet->GetBlob(columnIndex, blob);
}

void TestGetString(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    std::string value;
    resultSet->GetString(columnIndex, value);
}

void TestGetInt(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    int value;
    resultSet->GetInt(columnIndex, value);
}

void TestGetLong(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    int64_t value;
    resultSet->GetLong(columnIndex, value);
}

void TestGetDouble(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    double value;
    resultSet->GetDouble(columnIndex, value);
}

void TestGetAsset(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int32_t columnIndex = provider.ConsumeIntegral<int32_t>();
    ValueObject::Asset value;
    resultSet->GetAsset(columnIndex, value);
}

void TestGetAssets(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int32_t columnIndex = provider.ConsumeIntegral<int32_t>();
    ValueObject::Assets value;
    resultSet->GetAssets(columnIndex, value);
}

void TestGetFloat32Array(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int32_t columnIndex = provider.ConsumeIntegral<int32_t>();
    ValueObject::FloatVector value;
    resultSet->GetFloat32Array(columnIndex, value);
}

void TestIsColumnNull(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    bool isNull;
    resultSet->IsColumnNull(columnIndex, isNull);
}

void TestGetRow(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    RowEntity rowEntity;
    resultSet->GetRow(rowEntity);
}

void TestGoToRow(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int position = provider.ConsumeIntegral<int>();
    resultSet->GoToRow(position);
}

void TestGetColumnType(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    ColumnType columnType;
    resultSet->GetColumnType(columnIndex, columnType);
}

void TestGetRowIndex(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int position;
    resultSet->GetRowIndex(position);
}

void TestGoTo(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int offset = provider.ConsumeIntegral<int>();
    resultSet->GoTo(offset);
}

void TestGoToFirstRow(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GoToFirstRow();
}

void TestGoToLastRow(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GoToLastRow();
}

void TestGoToNextRow(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GoToNextRow();
}

void TestGoToPreviousRow(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GoToPreviousRow();
}

void TestIsAtFirstRow(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    bool result;
    resultSet->IsAtFirstRow(result);
}

void TestIsAtLastRow(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    bool result;
    resultSet->IsAtLastRow(result);
}

void TestIsStarted(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    bool result;
    resultSet->IsStarted(result);
}

void TestIsEnded(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    bool result;
    resultSet->IsEnded(result);
}

void TestGetColumnCount(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int count;
    resultSet->GetColumnCount(count);
}

void TestGetColumnIndex(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    std::string columnName = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int columnIndex;
    resultSet->GetColumnIndex(columnName, columnIndex);
}

void TestGetColumnName(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegral<int>();
    std::string columnName;
    resultSet->GetColumnName(columnIndex, columnName);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    RdbHelper::DeleteRdbStore(RDB_PATH);
    RdbStoreConfig config(RDB_PATH);
    config.SetHaMode(HAMode::MAIN_REPLICA);
    config.SetReadOnly(false);
    AbsresultsetFuzzerTestCallback helper;
    int errCode = E_OK;
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    if (store == nullptr || errCode != E_OK) {
        return 0;
    }
    std::vector<std::string> selectionArgs;
    std::shared_ptr<AbsResultSet> resultSet = store->QuerySql("SELECT * FROM test", selectionArgs);
    if (resultSet == nullptr) {
        return 0;
    }

    // Call test functions
    OHOS::TestGetBlob(provider, resultSet);
    OHOS::TestGetString(provider, resultSet);
    OHOS::TestGetInt(provider, resultSet);
    OHOS::TestGetLong(provider, resultSet);
    OHOS::TestGetDouble(provider, resultSet);
    OHOS::TestGetAsset(provider, resultSet);
    OHOS::TestGetAssets(provider, resultSet);
    OHOS::TestGetFloat32Array(provider, resultSet);
    OHOS::TestIsColumnNull(provider, resultSet);
    OHOS::TestGetRow(provider, resultSet);
    OHOS::TestGoToRow(provider, resultSet);
    OHOS::TestGetColumnType(provider, resultSet);
    OHOS::TestGetRowIndex(provider, resultSet);
    OHOS::TestGoTo(provider, resultSet);
    OHOS::TestGoToFirstRow(provider, resultSet);
    OHOS::TestGoToLastRow(provider, resultSet);
    OHOS::TestGoToNextRow(provider, resultSet);
    OHOS::TestGoToPreviousRow(provider, resultSet);
    OHOS::TestIsAtFirstRow(provider, resultSet);
    OHOS::TestIsAtLastRow(provider, resultSet);
    OHOS::TestIsStarted(provider, resultSet);
    OHOS::TestIsEnded(provider, resultSet);
    OHOS::TestGetColumnCount(provider, resultSet);
    OHOS::TestGetColumnIndex(provider, resultSet);
    OHOS::TestGetColumnName(provider, resultSet);
    return 0;
}