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
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <exception>
#include "abs_result_set.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

// Define constants
#define MAX_STRING_LENGTH 50
#define MAX_VECTOR_SIZE 10
#define MAX_COLUMN_INDEX 100
#define MIN_POSITION_VALUE -1000
#define MAX_POSITION_VALUE 1000

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
    explicit AbsresultsetFuzzerTestCallback(const std::string &createTableSql) : createTableSql_(createTableSql) {}

    int OnCreate(RdbStore &store) override
    {
        return store.ExecuteSql(createTableSql_);
    }

    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }

private:
    std::string createTableSql_;
};

std::vector<std::string> ConsumeRandomLengthStringVector(FuzzedDataProvider &provider)
{
    const size_t loopsMin = 0;
    const size_t loopsMax = MAX_VECTOR_SIZE;
    size_t loops = provider.ConsumeIntegralInRange<size_t>(loopsMin, loopsMax);
    std::vector<std::string> columns;
    for (size_t i = 0; i < loops; ++i) {
        int32_t length = provider.ConsumeIntegralInRange<int32_t>(0, MAX_STRING_LENGTH);
        auto bytes = provider.ConsumeBytes<char>(length);
        columns.emplace_back(bytes.begin(), bytes.end());
    }
    return columns;
}

void TestGetBlob(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegralInRange<int>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    std::vector<uint8_t> blob;
    resultSet->GetBlob(columnIndex, blob);
}

void TestGetString(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegralInRange<int>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    std::string value;
    resultSet->GetString(columnIndex, value);
}

void TestGetInt(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegralInRange<int>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    int value;
    resultSet->GetInt(columnIndex, value);
}

void TestGetLong(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegralInRange<int>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    int64_t value;
    resultSet->GetLong(columnIndex, value);
}

void TestGetDouble(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegralInRange<int>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    double value;
    resultSet->GetDouble(columnIndex, value);
}

void TestGetAsset(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    ValueObject::Asset value;
    resultSet->GetAsset(columnIndex, value);
}

void TestGetAssets(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    ValueObject::Assets value;
    resultSet->GetAssets(columnIndex, value);
}

void TestGetFloat32Array(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int32_t columnIndex = provider.ConsumeIntegralInRange<int32_t>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    ValueObject::FloatVector value;
    resultSet->GetFloat32Array(columnIndex, value);
}

void TestIsColumnNull(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegralInRange<int>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    bool isNull;
    resultSet->IsColumnNull(columnIndex, isNull);
}

void TestGetRow(std::shared_ptr<AbsResultSet> &resultSet)
{
    RowEntity rowEntity;
    resultSet->GetRow(rowEntity);
}

void TestGoToRow(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int position = provider.ConsumeIntegralInRange<int>(MIN_POSITION_VALUE, MAX_POSITION_VALUE);
    resultSet->GoToRow(position);
}

void TestGetColumnType(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int columnIndex = provider.ConsumeIntegralInRange<int>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    ColumnType columnType;
    resultSet->GetColumnType(columnIndex, columnType);
}

void TestGetRowIndex(std::shared_ptr<AbsResultSet> &resultSet)
{
    int position;
    resultSet->GetRowIndex(position);
}

void TestGoTo(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int offset = provider.ConsumeIntegralInRange<int>(MIN_POSITION_VALUE, MAX_POSITION_VALUE);
    resultSet->GoTo(offset);
}

void TestGoToFirstRow(std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GoToFirstRow();
}

void TestGoToLastRow(std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GoToLastRow();
}

void TestGoToNextRow(std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GoToNextRow();
}

void TestGoToPreviousRow(std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GoToPreviousRow();
}

void TestIsAtFirstRow(std::shared_ptr<AbsResultSet> &resultSet)
{
    bool result;
    resultSet->IsAtFirstRow(result);
}

void TestIsAtLastRow(std::shared_ptr<AbsResultSet> &resultSet)
{
    bool result;
    resultSet->IsAtLastRow(result);
}

void TestIsStarted(std::shared_ptr<AbsResultSet> &resultSet)
{
    bool result;
    resultSet->IsStarted(result);
}

void TestIsEnded(std::shared_ptr<AbsResultSet> &resultSet)
{
    bool result;
    resultSet->IsEnded(result);
}

void TestGetColumnCount(std::shared_ptr<AbsResultSet> &resultSet)
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
    int columnIndex = provider.ConsumeIntegralInRange<int>(-MAX_COLUMN_INDEX, MAX_COLUMN_INDEX);
    std::string columnName;
    resultSet->GetColumnName(columnIndex, columnName);
}

void TestGetWholeColumnNames(std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GetWholeColumnNames();
}

void TestGetRowData(std::shared_ptr<AbsResultSet> &resultSet)
{
    resultSet->GetRowData();
}

void TestGetRowsData(FuzzedDataProvider &provider, std::shared_ptr<AbsResultSet> &resultSet)
{
    int32_t maxCount = provider.ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    int32_t position = provider.ConsumeIntegralInRange<int32_t>(MIN_POSITION_VALUE, MAX_POSITION_VALUE);
    resultSet->GetRowsData(maxCount, position);
}

} // namespace OHOS

std::string CreateTableSql(FuzzedDataProvider &provider)
{
    // Use a limited set of valid SQL statements to reduce crashes
    // The fuzzer will test the database operations with valid table structures
    bool useCustomSql = provider.ConsumeBool();
    if (useCustomSql && provider.remaining_bytes() > 5) {
        std::string createTableSql = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
        if (!createTableSql.empty()) {
            return createTableSql;
        }
    }
    return CREATE_TABLE_TEST;
}

std::string CreateQuerySql(FuzzedDataProvider &provider)
{
    // Use a limited set of valid SQL queries to reduce crashes
    // The fuzzer will test the database operations with valid query structures
    bool useCustomSql = provider.ConsumeBool();
    if (useCustomSql && provider.remaining_bytes() > 5) {
        std::string sqlQuery = provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
        if (!sqlQuery.empty()) {
            return sqlQuery;
        }
    }
    return "SELECT * FROM test";
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Handle empty input gracefully
    if (data == nullptr || size == 0) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    RdbHelper::DeleteRdbStore(RDB_PATH);
    RdbStoreConfig config(RDB_PATH);
    // Use mutation data for configuration to improve fuzz coverage
    config.SetHaMode(provider.ConsumeBool() ? HAMode::MAIN_REPLICA : HAMode::SINGLE);
    config.SetReadOnly(provider.ConsumeBool());

    // Use mutation data for table creation SQL to improve fuzz coverage
    std::string createTableSql = CreateTableSql(provider);
    AbsresultsetFuzzerTestCallback helper(createTableSql);
    int errCode = E_OK;
    int version = provider.ConsumeIntegralInRange<int>(1, 10);
    std::shared_ptr<RdbStore> store = RdbHelper::GetRdbStore(config, version, helper, errCode);
    if (store == nullptr || errCode != E_OK) {
        return 0;
    }
    // Use mutation data for SQL query to improve fuzz coverage
    std::string sqlQuery = CreateQuerySql(provider);
    std::vector<std::string> selectionArgs = ConsumeRandomLengthStringVector(provider);
    std::shared_ptr<AbsResultSet> resultSet = store->QuerySql(sqlQuery, selectionArgs);
    if (resultSet == nullptr) {
        return 0;
    }

    // Call test functions with error handling
    OHOS::TestGetBlob(provider, resultSet);
    OHOS::TestGetString(provider, resultSet);
    OHOS::TestGetInt(provider, resultSet);
    OHOS::TestGetLong(provider, resultSet);
    OHOS::TestGetDouble(provider, resultSet);
    OHOS::TestGetAsset(provider, resultSet);
    OHOS::TestGetAssets(provider, resultSet);
    OHOS::TestGetFloat32Array(provider, resultSet);
    OHOS::TestIsColumnNull(provider, resultSet);
    OHOS::TestGetRow(resultSet);
    OHOS::TestGoToRow(provider, resultSet);
    OHOS::TestGetColumnType(provider, resultSet);
    OHOS::TestGetRowIndex(resultSet);
    OHOS::TestGoTo(provider, resultSet);
    OHOS::TestGoToFirstRow(resultSet);
    OHOS::TestGoToLastRow(resultSet);
    OHOS::TestGoToNextRow(resultSet);
    OHOS::TestGoToPreviousRow(resultSet);
    OHOS::TestIsAtFirstRow(resultSet);
    OHOS::TestIsAtLastRow(resultSet);
    OHOS::TestIsStarted(resultSet);
    OHOS::TestIsEnded(resultSet);
    OHOS::TestGetColumnCount(resultSet);
    OHOS::TestGetColumnIndex(provider, resultSet);
    OHOS::TestGetColumnName(provider, resultSet);
    OHOS::TestGetWholeColumnNames(resultSet);
    OHOS::TestGetRowData(resultSet);
    OHOS::TestGetRowsData(provider, resultSet);

    // Clean up database
    RdbHelper::DeleteRdbStore(RDB_PATH);
    return 0;
}
