/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cache_result_set.h"

#include <gtest/gtest.h>
#include <map>
#include <string>

#include "common.h"
#include "rdb_errno.h"
#include "value_object.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using Asset = ValueObject::Asset;
using Assets = ValueObject::Assets;
class CacheResultSetTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CacheResultSetTest::SetUpTestCase(void) {}

void CacheResultSetTest::TearDownTestCase(void) {}

void CacheResultSetTest::SetUp() {}

void CacheResultSetTest::TearDown() {}

/* *
 * @tc.name: GetRowCountTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get the number of rows from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetRowCountTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int count = 0;
    int ret = cacheResultSet.GetRowCount(count);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(count, 1);
}

/* *
 * @tc.name: GetAllColumnNamesTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get the all column names from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetAllColumnNamesTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, "test");
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    std::vector<std::string> columnNamesTmp = {};
    int ret = cacheResultSet.GetAllColumnNames(columnNamesTmp);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(std::set<std::string>(columnNamesTmp.begin(), columnNamesTmp.end()), columnNames);
}

/* *
 * @tc.name: GetBlobTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get blob of type from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetBlobTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    std::vector<uint8_t> blob = { 't', 'e', 's', 't' };
    valuesBucket.Put("data", blob);
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int columnIndex = 0;
    EXPECT_EQ(E_OK, cacheResultSet.GetColumnIndex("data", columnIndex));
    std::vector<uint8_t> blobOut = {};
    EXPECT_EQ(E_OK, cacheResultSet.GetBlob(columnIndex, blobOut));
    EXPECT_EQ(blob, blobOut);

    EXPECT_EQ(E_OK, cacheResultSet.GetColumnIndex("id", columnIndex));
    EXPECT_NE(E_OK, cacheResultSet.GetBlob(columnIndex, blobOut));
}

/* *
 * @tc.name: GetStringTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get string of type from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetStringTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, "test");
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int columnIndex = 0;
    std::string value;
    int ret = cacheResultSet.GetString(columnIndex, value);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ("test", value);
}

/* *
 * @tc.name: GetIntTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get int of type from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetIntTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, 111);
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int columnIndex = 1;
    int value;
    int ret = cacheResultSet.GetInt(columnIndex, value);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(111, value);
}

/* *
 * @tc.name: GetLongTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get long of type from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetLongTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, 11111111);
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int columnIndex = 1;
    int64_t value;
    int ret = cacheResultSet.GetLong(columnIndex, value);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(11111111, value);
}

/* *
 * @tc.name: GetDoubleTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get double of type from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetDoubleTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, 1111.1111);
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int columnIndex = 1;
    double value;
    int ret = cacheResultSet.GetDouble(columnIndex, value);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(1111.1111, value);
}

/* *
 * @tc.name: GetAssetTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get asset of type from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetAssetTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    ValueObject::Asset value = {};
    valuesBucket.Put("data", value);
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int32_t col = 0;
    EXPECT_EQ(E_OK, cacheResultSet.GetColumnIndex("data", col));
    ValueObject::Asset valueOut = {};
    EXPECT_EQ(E_OK, cacheResultSet.GetAsset(col, valueOut));

    EXPECT_EQ(E_OK, cacheResultSet.GetColumnIndex("id", col));
    EXPECT_NE(E_OK, cacheResultSet.GetAsset(col, valueOut));
}

/* *
 * @tc.name: GetAssetsTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get assets of type from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetAssetsTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    ValueObject::Assets value = {};
    valuesBucket.Put("data", value);
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int32_t col = 0;
    EXPECT_EQ(E_OK, cacheResultSet.GetColumnIndex("data", col));
    ValueObject::Assets valueOut = {};
    EXPECT_EQ(E_OK, cacheResultSet.GetAssets(col, valueOut));

    EXPECT_EQ(E_OK, cacheResultSet.GetColumnIndex("id", col));
    EXPECT_NE(E_OK, cacheResultSet.GetAssets(col, valueOut));
}

/* *
 * @tc.name: GetTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, 10);
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    ValueObject value;
    int res;
    EXPECT_EQ(E_OK, cacheResultSet.Get(0, value));
    EXPECT_EQ(E_OK, value.GetInt(res));
    EXPECT_EQ(res, 10);
}

/* *
 * @tc.name: IsColumnNullTest_001
 * @tc.desc: Normal testCase for CacheResultSet, check if the column is empty
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, IsColumnNullTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBucket.PutNull("null");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int columnIndex = 1;
    bool isNull = true;
    int ret = cacheResultSet.IsColumnNull(columnIndex, isNull);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(false, isNull);

    columnIndex = 3;
    int rets = cacheResultSet.IsColumnNull(columnIndex, isNull);
    EXPECT_EQ(E_OK, rets);
    EXPECT_EQ(true, isNull);
}

/* *
 * @tc.name: GetRowTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get row from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetRowTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, "1");
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    RowEntity rowEntity;
    EXPECT_EQ(E_OK, cacheResultSet.GetRow(rowEntity));
    for (auto& columnName : columnNames) {
        auto value = rowEntity.Get(columnName);
        string res;
        EXPECT_EQ(E_OK, value.GetString(res));
        EXPECT_EQ("1", res);
    }
}

/* *
 * @tc.name: GoToRowTest_001
 * @tc.desc: Normal testCase for CacheResultSet, go to row in the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GoToRowTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, "1");
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int position = 0;
    int ret = cacheResultSet.GoToRow(position);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(0, position);
}

/* *
 * @tc.name: GetColumnTypeTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get column type from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetColumnTypeTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, "1");
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int columnIndex = 1;
    ColumnType columnType;
    int ret = cacheResultSet.GetColumnType(columnIndex, columnType);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(ColumnType::TYPE_STRING, columnType);
}

/* *
 * @tc.name: GetRowIndexTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get row index from the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetRowIndexTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, "1");
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int columnIndex = 1;
    int ret = cacheResultSet.GetRowIndex(columnIndex);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(0, columnIndex);
}

/* *
 * @tc.name: GoToTest_001
 * @tc.desc: Normal testCase for CacheResultSet, go to a specific line
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GoToTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 5; i++) {
        ValuesBucket valuesBucket;
        std::set<std::string> columnNames = { "id", "data", "field" };
        for (auto& column : columnNames) {
            valuesBucket.Put(column, "test" + std::to_string(i));
        }
        valuesBuckets.push_back(std::move(valuesBucket));
    }
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    // now position is 0
    int offset = 1;
    // go to position 1
    EXPECT_EQ(E_OK, cacheResultSet.GoTo(offset));
    std::string value;
    EXPECT_EQ(E_OK, cacheResultSet.GetString(0, value));
    EXPECT_EQ(value, "test1");

    EXPECT_EQ(E_OK, cacheResultSet.GoToRow(3));
    EXPECT_EQ(E_OK, cacheResultSet.GetString(0, value));
    EXPECT_EQ(value, "test3");

    // exceed maxRow
    EXPECT_NE(E_OK, cacheResultSet.GoTo(2));
}

/* *
 * @tc.name: GoToFirstRowTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get the first row of the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GoToFirstRowTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, "test");
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    EXPECT_EQ(E_OK, cacheResultSet.GoToFirstRow());
    int position = -1;
    EXPECT_EQ(E_OK, cacheResultSet.GetRowIndex(position));
    EXPECT_EQ(position, 0);
}

/* *
 * @tc.name: GoToLastRowTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get the last row of the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GoToLastRowTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, "test");
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    EXPECT_EQ(E_OK, cacheResultSet.GoToLastRow());
    int position = -1;
    EXPECT_EQ(E_OK, cacheResultSet.GetRowIndex(position));
    EXPECT_EQ(position, 0);
}

/* *
 * @tc.name: GoToNextRowTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get the next row of the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GoToNextRowTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    for (int i = 0; i < 5; i++) {
        ValuesBucket valuesBucket;
        std::set<std::string> columnNames = { "id", "data", "field" };
        for (auto& column : columnNames) {
            valuesBucket.Put(column, "test" + std::to_string(i));
        }
        valuesBuckets.push_back(std::move(valuesBucket));
    }
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    EXPECT_EQ(E_OK, cacheResultSet.GoToNextRow());
    int position = -1;
    EXPECT_EQ(E_OK, cacheResultSet.GetRowIndex(position));
    EXPECT_EQ(position, 1);
}

/* *
 * @tc.name: GoToPreviousRowTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get the previous row of the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GoToPreviousRowTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int offset = 1;
    int position = 0;
    cacheResultSet.GoToRow(position);
    cacheResultSet.GoTo(offset);
    int ret = cacheResultSet.GoToPreviousRow();
    EXPECT_EQ(E_OK, ret);
}

/* *
 * @tc.name: IsAtFirstRowTest_001
 * @tc.desc: Normal testCase for CacheResultSet, is it on the first line
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, IsAtFirstRowTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    bool result = false;
    EXPECT_EQ(E_OK, cacheResultSet.IsAtFirstRow(result));
    EXPECT_TRUE(result);
    EXPECT_NE(E_OK, cacheResultSet.GoToNextRow());
    EXPECT_EQ(E_OK, cacheResultSet.IsAtLastRow(result));
    EXPECT_FALSE(result);
}

/* *
 * @tc.name: IsAtLastRowTest_001
 * @tc.desc: Normal testCase for CacheResultSet, is it on the last line
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, IsAtLastRowTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    bool result = false;
    EXPECT_EQ(E_OK, cacheResultSet.IsAtLastRow(result));
    EXPECT_TRUE(result);
    EXPECT_NE(E_OK, cacheResultSet.GoToNextRow());
    EXPECT_EQ(E_OK, cacheResultSet.IsAtLastRow(result));
    EXPECT_FALSE(result);
}

/* *
 * @tc.name: IsStartedTest_001
 * @tc.desc: Normal testCase for CacheResultSet, is it at the starting
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, IsStartedTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    bool result = true;
    int ret = cacheResultSet.IsStarted(result);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(false, result);
}

/* *
 * @tc.name: IsEndedTest_001
 * @tc.desc: Normal testCase for CacheResultSet, is it at the end
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, IsEndedTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    bool result = true;
    int ret = cacheResultSet.IsEnded(result);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(false, result);
}

/* *
 * @tc.name: GetColumnCountTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get the number of columns in the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetColumnCountTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int count = 0;
    int ret = cacheResultSet.GetColumnCount(count);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(3, count);
}

/* *
 * @tc.name: GetColumnIndexTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get the number of columnsIndex in the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetColumnIndexTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    std::string columnName = "field";
    int columnIndex;
    int ret = cacheResultSet.GetColumnIndex(columnName, columnIndex);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(1, columnIndex);

    columnName = "wang";
    ret = cacheResultSet.GetColumnIndex(columnName, columnIndex);
    EXPECT_NE(E_OK, ret);
}

/* *
 * @tc.name: GetColumnNameTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get the number of columnsName in the list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetColumnNameTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    std::set<std::string> columnNames = { "id", "data", "field" };
    for (auto& column : columnNames) {
        valuesBucket.Put(column, "test");
    }
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    std::string columnName;
    std::vector<std::string> columnNamesTmp = {};
    for (int i = 0; i < 3; i++) {
        EXPECT_EQ(E_OK, cacheResultSet.GetColumnName(i, columnName));
        columnNamesTmp.push_back(columnName);
    }
    EXPECT_EQ(std::set<std::string>(columnNamesTmp.begin(), columnNamesTmp.end()), columnNames);
}

/* *
 * @tc.name: IsClosedTest_001
 * @tc.desc: Normal testCase for CacheResultSet, is the list closed
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, IsClosedTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    EXPECT_EQ(false, cacheResultSet.IsClosed());
}

/* *
 * @tc.name: CloseTest_001
 * @tc.desc: Normal testCase for CacheResultSet, close list
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, CloseTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int ret = cacheResultSet.Close();
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}

/* *
 * @tc.name: GetSizeTest_001
 * @tc.desc: Normal testCase for CacheResultSet, get size
 * @tc.type: FUNC
 */
HWTEST_F(CacheResultSetTest, GetSizeTest_001, TestSize.Level2)
{
    std::vector<ValuesBucket> valuesBuckets;
    ValuesBucket valuesBucket;
    valuesBucket.Put("id", 1);
    valuesBucket.Put("data", "test");
    valuesBucket.Put("field", "test");
    valuesBuckets.push_back(std::move(valuesBucket));
    CacheResultSet cacheResultSet(std::move(valuesBuckets));

    int columnIndex = 0;
    size_t size;
    int ret = cacheResultSet.GetSize(columnIndex, size);
    EXPECT_EQ(E_NOT_SUPPORT, ret);
}