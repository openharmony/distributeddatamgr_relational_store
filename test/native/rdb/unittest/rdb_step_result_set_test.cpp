/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include <climits>
#include <string>

#include "cache_result_set.h"
#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "result_set_proxy.h"
#include "sqlite_sql_builder.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
namespace OHOS {
namespace NativeRdb {
struct ResultSetData {
    std::string strValue;
    int iValue;
    double dValue;
    std::vector<uint8_t> blobValue;
};

class RdbStepResultSetTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void GenerateDefaultTable();
    void GenerateDefaultEmptyTable();
    void CheckColumnType(std::shared_ptr<ResultSet> resultSet, int columnIndex, ColumnType type);
    void CheckResultSetAttribute(
        std::shared_ptr<ResultSet> resultSet, int pos, bool isStart, bool isAtFirstRow, bool isEnded);
    void CheckResultSetData(int columnIndex, std::shared_ptr<ResultSet> resultSet, ResultSetData &rowData);

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static ResultSetData g_resultSetData[3];
};

const std::string RdbStepResultSetTest::DATABASE_NAME = RDB_TEST_PATH + "stepResultSet_test.db";
std::shared_ptr<RdbStore> RdbStepResultSetTest::store = nullptr;
ResultSetData RdbStepResultSetTest::g_resultSetData[3] = { { "2", -5, 2.5, std::vector<uint8_t>{} },
    { "hello", 10, 1.0, std::vector<uint8_t>{ 66 } }, { "hello world", 3, 1.8, std::vector<uint8_t>{} } };

class RdbStepResultSetOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST;
};

int RdbStepResultSetOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int RdbStepResultSetOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStepResultSetTest::SetUpTestCase(void)
{
    int errCode = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig config(RdbStepResultSetTest::DATABASE_NAME);
    RdbStepResultSetOpenCallback helper;
    RdbStepResultSetTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbStepResultSetTest::store, nullptr);
    EXPECT_EQ(errCode, E_OK);
}

void RdbStepResultSetTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbStepResultSetTest::DATABASE_NAME);
}

void RdbStepResultSetTest::SetUp(void)
{
    store->ExecuteSql("DELETE FROM test");
}

void RdbStepResultSetTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

void RdbStepResultSetTest::GenerateDefaultTable()
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, ") +
        std::string("data2 INTEGER, data3 FLOAT, data4 BLOB);");
    store->ExecuteSql(createTableSql);

    std::string insertSql = "INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);";

    /* insert first entry data */
    uint8_t uValue = 66;
    std::vector<uint8_t> typeBlob;
    typeBlob.push_back(uValue);
    store->ExecuteSql(insertSql, std::vector<ValueObject>{ ValueObject(std::string("hello")), ValueObject((int)10),
                                     ValueObject((double)1.0), ValueObject((std::vector<uint8_t>)typeBlob) });

    /* insert second entry data */
    typeBlob.clear();
    store->ExecuteSql(insertSql, std::vector<ValueObject>{
                                     ValueObject(std::string("2")), ValueObject((int)-5), ValueObject((double)2.5),
                                     ValueObject() // set double value 2.5
                                 });

    /* insert third entry data */
    store->ExecuteSql(insertSql, std::vector<ValueObject>{
                                     ValueObject(std::string("hello world")), ValueObject((int)3),
                                     ValueObject((double)1.8), ValueObject() // set int value 3, double 1.8
                                 });
}

void RdbStepResultSetTest::GenerateDefaultEmptyTable()
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, ") +
        std::string("data2 INTEGER, data3 FLOAT, data4 BLOB);");
    store->ExecuteSql(createTableSql);
}

void RdbStepResultSetTest::CheckColumnType(std::shared_ptr<ResultSet> resultSet, int columnIndex, ColumnType type)
{
    ColumnType columnType;
    int iRet = resultSet->GetColumnType(columnIndex, columnType);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(columnType, type);
}

void RdbStepResultSetTest::CheckResultSetAttribute(
    std::shared_ptr<ResultSet> resultSet, int pos, bool isStart, bool isAtFirstRow, bool isEnded)
{
    int position = -1;
    int iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(pos, position);

    bool bResultSet = !isStart;
    iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(isStart, bResultSet);

    bResultSet = !isAtFirstRow;
    iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(isAtFirstRow, bResultSet);

    bResultSet = !isEnded;
    iRet = resultSet->IsEnded(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(isEnded, bResultSet);
}

void RdbStepResultSetTest::CheckResultSetData(
    int columnIndex, std::shared_ptr<ResultSet> resultSet, ResultSetData &resultSetData)
{
    std::string strValue;
    int iValue;
    double dValue;
    std::vector<uint8_t> blobValue;

    int iRet = resultSet->GetString(columnIndex, strValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(resultSetData.strValue, strValue);

    iRet = resultSet->GetInt(++columnIndex, iValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(resultSetData.iValue, iValue);

    iRet = resultSet->GetDouble(++columnIndex, dValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(resultSetData.dValue, dValue);

    iRet = resultSet->GetBlob(++columnIndex, blobValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(resultSetData.blobValue.size(), blobValue.size());
    for (int i = 0; i < blobValue.size(); i++) {
        EXPECT_EQ(resultSetData.blobValue[i], blobValue[i]);
    }
}

/* *
 * @tc.name: RdbStore_StepResultSet_001
 * @tc.desc: test StepResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_001, TestSize.Level1)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    bool bResultSet = true;
    int iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);
    EXPECT_EQ(resultSet->GoTo(1), E_OK);

    bResultSet = false;
    iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    CheckColumnType(resultSet, 0, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSet, 1, ColumnType::TYPE_STRING);

    CheckColumnType(resultSet, 2, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSet, 3, ColumnType::TYPE_FLOAT);

    CheckColumnType(resultSet, 4, ColumnType::TYPE_BLOB);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    EXPECT_EQ(E_OK, resultSet->GoToNextRow());

    int position = -1;
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, position);
    int count = -1;
    iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);

    CheckResultSetData(1, resultSet, g_resultSetData[0]);
}

/* *
 * @tc.name: RdbStore_StepResultSet_002
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_002, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    int count = -1;
    resultSet->GetRowCount(count);
    EXPECT_EQ(3, count);

    int position = INT_MIN;
    int iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(-1, position);

    bool bResultSet = true;
    resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(bResultSet, false);

    EXPECT_EQ(E_OK, resultSet->GoToRow(2));

    bResultSet = false;
    iRet = resultSet->IsAtLastRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(true, bResultSet);

    EXPECT_EQ(E_OK, resultSet->GoToPreviousRow());

    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, position);

    EXPECT_EQ(E_OK, resultSet->GoToLastRow());

    bResultSet = false;
    iRet = resultSet->IsAtLastRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(true, bResultSet);

    bResultSet = false;
    iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    bResultSet = true;
    iRet = resultSet->IsEnded(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);
}

/* *
 * @tc.name: RdbStore_StepResultSet_003
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_003, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    CheckResultSetAttribute(resultSet, -1, false, false, false);

    int moveTimes = 0;
    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    moveTimes++;

    CheckResultSetAttribute(resultSet, 0, true, true, false);

    int position = INT_MIN;
    int iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0, position);
    while (E_OK == resultSet->GoToNextRow()) {
        moveTimes++;
    }
    /* Cursor is before first */

    CheckResultSetAttribute(resultSet, 3, true, false, true);
}

/* *
 * @tc.name: RdbStore_StepResultSet_004
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_004, TestSize.Level1)
{
    GenerateDefaultEmptyTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    CheckResultSetAttribute(resultSet, -1, false, false, false);

    EXPECT_NE(E_OK, resultSet->GoToNextRow());

    int position = INT_MIN;
    int iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0, position);

    CheckResultSetAttribute(resultSet, 0, true, false, false);
}

/* *
 * @tc.name: RdbStore_StepResultSet_005
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_005, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    CheckResultSetAttribute(resultSet, 0, true, true, false);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    CheckResultSetAttribute(resultSet, 0, true, true, false);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    bool bResultSet = false;
    int iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    bResultSet = false;
    iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);
}

/* *
 * @tc.name: RdbStore_StepResultSet_006
 * @tc.desc: normal testcase of StepResultSet for moveFirstWithoutEntry
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_006, TestSize.Level1)
{
    GenerateDefaultEmptyTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    EXPECT_NE(E_OK, resultSet->GoToFirstRow());

    CheckResultSetAttribute(resultSet, 0, true, false, false);

    EXPECT_NE(E_OK, resultSet->GoToNextRow());
    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    bool bResultSet = false;
    int iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);

    bResultSet = false;
    iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);
}

/* *
 * @tc.name: RdbStore_StepResultSet_007
 * @tc.desc: normal testcase of StepResultSet for goToNextRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_007, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    int moveTimes = 0;
    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    moveTimes++;
    int position = INT_MIN;
    bool bResultSet = true;
    int iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0, position);

    iRet = resultSet->IsEnded(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);

    while (E_OK == resultSet->GoToNextRow()) {
        moveTimes++;
    }
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, position);

    bResultSet = false;
    iRet = resultSet->IsEnded(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);
}
/* *
 * @tc.name: RdbStore_StepResultSet_008
 * @tc.desc: normal testcase of StepResultSet for moveNextWithoutEntry
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_008, TestSize.Level1)
{
    GenerateDefaultEmptyTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    int moveTimes = 0;

    EXPECT_NE(E_OK, resultSet->GoToFirstRow());
    moveTimes++;
    int position = INT_MIN;
    bool bResultSet = false;
    int iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0, position);

    iRet = resultSet->IsEnded(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);

    while (E_OK == resultSet->GoToNextRow()) {
        moveTimes++;
    }
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0, position);

    bResultSet = false;
    iRet = resultSet->IsEnded(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);
}
/* *
 * @tc.name: RdbStore_StepResultSet_009
 * @tc.desc: normal testcase of StepResultSet for getInt
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_009, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    int iValue;
    int iRet = resultSet->GetInt(0, iValue);
    EXPECT_NE(E_OK, iRet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    iRet = resultSet->GetInt(0, iValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0, iValue);

    iRet = resultSet->GetInt(1, iValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(10, iValue);

    iRet = resultSet->GetInt(2, iValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, iValue);

    iRet = resultSet->GetInt(3, iValue);
    EXPECT_EQ(E_OK, iRet);

    int columnCount = 0;
    iRet = resultSet->GetColumnCount(columnCount);
    EXPECT_EQ(4, columnCount);
    iRet = resultSet->GetInt(columnCount, iValue);
    EXPECT_NE(E_OK, iRet);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    iRet = resultSet->GetInt(0, iValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(2, iValue);

    int64_t longValue;
    iRet = resultSet->GetLong(0, longValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(2, longValue);

    iRet = resultSet->GetInt(1, iValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(-5, iValue);

    iRet = resultSet->GetLong(1, longValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(-5, longValue);

    iRet = resultSet->GetInt(2, iValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(2, iValue);
}
/* *
 * @tc.name: RdbStore_StepResultSet_010
 * @tc.desc: normal testcase of StepResultSet for getString
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_010, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    std::string strValue;
    int iRet = resultSet->GetString(0, strValue);
    EXPECT_NE(E_OK, iRet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    iRet = resultSet->GetString(0, strValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ("hello", strValue);
    iRet = resultSet->GetString(1, strValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ("10", strValue);
    iRet = resultSet->GetString(2, strValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ("1", strValue);

    iRet = resultSet->GetString(3, strValue);
    EXPECT_EQ(E_OK, iRet);

    int columnCount = 0;
    iRet = resultSet->GetColumnCount(columnCount);
    EXPECT_EQ(4, columnCount);
    iRet = resultSet->GetString(columnCount, strValue);
    EXPECT_NE(E_OK, iRet);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    iRet = resultSet->GetString(0, strValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ("2", strValue);
    iRet = resultSet->GetString(1, strValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ("-5", strValue);
    iRet = resultSet->GetString(2, strValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ("2.5", strValue);
}

/* *
 * @tc.name: RdbStore_StepResultSet_011
 * @tc.desc: normal testcase of StepResultSet for GetDouble
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_011, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    double dValue;
    int iRet = resultSet->GetDouble(0, dValue);
    EXPECT_NE(E_OK, iRet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    iRet = resultSet->GetDouble(0, dValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0.0, dValue);
    iRet = resultSet->GetDouble(1, dValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(10.0, dValue);

    iRet = resultSet->GetDouble(2, dValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1.0, dValue);

    iRet = resultSet->GetDouble(3, dValue);
    EXPECT_EQ(E_OK, iRet);
    int columnCount = 0;
    iRet = resultSet->GetColumnCount(columnCount);
    EXPECT_EQ(4, columnCount);
    iRet = resultSet->GetDouble(columnCount, dValue);
    EXPECT_NE(E_OK, iRet);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    iRet = resultSet->GetDouble(0, dValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(2.0, dValue);
    iRet = resultSet->GetDouble(1, dValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(-5.0, dValue);
    iRet = resultSet->GetDouble(2, dValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(2.5, dValue);
}

/* *
 * @tc.name: RdbStore_StepResultSet_012
 * @tc.desc: normal testcase of StepResultSet for getBlob
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_012, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    std::vector<uint8_t> blobValue;
    int iRet = resultSet->GetBlob(0, blobValue);
    EXPECT_NE(E_OK, iRet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    iRet = resultSet->GetBlob(0, blobValue);
    EXPECT_EQ(E_OK, iRet);

    string strBlob;
    for (size_t i = 0; i < blobValue.size(); i++) {
        strBlob += char(blobValue[i]);
    }
    EXPECT_EQ("hello", strBlob);

    iRet = resultSet->GetBlob(1, blobValue);
    EXPECT_EQ(E_OK, iRet);

    iRet = resultSet->GetBlob(2, blobValue);
    EXPECT_EQ(E_OK, iRet);

    iRet = resultSet->GetBlob(3, blobValue);
    EXPECT_EQ(E_OK, iRet);

    strBlob.clear();
    for (size_t i = 0; i < blobValue.size(); i++) {
        strBlob += char(blobValue[i]);
    }
    char cValue = 66;
    string strTmpValue(1, cValue);
    EXPECT_EQ(strTmpValue, strBlob);

    int columnCount = 0;
    iRet = resultSet->GetColumnCount(columnCount);
    EXPECT_EQ(4, columnCount);
    iRet = resultSet->GetBlob(columnCount, blobValue);
    EXPECT_NE(E_OK, iRet);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    iRet = resultSet->GetBlob(3, blobValue);
    EXPECT_EQ(E_OK, iRet);
}

/* *
 * @tc.name: RdbStore_StepResultSet_013
 * @tc.desc: normal testcase of StepResultSet for getBlob
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_013, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    ColumnType type;
    int iRet = resultSet->GetColumnType(0, type);
    EXPECT_NE(E_OK, iRet);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    CheckColumnType(resultSet, 0, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSet, 1, ColumnType::TYPE_STRING);

    CheckColumnType(resultSet, 2, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSet, 3, ColumnType::TYPE_FLOAT);

    CheckColumnType(resultSet, 4, ColumnType::TYPE_BLOB);

    int columnCount = 0;
    iRet = resultSet->GetColumnCount(columnCount);
    EXPECT_EQ(5, columnCount);
    iRet = resultSet->GetColumnType(columnCount, type);
    EXPECT_NE(E_OK, iRet);
}

/* *
 * @tc.name: RdbStore_StepResultSet_014
 * @tc.desc: normal testcase of StepResultSet for getColumnIndexForName
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_014, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    int columnIndex;
    int iRet = resultSet->GetColumnIndex("data1", columnIndex);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, columnIndex);

    iRet = resultSet->GetColumnIndex("data2", columnIndex);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(2, columnIndex);

    iRet = resultSet->GetColumnIndex("data3", columnIndex);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, columnIndex);

    iRet = resultSet->GetColumnIndex("data4", columnIndex);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(4, columnIndex);

    iRet = resultSet->GetColumnIndex("jank.data1", columnIndex);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, columnIndex);

    iRet = resultSet->GetColumnIndex("datax", columnIndex);
    EXPECT_EQ(E_ERROR, iRet);
    EXPECT_EQ(-1, columnIndex);
}

/* *
 * @tc.name: RdbStore_StepResultSet_015
 * @tc.desc: normal testcase of StepResultSet for getColumnNameForIndex
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_015, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    std::vector<std::string> allColumnNames;
    int iRet = resultSet->GetAllColumnNames(allColumnNames);
    EXPECT_EQ(E_OK, iRet);

    std::string columnName;
    iRet = resultSet->GetColumnName(1, columnName);
    EXPECT_EQ("data1", columnName);
    EXPECT_EQ(allColumnNames[1], columnName);

    iRet = resultSet->GetColumnName(2, columnName);
    EXPECT_EQ("data2", columnName);
    EXPECT_EQ(allColumnNames[2], columnName);

    iRet = resultSet->GetColumnName(3, columnName);
    EXPECT_EQ("data3", columnName);
    EXPECT_EQ(allColumnNames[3], columnName);

    iRet = resultSet->GetColumnName(4, columnName);
    EXPECT_EQ("data4", columnName);
    EXPECT_EQ(allColumnNames[4], columnName);

    int columnCount = 0;
    iRet = resultSet->GetColumnCount(columnCount);
    EXPECT_EQ(5, columnCount);
    iRet = resultSet->GetColumnName(columnCount, columnName);
    EXPECT_NE(E_OK, iRet);
}

/* *
 * @tc.name: RdbStore_StepResultSet_016
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, RdbStore_StepResultSet_016, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    bool bResultSet = false;
    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    int iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    bResultSet = false;
    iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    int iValue;
    iRet = resultSet->GetInt(1, iValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(10, iValue);

    int64_t longValue;
    iRet = resultSet->GetLong(1, longValue);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(10, longValue);
}

/* *
 * @tc.name: testGetRowCount003
 * @tc.desc: normal testcase of StepResultSet for getRowCount
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, testGetRowCount003, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    bool bResultSet = true;
    int iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);

    int count = -1;
    iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);
    EXPECT_EQ(E_OK, resultSet->GoToNextRow());

    bResultSet = false;
    EXPECT_EQ(E_OK, resultSet->IsAtFirstRow(bResultSet));
    EXPECT_EQ(bResultSet, true);

    CheckResultSetData(1, resultSet, g_resultSetData[1]);

    iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    int position = INT_MIN;
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, position);

    CheckResultSetData(1, resultSet, g_resultSetData[0]);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(2, position);

    iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);
}

/* *
 * @tc.name: testGetRowCount004
 * @tc.desc: normal testcase of StepResultSet for getRowCount
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, testGetRowCount004, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    bool bResultSet = true;
    int iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);
    EXPECT_EQ(E_OK, resultSet->GoToNextRow());

    bResultSet = false;
    iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    int count = -1;
    iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);

    CheckResultSetData(0, resultSet, g_resultSetData[1]);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());

    int position = INT_MIN;
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, position);

    EXPECT_EQ(E_OK, resultSet->GoToNextRow());

    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(2, position);

    iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);

    CheckResultSetData(0, resultSet, g_resultSetData[2]);
}

/* *
 * @tc.name: testGoToRow005
 * @tc.desc: normal testcase of StepResultSet for goToRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, testGoToRow005, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    bool bResultSet = true;
    int iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);
    EXPECT_EQ(E_OK, resultSet->GoToNextRow());

    bResultSet = false;
    iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    int position = INT_MIN;
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0, position);

    EXPECT_EQ(E_OK, resultSet->GoToRow(2));

    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(2, position);

    CheckResultSetData(0, resultSet, g_resultSetData[2]);

    EXPECT_EQ(E_OK, resultSet->GoToRow(1));

    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, position);

    CheckResultSetData(0, resultSet, g_resultSetData[0]);
}

/* *
 * @tc.name: testGo006
 * @tc.desc: normal testcase of StepResultSet for goToRow
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, testGo006, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    int position = INT_MIN;
    int iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(-1, position);

    int count = -1;
    iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0, position);

    EXPECT_EQ(resultSet->GoTo(2), E_OK);

    CheckResultSetData(1, resultSet, g_resultSetData[2]);

    EXPECT_EQ(resultSet->GoTo(-2), E_OK);

    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(0, position);

    CheckResultSetData(1, resultSet, g_resultSetData[1]);
}

/* *
 * @tc.name: testGoToPrevious007
 * @tc.desc: normal testcase of StepResultSet for go
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, testGoToPrevious007, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    int count = -1;
    int iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);

    bool bResultSet = true;
    iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());

    bResultSet = false;
    iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    CheckResultSetData(0, resultSet, g_resultSetData[1]);

    int ret = resultSet->GoToPreviousRow();
    EXPECT_NE(E_OK, ret);

    CheckResultSetAttribute(resultSet, 0, true, true, false);

    EXPECT_EQ(resultSet->GoTo(1), E_OK);

    CheckResultSetData(0, resultSet, g_resultSetData[0]);

    EXPECT_EQ(E_OK, resultSet->GoToLastRow());

    iRet = resultSet->IsAtLastRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(true, bResultSet);

    EXPECT_EQ(E_OK, resultSet->GoToPreviousRow());

    int position = INT_MIN;
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, position);

    EXPECT_NE(E_OK, resultSet->GoTo(3));

    CheckResultSetAttribute(resultSet, 3, true, false, true);
}

/* *
 * @tc.name: testSqlStep008
 * @tc.desc: normal testcase of SqlStep for go
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep008, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    bool bResultSet = true;
    int iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);

    EXPECT_EQ(E_OK, resultSet->GoTo(1));

    bResultSet = false;
    iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    CheckColumnType(resultSet, 0, ColumnType::TYPE_STRING);

    CheckColumnType(resultSet, 1, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSet, 2, ColumnType::TYPE_FLOAT);

    CheckColumnType(resultSet, 3, ColumnType::TYPE_BLOB);

    EXPECT_EQ(E_OK, resultSet->GoToFirstRow());
    EXPECT_EQ(E_OK, resultSet->GoToNextRow());

    int position = INT_MIN;
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, position);

    int count = -1;
    iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);

    CheckResultSetData(0, resultSet, g_resultSetData[0]);
}

/* *
 * @tc.name: testSqlStep009
 * @tc.desc: normal testcase of SqlStep for go
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep009, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    int count = -1;
    int iRet = resultSet->GetRowCount(count);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(3, count);

    int position = INT_MIN;
    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(-1, position);

    bool bResultSet = true;
    iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);

    EXPECT_EQ(E_OK, resultSet->GoToRow(2));

    bResultSet = false;
    iRet = resultSet->IsAtLastRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(true, bResultSet);

    EXPECT_EQ(E_OK, resultSet->GoToPreviousRow());

    iRet = resultSet->GetRowIndex(position);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(1, position);

    EXPECT_EQ(E_OK, resultSet->GoToLastRow());

    bResultSet = false;
    iRet = resultSet->IsAtLastRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(true, bResultSet);

    bResultSet = false;
    iRet = resultSet->IsAtLastRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(true, bResultSet);

    bResultSet = false;
    iRet = resultSet->IsStarted(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    bResultSet = true;
    iRet = resultSet->IsEnded(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, false);
}

/* *
 * @tc.name: testSqlStep010
 * @tc.desc: normal testcase of SqlStep for go
 * @tc.type: FUNC
 * @tc.require: AR000FKD4F
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep010, TestSize.Level1)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    CheckResultSetAttribute(resultSet, -1, false, false, false);

    int moveTimes = 0;
    EXPECT_EQ(E_OK, resultSet->GoToNextRow());
    moveTimes++;

    CheckResultSetAttribute(resultSet, 0, true, true, false);

    while (E_OK == resultSet->GoToNextRow()) {
        moveTimes++;
    }

    CheckResultSetAttribute(resultSet, 3, true, false, true);
}

/* *
 * @tc.name: testSqlStep011
 * @tc.desc: normal testcase of SqlStep for GetString()
 * @tc.type: FUNC
 * @tc.require: NA
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep011, TestSize.Level1)
{
    GenerateDefaultEmptyTable();

    std::string insertSql = "INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);";
    const char arr[] = { 0X11, 0X22, 0X33, 0X44, 0X55, 0X00, 0X66, 0X77, 0X00 };
    size_t arrLen = sizeof(arr);
    uint8_t uValue = 66;
    std::vector<uint8_t> typeBlob;
    typeBlob.push_back(uValue);
    store->ExecuteSql(insertSql, std::vector<ValueObject>{ ValueObject(std::string(arr, arrLen)), ValueObject((int)10),
                                     ValueObject((double)1.0), ValueObject((std::vector<uint8_t>)typeBlob) });
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    EXPECT_NE(resultSet, nullptr);

    int iRet = resultSet->GoToFirstRow();
    EXPECT_EQ(E_OK, iRet);
    bool bResultSet = false;
    iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    std::string stringValue;
    iRet = resultSet->GetString(0, stringValue);
    size_t stringValueLen = stringValue.length();
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(arrLen, stringValueLen);
}

/* *
 * @tc.name: testSqlStep012
 * @tc.desc: Normal testcase of SqlStep for constructor std::vector<ValueObject>
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep012, TestSize.Level1)
{
    GenerateDefaultEmptyTable();

    std::string insertSql = "INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);";
    const char arr[] = { 0X11, 0X22, 0X33, 0X44, 0X55, 0X00, 0X66, 0X77, 0X00 };
    size_t arrLen = sizeof(arr);
    uint8_t uValue = 66;
    std::vector<uint8_t> typeBlob;
    typeBlob.push_back(uValue);
    store->ExecuteSql(insertSql, std::vector<ValueObject>{ ValueObject(std::string(arr, arrLen)), ValueObject((int)10),
                                     ValueObject((double)1.0), ValueObject((std::vector<uint8_t>)typeBlob) });

    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT ? FROM test", std::vector<ValueObject>{ ValueObject((std::string) "data1") });
    EXPECT_NE(resultSet, nullptr);

    int iRet = resultSet->GoToFirstRow();
    EXPECT_EQ(E_OK, iRet);
    bool bResultSet = false;
    iRet = resultSet->IsAtFirstRow(bResultSet);
    EXPECT_EQ(E_OK, iRet);
    EXPECT_EQ(bResultSet, true);

    EXPECT_EQ(E_OK, resultSet->Close());
}

/* *
 * @tc.name: testSqlStep013
 * @tc.desc: Abnormal testcase of SqlStep, if close resultSet before query
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep013, TestSize.Level1)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);

    EXPECT_EQ(E_OK, resultSet->Close());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToNextRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToLastRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToPreviousRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToFirstRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToRow(1));

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToLastRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToPreviousRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToFirstRow());

    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GoToRow(1));

    std::vector<std::string> columnNames;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetAllColumnNames(columnNames));

    ColumnType columnType;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetColumnType(1, columnType));

    std::vector<uint8_t> blob;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetBlob(1, blob));

    std::string valueString;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetString(1, valueString));

    int valueInt;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetInt(1, valueInt));

    int64_t valueInt64;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetLong(1, valueInt64));

    double valuedouble;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->GetDouble(1, valuedouble));

    ValueObject object;
    EXPECT_EQ(E_ALREADY_CLOSED, resultSet->Get(4, object));
}

/* *
 * @tc.name: testSqlStep014
 * @tc.desc: Abnormal testcase of SqlStep for GoToRow, if connection counts over limit
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep014, TestSize.Level1)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSet1 = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet1, nullptr);

    std::shared_ptr<ResultSet> resultSet2 = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet2, nullptr);

    std::shared_ptr<ResultSet> resultSet3 = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet2, nullptr);

    std::shared_ptr<ResultSet> resultSet4 = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet2, nullptr);

    std::shared_ptr<ResultSet> resultSet5 = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet2, nullptr);

    EXPECT_EQ(E_OK, resultSet5->GoToRow(1));

    EXPECT_EQ(E_OK, resultSet1->Close());

    EXPECT_EQ(E_OK, resultSet5->GoToRow(1));

    EXPECT_EQ(E_OK, resultSet2->Close());
    EXPECT_EQ(E_OK, resultSet3->Close());
    EXPECT_EQ(E_OK, resultSet4->Close());
    EXPECT_EQ(E_OK, resultSet5->Close());
}

/* *
 * @tc.name: testSqlStep015
 * @tc.desc: Abnormal testcase of SqlStep for QueryByStep, if sql is inValid
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep015, TestSize.Level1)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SE");
    EXPECT_NE(resultSet, nullptr);

    std::vector<std::string> columnNames;
    EXPECT_EQ(E_NOT_SELECT, resultSet->GetAllColumnNames(columnNames));

    EXPECT_EQ(E_OK, resultSet->Close());
}

/* *
 * @tc.name: testSqlStep016
 * @tc.desc: Abnormal testcase of SqlStep for GetSize, if rowPos is inValid
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep016, TestSize.Level1)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SE");
    EXPECT_NE(resultSet, nullptr);

    size_t size;
    EXPECT_EQ(E_ROW_OUT_RANGE, resultSet->GetSize(2, size));

    EXPECT_EQ(E_OK, resultSet->Close());
    EXPECT_EQ(true, resultSet->IsClosed());
}

/* *
 * @tc.name: testSqlStep017
 * @tc.desc: Abnormal testcase for build query string
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep017, TestSize.Level1)
{
    std::vector<std::string> columns = { "data1", "data2" };

    std::string outSql;
    int errCode = SqliteSqlBuilder::BuildQueryString(false, "", "", columns, "", "", "", "", 0, 0, outSql);
    EXPECT_EQ(E_EMPTY_TABLE_NAME, errCode);
}

/* *
 * @tc.name: testSqlStep018
 * @tc.desc: Abnormal testcase for build query string
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep018, TestSize.Level1)
{
    AbsRdbPredicates predicates("test");
    std::vector<std::string> columns;
    std::string logTable = "naturalbase_rdb_aux_test_log";
    std::string sqlstr;
    std::pair<bool, bool> queryStatus = {false, false};

    // logtable is empty && tableName is not empty
    queryStatus = {false, true};
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, "", queryStatus);
    EXPECT_EQ("", sqlstr);

    // logtable is empty && tableName is empty
    AbsRdbPredicates emptyPredicates("");
    std::string tableName = emptyPredicates.GetTableName();
    EXPECT_EQ("", tableName);
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(emptyPredicates, columns, "", queryStatus);
    EXPECT_EQ("", sqlstr);

    // logtable is not empty && tableName is empty
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(emptyPredicates, columns, logTable, queryStatus);
    EXPECT_EQ("", sqlstr);

    // Distinct is false, clumns is empty
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, logTable, queryStatus);
    std::string value = "SELECT test.*, naturalbase_rdb_aux_test_log.cursor, CASE "
                        "WHEN naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 "
                        "THEN true ELSE false END AS deleted_flag "
                        "FROM test INNER JOIN naturalbase_rdb_aux_test_log "
                        "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    EXPECT_EQ(value, sqlstr);

    // Distinct is true, clumns is not empty
    predicates.Distinct();
    columns.push_back("name");
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, logTable, queryStatus);
    value = "SELECT DISTINCT test.name, naturalbase_rdb_aux_test_log.cursor, CASE "
            "WHEN naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 "
            "THEN true ELSE false END AS deleted_flag "
            "FROM test INNER JOIN naturalbase_rdb_aux_test_log "
            "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    EXPECT_EQ(value, sqlstr);
}

/* *
 * @tc.name: testSqlStep019
 * @tc.desc: Abnormal testcase for build query string
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep019, TestSize.Level1)
{
    AbsRdbPredicates predicates("test");
    std::vector<std::string> columns;
    std::string logTable = "naturalbase_rdb_aux_test_log";
    std::string sqlstr;
    std::pair<bool, bool> queryStatus = {true, false};

    //Distinct is false, columns has spacial field
    queryStatus = {true, false};
    columns.push_back("name");
    columns.push_back("#_sharing_resource_field");
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, logTable, queryStatus);
    std::string value = "SELECT test.name, naturalbase_rdb_aux_test_log.sharing_resource AS sharing_resource_field"
                        " FROM test INNER JOIN naturalbase_rdb_aux_test_log "
                        "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    EXPECT_EQ(value, sqlstr);

    //Distinct is true, columns has spacial field
    predicates.Distinct();
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, logTable, queryStatus);
    value = "SELECT DISTINCT test.name, naturalbase_rdb_aux_test_log.sharing_resource AS sharing_resource_field"
            " FROM test INNER JOIN naturalbase_rdb_aux_test_log "
            "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    EXPECT_EQ(value, sqlstr);

    //Distinct is true, columns and predicates have spacial fields
    queryStatus = {true, true};
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, logTable, queryStatus);
    value = "SELECT DISTINCT test.name, naturalbase_rdb_aux_test_log.sharing_resource AS sharing_resource_field, "
            "naturalbase_rdb_aux_test_log.cursor, CASE "
            "WHEN naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 "
            "THEN true ELSE false END AS deleted_flag "
            "FROM test INNER JOIN naturalbase_rdb_aux_test_log "
            "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    EXPECT_EQ(value, sqlstr);
}

/* *
 * @tc.name: testSqlStep020
 * @tc.desc: normal testcase of SqlStep for QueryByStep, if sql is WITH
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, testSqlStep020, TestSize.Level1)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("WITH tem AS ( SELECT * FROM test) SELECT * FROM tem");
    EXPECT_NE(nullptr, resultSet);

    std::vector<std::string> allColumnNames;
    int ret = resultSet->GetAllColumnNames(allColumnNames);
    EXPECT_EQ(E_OK, ret);

    std::string columnName;
    ret = resultSet->GetColumnName(1, columnName);
    EXPECT_EQ("data1", columnName);
    EXPECT_EQ(allColumnNames[1], columnName);

    ret = resultSet->GetColumnName(2, columnName);
    EXPECT_EQ("data2", columnName);
    EXPECT_EQ(allColumnNames[2], columnName);

    ret = resultSet->GetColumnName(3, columnName);
    EXPECT_EQ("data3", columnName);
    EXPECT_EQ(allColumnNames[3], columnName);

    ret = resultSet->GetColumnName(4, columnName);
    EXPECT_EQ("data4", columnName);
    EXPECT_EQ(allColumnNames[4], columnName);

    int columnCount = 0;
    ret = resultSet->GetColumnCount(columnCount);
    EXPECT_EQ(5, columnCount);
    ret = resultSet->GetColumnName(columnCount, columnName);
    EXPECT_NE(E_OK, ret);

    EXPECT_EQ(E_OK, resultSet->Close());
}

/**
 * @tc.name: ResultSetProxy001
 * @tc.desc: Abnormal testcase of distributed ResultSetProxy, if resultSet is Empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, Abnormal_ResultSetProxy001, TestSize.Level1)
{
    int errCode = 0;
    auto resultSet = std::make_shared<OHOS::NativeRdb::ResultSetProxy>(nullptr);
    ColumnType columnType;
    errCode = resultSet->GetColumnType(1, columnType);
    EXPECT_NE(E_OK, errCode);

    std::string columnName;
    errCode = resultSet->GetColumnName(1, columnName);
    EXPECT_NE(E_OK, errCode);

    std::vector<uint8_t> blob;
    errCode = resultSet->GetBlob(1, blob);
    EXPECT_NE(E_OK, errCode);

    std::string getStringValue;
    errCode = resultSet->GetString(1, getStringValue);
    EXPECT_NE(E_OK, errCode);

    int getIntValue;
    errCode = resultSet->GetInt(1, getIntValue);
    EXPECT_NE(E_OK, errCode);

    int64_t getLongValue;
    errCode = resultSet->GetLong(1, getLongValue);
    EXPECT_NE(E_OK, errCode);

    double getDoubleValue;
    errCode = resultSet->GetDouble(1, getDoubleValue);
    EXPECT_NE(E_OK, errCode);

    bool isNull;
    errCode = resultSet->IsColumnNull(1, isNull);
    EXPECT_NE(E_OK, errCode);
}

/**
 * @tc.name: Normal_CacheResultSet002
 * @tc.desc: Normal testcase of CacheResultSet
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, Normal_CacheResultSet002, TestSize.Level1)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    OHOS::NativeRdb::ValuesBucket value1;
    value1.PutInt("id", 1);
    value1.PutString("name", std::string("zhangsan"));
    value1.PutLong("age", 18);
    value1.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    valueBuckets.push_back(value1);

    OHOS::NativeRdb::ValuesBucket value2;
    value2.PutInt("id", 2);
    value2.PutString("name", std::string("lisi"));
    value2.PutLong("age", 19);
    value2.PutBlob("blobType", std::vector<uint8_t>{ 4, 5, 6 });
    valueBuckets.push_back(value2);

    std::shared_ptr<OHOS::NativeRdb::CacheResultSet> resultSet =
        std::make_shared<CacheResultSet>(std::move(valueBuckets));
    int errCode = 0, columnIndex = 0;

    int id;
    errCode = resultSet->GetColumnIndex("id", columnIndex);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(E_OK, resultSet->GetInt(columnIndex, id));
    EXPECT_EQ(id, 1);

    std::string name;
    errCode = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(E_OK, resultSet->GetString(columnIndex, name));
    EXPECT_EQ(name, "zhangsan");

    int64_t age;
    errCode = resultSet->GetColumnIndex("age", columnIndex);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(E_OK, resultSet->GetLong(columnIndex, age));
    EXPECT_EQ(age, 18);

    std::vector<uint8_t> blob;
    errCode = resultSet->GetColumnIndex("blobType", columnIndex);
    EXPECT_EQ(errCode, E_OK);
    EXPECT_EQ(E_OK, resultSet->GetBlob(columnIndex, blob));
    EXPECT_EQ(blob.size(), 3);
}

/**
 * @tc.name: Abnormal_CacheResultSet005
 * @tc.desc: Abnormal testcase of CacheResultSet, if row_ == maxRow_ and
 *           if position is illegal, and columName is not exist.
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, Abnormal_CacheResultSet005, TestSize.Level1)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    OHOS::NativeRdb::ValuesBucket value1;
    value1.PutInt("id", 1);
    value1.PutString("name", std::string("zhangsan"));
    value1.PutLong("age", 18);
    value1.PutBlob("blobType", std::vector<uint8_t>{ 1, 2, 3 });
    valueBuckets.push_back(value1);
    std::shared_ptr<OHOS::NativeRdb::CacheResultSet> resultSet =
        std::make_shared<CacheResultSet>(std::move(valueBuckets));
    int errCode = 0, columnIndex = 0;

    // if columnName is not exist
    errCode = resultSet->GetColumnIndex("empty", columnIndex);
    EXPECT_NE(errCode, E_OK);
    // if position < 0
    errCode = resultSet->GoToRow(-1);
    EXPECT_NE(errCode, E_OK);
    //if position > maxRow_
    errCode = resultSet->GoToRow(3);
    EXPECT_NE(errCode, E_OK);
    // if row_ = maxRow_
    int id;
    errCode = resultSet->GetInt(1, id);
    EXPECT_NE(errCode, E_OK);
    // if row_ = maxRow_
    std::string name;
    errCode = resultSet->GetString(2, name);
    EXPECT_NE(errCode, E_OK);
    // if row_ = maxRow_
    int64_t age;
    errCode = resultSet->GetLong(3, age);
    EXPECT_NE(errCode, E_OK);
    // if row_ = maxRow_
    std::vector<uint8_t> blob;
    errCode = resultSet->GetBlob(4, blob);
    EXPECT_NE(errCode, E_OK);
    // if row_ = maxRow_
    RowEntity rowEntity;
    errCode = resultSet->GetRow(rowEntity);
    EXPECT_EQ(errCode, E_ERROR);
    // if row_ = maxRow_
    bool IsNull;
    errCode = resultSet->IsColumnNull(1, IsNull);
    EXPECT_EQ(errCode, E_ERROR);
    // if row_ = maxRow_
    ValueObject::Asset asset;
    errCode = resultSet->GetAsset(1, asset);
    EXPECT_EQ(errCode, E_ERROR);
    // if row_ = maxRow_
    ValueObject::Assets assets;
    errCode = resultSet->GetAssets(1, assets);
    EXPECT_EQ(errCode, E_ERROR);
    // if row_ = maxRow_
    ValueObject value;
    errCode = resultSet->Get(1, value);
    EXPECT_EQ(errCode, E_ERROR);
}

/**
 * @tc.name: Abnormal_CacheResultSet003
 * @tc.desc: Abnormal testcase of CacheResultSet, if CacheResultSet is Empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, Abnormal_CacheResultSet003, TestSize.Level1)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    // if valuebucket.size = 0
    std::shared_ptr<OHOS::NativeRdb::CacheResultSet> resultSet =
        std::make_shared<CacheResultSet>(std::move(valueBuckets));

    int errCode = 0;
    int columnIndex = 0;
    // if columnName is not exist
    errCode = resultSet->GetColumnIndex("empty", columnIndex);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex < 0
    std::string columnName;
    errCode = resultSet->GetColumnName(-1, columnName);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->GetColumnName(5, columnName);
    EXPECT_NE(errCode, E_OK);

    // if columnIndex < 0
    ColumnType columnType;
    errCode = resultSet->GetColumnType(-1, columnType);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->GetColumnType(5, columnType);
    EXPECT_NE(errCode, E_OK);

    // if columnIndex < 0
    int id;
    errCode = resultSet->GetInt(-1, id);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->GetInt(5, id);
    EXPECT_NE(errCode, E_OK);

    // if columnIndex < 0
    std::string name;
    errCode = resultSet->GetString(-1, name);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->GetString(5, name);
    EXPECT_NE(errCode, E_OK);

    // if columnIndex < 0
    int64_t age;
    errCode = resultSet->GetLong(-1, age);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->GetLong(5, age);
    EXPECT_NE(errCode, E_OK);

    // if columnIndex < 0
    double value;
    errCode = resultSet->GetDouble(-1, value);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->GetDouble(5, value);
    EXPECT_NE(errCode, E_OK);
}

/**
 * @tc.name: Abnormal_CacheResultSet004
 * @tc.desc: Abnormal testcase of CacheResultSet, if CacheResultSet is Empty
 * @tc.type: FUNC
 */
HWTEST_F(RdbStepResultSetTest, Abnormal_CacheResultSet004, TestSize.Level1)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    std::shared_ptr<OHOS::NativeRdb::CacheResultSet> resultSet =
        std::make_shared<CacheResultSet>(std::move(valueBuckets));
    int errCode = 0;
    // if columnIndex < 0
    bool isNull;
    errCode = resultSet->IsColumnNull(-1, isNull);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->IsColumnNull(5, isNull);
    EXPECT_NE(errCode, E_OK);

    // if columnIndex < 0
    ValueObject::Asset asset;
    errCode = resultSet->GetAsset(-1, asset);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->GetAsset(5, asset);
    EXPECT_NE(errCode, E_OK);

    // if columnIndex < 0
    ValueObject::Assets assets;
    errCode = resultSet->GetAssets(-1, assets);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->GetAssets(5, assets);
    EXPECT_NE(errCode, E_OK);

    // if columnIndex < 0
    ValueObject valueobject;
    errCode = resultSet->Get(-1, valueobject);
    EXPECT_NE(errCode, E_OK);
    // if columnIndex > colNames_.size
    errCode = resultSet->Get(5, valueobject);
    EXPECT_NE(errCode, E_OK);
}
} // namespace NativeRdb
} // namespace OHOS
