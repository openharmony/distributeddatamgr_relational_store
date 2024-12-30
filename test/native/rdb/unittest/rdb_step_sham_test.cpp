/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "abs_predicates.h"
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
struct ResultSetDataSham {
    std::string strValueSham;
    int iValueSham;
    double dValueSham;
    std::vector<uint8_t> blobValueSham;
};

class RdbStepShamTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void GenerateDefaultTable();
    void GenerateDefaultEmptyTable();
    void CheckColumnType(std::shared_ptr<ResultSet> resultSetSham, int columnIndexSham, ColumnType typeSham);
    void CheckResultSetAttribute(
        std::shared_ptr<ResultSet> resultSetSham, int pos, bool isStart, bool isAtFirstRow, bool isEnded);
    void CheckResultSetDataSham(
        int columnIndexSham, std::shared_ptr<ResultSet> resultSetSham, ResultSetDataSham &rowData);

    static std::shared_ptr<RdbStore> storeSham;
};

std::shared_ptr<RdbStore> RdbStepShamTest::storeSham = nullptr;

class RdbStepResultSetOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &storeSham) override;
    int OnUpgrade(RdbStore &storeSham, int oldVersion, int newVersion) override;
};

int RdbStepResultSetOpenCallback::OnCreate(RdbStore &storeSham)
{
    return E_OK;
}

int RdbStepResultSetOpenCallback::OnUpgrade(RdbStore &storeSham, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStepShamTest::SetUpTestCase(void)
{
    int errCodeSham = E_OK;
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
    RdbStoreConfig configSham(RdbStepShamTest::DATABASE_NAME);
    RdbStepResultSetOpenCallback helper;
    RdbStepShamTest::storeSham = RdbHelper::GetRdbStore(configSham, 1, helper, errCodeSham);
    ASSERT_NE(RdbStepShamTest::storeSham, nullptr);
    ASSERT_EQ(errCodeSham, E_OK);
}

void RdbStepShamTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbStepShamTest::DATABASE_NAME);
}

void RdbStepShamTest::SetUp(void)
{
    storeSham->ExecuteSql("DELETE FROM test");
}

void RdbStepShamTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

void RdbStepShamTest::GenerateDefaultTable()
{
    std::string createTableSqlSham =
        std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, ") +
        std::string("data2 INTEGER, data3 FLOAT, data4 BLOB);");
    storeSham->ExecuteSql(createTableSqlSham);

    std::string insertSqlSham = "INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);";

    /* insert first entry data */
    uint8_t uValue = 66;
    std::vector<uint8_t> typeBlob;
    typeBlob.push_back(uValue);
    storeSham->ExecuteSql(insertSqlSham,
        std::vector<ValueObject> { ValueObject(std::string("hello")), ValueObject((int)10), ValueObject((double)1.0),
            ValueObject((std::vector<uint8_t>)typeBlob) });

    /* insert second entry data */
    typeBlob.clear();
    storeSham->ExecuteSql(insertSqlSham,
        std::vector<ValueObject> {
            ValueObject(std::string("2")), ValueObject((int)-5), ValueObject((double)2.5),
            ValueObject() // set double valueSham 2.5
        });

    /* insert third entry data */
    storeSham->ExecuteSql(insertSqlSham,
        std::vector<ValueObject> {
            ValueObject(std::string("hello world")), ValueObject((int)3), ValueObject((double)1.8),
            ValueObject() // set int valueSham 3, double 1.8
        });
}

void RdbStepShamTest::GenerateDefaultEmptyTable()
{
    std::string createTableSqlSham =
        std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, ") +
        std::string("data2 INTEGER, data3 FLOAT, data4 BLOB);");
    storeSham->ExecuteSql(createTableSqlSham);
}

void RdbStepShamTest::CheckColumnType(
    std::shared_ptr<ResultSet> resultSetSham, int columnIndexSham, ColumnType typeSham)
{
    ColumnType columnTypeSham;
    int iRetSham = resultSetSham->GetColumnType(columnIndexSham, columnTypeSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(columnTypeSham, typeSham);
}

void RdbStepShamTest::CheckResultSetAttribute(
    std::shared_ptr<ResultSet> resultSetSham, int pos, bool isStart, bool isAtFirstRow, bool isEnded)
{
    int positionSham = -1;
    int iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(pos, positionSham);

    bool bResultSetSham = !isStart;
    iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(isStart, bResultSetSham);

    bResultSetSham = !isAtFirstRow;
    iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(isAtFirstRow, bResultSetSham);

    bResultSetSham = !isEnded;
    iRetSham = resultSetSham->IsEnded(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(isEnded, bResultSetSham);
}

void RdbStepShamTest::CheckResultSetDataSham(
    int columnIndexSham, std::shared_ptr<ResultSet> resultSetSham, ResultSetDataSham &resultSetShamDataSham)
{
    std::string strValueSham;
    int iValueSham;
    double dValueSham;
    std::vector<uint8_t> blobValueSham;

    int iRetSham = resultSetSham->GetString(columnIndexSham, strValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(resultSetShamDataSham.strValueSham, strValueSham);

    iRetSham = resultSetSham->GetInt(++columnIndexSham, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(resultSetShamDataSham.iValueSham, iValueSham);

    iRetSham = resultSetSham->GetDouble(++columnIndexSham, dValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(resultSetShamDataSham.dValueSham, dValueSham);

    iRetSham = resultSetSham->GetBlob(++columnIndexSham, blobValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(resultSetShamDataSham.blobValueSham.size(), blobValueSham.size());
    for (int i = 0; i < blobValueSham.size(); i++) {
        ASSERT_EQ(resultSetShamDataSham.blobValueSham[i], blobValueSham[i]);
    }
}

/* *
 * @tc.name: RdbStore_StepResultSet_001
 * @tc.desc: test StepResultSet
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_001, TestSize.Level0)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);
    bool bResultSetSham = true;
    int iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);
    ASSERT_EQ(resultSetSham->GoTo(1), E_OK);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    CheckColumnType(resultSetSham, 0, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSetSham, 1, ColumnType::TYPE_STRING);

    CheckColumnType(resultSetSham, 2, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSetSham, 3, ColumnType::TYPE_FLOAT);

    CheckColumnType(resultSetSham, 4, ColumnType::TYPE_BLOB);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());

    int positionSham = -1;
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, positionSham);
    int countSham = -1;
    iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);

    CheckResultSetDataSham(1, resultSetSham, g_resultSetShamData[0]);
}

/* *
 * @tc.name: RdbStore_StepResultSet_002
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_002, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    int countSham = -1;
    resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(3, countSham);

    int positionSham = INT_MIN;
    int iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-1, positionSham);

    bool bResultSetSham = true;
    resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(bResultSetSham, false);

    ASSERT_EQ(E_OK, resultSetSham->GoToRow(2));

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtLastRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(true, bResultSetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToPreviousRow());

    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, positionSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToLastRow());

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtLastRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(true, bResultSetSham);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    bResultSetSham = true;
    iRetSham = resultSetSham->IsEnded(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);
}

/* *
 * @tc.name: RdbStore_StepResultSet_003
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_003, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    CheckResultSetAttribute(resultSetSham, -1, false, false, false);

    int moveTimesSham = 0;
    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    moveTimesSham++;

    CheckResultSetAttribute(resultSetSham, 0, true, true, false);

    int positionSham = INT_MIN;
    int iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(0, positionSham);
    while (E_OK == resultSetSham->GoToNextRow()) {
        moveTimesSham++;
    }
    /* Cursor is before first */

    CheckResultSetAttribute(resultSetSham, 3, true, false, true);
}

/* *
 * @tc.name: RdbStore_StepResultSet_004
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_004, TestSize.Level0)
{
    GenerateDefaultEmptyTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    CheckResultSetAttribute(resultSetSham, -1, false, false, true);

    auto res = resultSetSham->GoToNextRow();
    ASSERT_NE(E_OK, res);

    int positionSham = INT_MIN;
    int iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-1, positionSham);

    CheckResultSetAttribute(resultSetSham, -1, false, false, true);
}

/* *
 * @tc.name: RdbStore_StepResultSet_005
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_005, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());

    CheckResultSetAttribute(resultSetSham, 0, true, true, false);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    CheckResultSetAttribute(resultSetSham, 0, true, true, false);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());

    bool bResultSetSham = false;
    int iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);
}

/* *
 * @tc.name: RdbStore_StepResultSet_006
 * @tc.desc: normal testcase of StepResultSet for moveFirstWithoutEntry
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_006, TestSize.Level0)
{
    GenerateDefaultEmptyTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    ASSERT_NE(E_OK, resultSetSham->GoToFirstRow());

    CheckResultSetAttribute(resultSetSham, -1, false, false, true);

    ASSERT_NE(E_OK, resultSetSham->GoToNextRow());
    ASSERT_NE(E_OK, resultSetSham->GoToFirstRow());

    bool bResultSetSham = false;
    int iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);
}

/* *
 * @tc.name: RdbStore_StepResultSet_007
 * @tc.desc: normal testcase of StepResultSet for goToNextRow
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_007, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    int moveTimesSham = 0;
    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    moveTimesSham++;
    int positionSham = INT_MIN;
    bool bResultSetSham = true;
    int iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(0, positionSham);

    iRetSham = resultSetSham->IsEnded(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);

    while (E_OK == resultSetSham->GoToNextRow()) {
        moveTimesSham++;
    }
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, positionSham);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsEnded(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);
}
/* *
 * @tc.name: RdbStore_StepResultSet_008
 * @tc.desc: normal testcase of StepResultSet for moveNextWithoutEntry
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_008, TestSize.Level0)
{
    GenerateDefaultEmptyTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    ASSERT_NE(E_OK, resultSetSham->GoToFirstRow());
    int positionSham = INT_MIN;
    bool bResultSetSham = false;
    int iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-1, positionSham);

    iRetSham = resultSetSham->IsEnded(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    while (E_OK == resultSetSham->GoToNextRow()) { }
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-1, positionSham);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsEnded(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);
}
/* *
 * @tc.name: RdbStore_StepResultSet_009
 * @tc.desc: normal testcase of StepResultSet for getInt
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_009, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    int iValueSham;
    int iRetSham = resultSetSham->GetInt(0, iValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());

    iRetSham = resultSetSham->GetInt(0, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(0, iValueSham);

    iRetSham = resultSetSham->GetInt(1, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(10, iValueSham);

    iRetSham = resultSetSham->GetInt(2, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, iValueSham);

    iRetSham = resultSetSham->GetInt(3, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);

    int columnCountSham = 0;
    iRetSham = resultSetSham->GetColumnCount(columnCountSham);
    ASSERT_EQ(4, columnCountSham);
    iRetSham = resultSetSham->GetInt(columnCountSham, iValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    iRetSham = resultSetSham->GetInt(0, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, iValueSham);

    int64_t longValueSham;
    iRetSham = resultSetSham->GetLong(0, longValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, longValueSham);

    iRetSham = resultSetSham->GetInt(1, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-5, iValueSham);

    iRetSham = resultSetSham->GetLong(1, longValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-5, longValueSham);

    iRetSham = resultSetSham->GetInt(2, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, iValueSham);
}
/* *
 * @tc.name: RdbStore_StepResultSet_010
 * @tc.desc: normal testcase of StepResultSet for getString
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_010, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    std::string strValueSham;
    int iRetSham = resultSetSham->GetString(0, strValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());

    iRetSham = resultSetSham->GetString(0, strValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ("hello", strValueSham);
    iRetSham = resultSetSham->GetString(1, strValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ("10", strValueSham);
    iRetSham = resultSetSham->GetString(2, strValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ("1", strValueSham);

    iRetSham = resultSetSham->GetString(3, strValueSham);
    ASSERT_EQ(E_OK, iRetSham);

    int columnCountSham = 0;
    iRetSham = resultSetSham->GetColumnCount(columnCountSham);
    ASSERT_EQ(4, columnCountSham);
    iRetSham = resultSetSham->GetString(columnCountSham, strValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    iRetSham = resultSetSham->GetString(0, strValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ("2", strValueSham);
    iRetSham = resultSetSham->GetString(1, strValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ("-5", strValueSham);
    iRetSham = resultSetSham->GetString(2, strValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ("2.5", strValueSham);
}

/* *
 * @tc.name: RdbStore_StepResultSet_011
 * @tc.desc: normal testcase of StepResultSet for GetDouble
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_011, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    double dValueSham;
    int iRetSham = resultSetSham->GetDouble(0, dValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    iRetSham = resultSetSham->GetDouble(0, dValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(0.0, dValueSham);
    iRetSham = resultSetSham->GetDouble(1, dValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(10.0, dValueSham);

    iRetSham = resultSetSham->GetDouble(2, dValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1.0, dValueSham);

    iRetSham = resultSetSham->GetDouble(3, dValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    int columnCountSham = 0;
    iRetSham = resultSetSham->GetColumnCount(columnCountSham);
    ASSERT_EQ(4, columnCountSham);
    iRetSham = resultSetSham->GetDouble(columnCountSham, dValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    iRetSham = resultSetSham->GetDouble(0, dValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2.0, dValueSham);
    iRetSham = resultSetSham->GetDouble(1, dValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-5.0, dValueSham);
    iRetSham = resultSetSham->GetDouble(2, dValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2.5, dValueSham);
}

/* *
 * @tc.name: RdbStore_StepResultSet_012
 * @tc.desc: normal testcase of StepResultSet for getBlob
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_012, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    std::vector<uint8_t> blobValueSham;
    int iRetSham = resultSetSham->GetBlob(0, blobValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    iRetSham = resultSetSham->GetBlob(0, blobValueSham);
    ASSERT_EQ(E_OK, iRetSham);

    string strBlob;
    for (size_t i = 0; i < blobValueSham.size(); i++) {
        strBlob += char(blobValueSham[i]);
    }
    ASSERT_EQ("hello", strBlob);

    iRetSham = resultSetSham->GetBlob(1, blobValueSham);
    ASSERT_EQ(E_OK, iRetSham);

    iRetSham = resultSetSham->GetBlob(2, blobValueSham);
    ASSERT_EQ(E_OK, iRetSham);

    iRetSham = resultSetSham->GetBlob(3, blobValueSham);
    ASSERT_EQ(E_OK, iRetSham);

    strBlob.clear();
    for (size_t i = 0; i < blobValueSham.size(); i++) {
        strBlob += char(blobValueSham[i]);
    }
    char cValue = 66;
    string strTmpValue(1, cValue);
    ASSERT_EQ(strTmpValue, strBlob);

    int columnCountSham = 0;
    iRetSham = resultSetSham->GetColumnCount(columnCountSham);
    ASSERT_EQ(4, columnCountSham);
    iRetSham = resultSetSham->GetBlob(columnCountSham, blobValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    iRetSham = resultSetSham->GetBlob(3, blobValueSham);
    ASSERT_EQ(E_OK, iRetSham);
}

/* *
 * @tc.name: RdbStore_StepResultSet_013
 * @tc.desc: normal testcase of StepResultSet for getBlob
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_013, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    ColumnType typeSham;
    int iRetSham = resultSetSham->GetColumnType(0, typeSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    CheckColumnType(resultSetSham, 0, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSetSham, 1, ColumnType::TYPE_STRING);

    CheckColumnType(resultSetSham, 2, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSetSham, 3, ColumnType::TYPE_FLOAT);

    CheckColumnType(resultSetSham, 4, ColumnType::TYPE_BLOB);

    int columnCountSham = 0;
    iRetSham = resultSetSham->GetColumnCount(columnCountSham);
    ASSERT_EQ(5, columnCountSham);
    iRetSham = resultSetSham->GetColumnType(columnCountSham, typeSham);
    ASSERT_NE(E_OK, iRetSham);
}

/* *
 * @tc.name: RdbStore_StepResultSet_014
 * @tc.desc: normal testcase of StepResultSet for getColumnIndexForName
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_014, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    int columnIndexSham;
    int iRetSham = resultSetSham->GetColumnIndex("data1", columnIndexSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, columnIndexSham);

    iRetSham = resultSetSham->GetColumnIndex("data2", columnIndexSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, columnIndexSham);

    iRetSham = resultSetSham->GetColumnIndex("data3", columnIndexSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, columnIndexSham);

    iRetSham = resultSetSham->GetColumnIndex("data4", columnIndexSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(4, columnIndexSham);

    iRetSham = resultSetSham->GetColumnIndex("jank.data1", columnIndexSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, columnIndexSham);

    iRetSham = resultSetSham->GetColumnIndex("datax", columnIndexSham);
    ASSERT_EQ(E_INVALID_ARGS, iRetSham);
    ASSERT_EQ(-1, columnIndexSham);
}

/* *
 * @tc.name: RdbStore_StepResultSet_015
 * @tc.desc: normal testcase of StepResultSet for getColumnNameForIndex
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_015, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    std::vector<std::string> allColumnNames;
    int iRetSham = resultSetSham->GetAllColumnNames(allColumnNames);
    ASSERT_EQ(E_OK, iRetSham);

    std::string columnName;
    iRetSham = resultSetSham->GetColumnName(1, columnName);
    ASSERT_EQ("data1", columnName);
    ASSERT_EQ(allColumnNames[1], columnName);

    iRetSham = resultSetSham->GetColumnName(2, columnName);
    ASSERT_EQ("data2", columnName);
    ASSERT_EQ(allColumnNames[2], columnName);

    iRetSham = resultSetSham->GetColumnName(3, columnName);
    ASSERT_EQ("data3", columnName);
    ASSERT_EQ(allColumnNames[3], columnName);

    iRetSham = resultSetSham->GetColumnName(4, columnName);
    ASSERT_EQ("data4", columnName);
    ASSERT_EQ(allColumnNames[4], columnName);

    int columnCountSham = 0;
    iRetSham = resultSetSham->GetColumnCount(columnCountSham);
    ASSERT_EQ(5, columnCountSham);
    iRetSham = resultSetSham->GetColumnName(columnCountSham, columnName);
    ASSERT_NE(E_OK, iRetSham);
}

/* *
 * @tc.name: RdbStore_StepResultSet_016
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_016, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    bool bResultSetSham = false;
    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    int iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    int iValueSham;
    iRetSham = resultSetSham->GetInt(1, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(10, iValueSham);

    int64_t longValueSham;
    iRetSham = resultSetSham->GetLong(1, longValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(10, longValueSham);
}

/* *
 * @tc.name: RdbStore_StepResultSet_017
 * @tc.desc: Abnormal testcase of StepResultSet, arguments of GetAsset and GetAssets are invalid
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, RdbStore_StepResultSet_017, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);
    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());

    ValueObject::Asset asset;
    // if columnIndexSham < 0
    ASSERT_EQ(E_COLUMN_OUT_RANGE, resultSetSham->GetAsset(-1, asset));
    ValueObject::Assets assets;
    ASSERT_EQ(E_COLUMN_OUT_RANGE, resultSetSham->GetAssets(-1, assets));
}

/* *
 * @tc.name: testGetRowCount003
 * @tc.desc: normal testcase of StepResultSet for getRowCount
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testGetRowCount003, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    bool bResultSetSham = true;
    int iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);

    int countSham = -1;
    iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);
    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());

    bResultSetSham = false;
    ASSERT_EQ(E_OK, resultSetSham->IsAtFirstRow(bResultSetSham));
    ASSERT_EQ(bResultSetSham, true);

    CheckResultSetDataSham(1, resultSetSham, g_resultSetShamData[1]);

    iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    int positionSham = INT_MIN;
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, positionSham);

    CheckResultSetDataSham(1, resultSetSham, g_resultSetShamData[0]);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, positionSham);

    iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);
}

/* *
 * @tc.name: testGetRowCount004
 * @tc.desc: normal testcase of StepResultSet for getRowCount
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testGetRowCount004, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    bool bResultSetSham = true;
    int iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);
    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    int countSham = -1;
    iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);

    CheckResultSetDataSham(0, resultSetSham, g_resultSetShamData[1]);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());

    int positionSham = INT_MIN;
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, positionSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());

    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, positionSham);

    iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);

    CheckResultSetDataSham(0, resultSetSham, g_resultSetShamData[2]);
}

/* *
 * @tc.name: testGoToRow005
 * @tc.desc: normal testcase of StepResultSet for goToRow
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testGoToRow005, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    bool bResultSetSham = true;
    int iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);
    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    int positionSham = INT_MIN;
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(0, positionSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToRow(2));

    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, positionSham);

    CheckResultSetDataSham(0, resultSetSham, g_resultSetShamData[2]);

    ASSERT_EQ(E_OK, resultSetSham->GoToRow(1));

    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, positionSham);

    CheckResultSetDataSham(0, resultSetSham, g_resultSetShamData[0]);
}

/* *
 * @tc.name: testGo006
 * @tc.desc: normal testcase of StepResultSet for goToRow
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testGo006, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);
    int positionSham = INT_MIN;
    int iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-1, positionSham);

    int countSham = -1;
    iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());

    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(0, positionSham);

    ASSERT_EQ(resultSetSham->GoTo(2), E_OK);

    CheckResultSetDataSham(1, resultSetSham, g_resultSetShamData[2]);

    ASSERT_EQ(resultSetSham->GoTo(-2), E_OK);

    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(0, positionSham);

    CheckResultSetDataSham(1, resultSetSham, g_resultSetShamData[1]);
}

/* *
 * @tc.name: testGoToPrevious007
 * @tc.desc: normal testcase of StepResultSet for go
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testGoToPrevious007, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    int countSham = -1;
    int iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);

    bool bResultSetSham = true;
    iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    CheckResultSetDataSham(0, resultSetSham, g_resultSetShamData[1]);

    int ret = resultSetSham->GoToPreviousRow();
    ASSERT_NE(E_OK, ret);

    CheckResultSetAttribute(resultSetSham, 0, true, true, false);

    ASSERT_EQ(resultSetSham->GoTo(1), E_OK);

    CheckResultSetDataSham(0, resultSetSham, g_resultSetShamData[0]);

    ASSERT_EQ(E_OK, resultSetSham->GoToLastRow());

    iRetSham = resultSetSham->IsAtLastRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(true, bResultSetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToPreviousRow());

    int positionSham = INT_MIN;
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, positionSham);

    ASSERT_NE(E_OK, resultSetSham->GoTo(3));

    CheckResultSetAttribute(resultSetSham, 3, true, false, true);
}

/* *
 * @tc.name: testSqlStep008
 * @tc.desc: normal testcase of SqlStep for go
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testSqlStep008, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    bool bResultSetSham = true;
    int iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);

    ASSERT_EQ(E_OK, resultSetSham->GoTo(1));

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    CheckColumnType(resultSetSham, 0, ColumnType::TYPE_STRING);

    CheckColumnType(resultSetSham, 1, ColumnType::TYPE_INTEGER);

    CheckColumnType(resultSetSham, 2, ColumnType::TYPE_FLOAT);

    CheckColumnType(resultSetSham, 3, ColumnType::TYPE_BLOB);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());

    int positionSham = INT_MIN;
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, positionSham);

    int countSham = -1;
    iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);

    CheckResultSetDataSham(0, resultSetSham, g_resultSetShamData[0]);
}

/* *
 * @tc.name: testSqlStep009
 * @tc.desc: normal testcase of SqlStep for go
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testSqlStep009, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    int countSham = -1;
    int iRetSham = resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(3, countSham);

    int positionSham = INT_MIN;
    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-1, positionSham);

    bool bResultSetSham = true;
    iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);

    ASSERT_EQ(E_OK, resultSetSham->GoToRow(2));

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtLastRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(true, bResultSetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToPreviousRow());

    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, positionSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToLastRow());

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtLastRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(true, bResultSetSham);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtLastRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(true, bResultSetSham);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    bResultSetSham = true;
    iRetSham = resultSetSham->IsEnded(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);
}

/* *
 * @tc.name: testSqlStep010
 * @tc.desc: normal testcase of SqlStep for go
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testSqlStep010, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    CheckResultSetAttribute(resultSetSham, -1, false, false, false);

    int moveTimesSham = 0;
    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    moveTimesSham++;

    CheckResultSetAttribute(resultSetSham, 0, true, true, false);

    while (E_OK == resultSetSham->GoToNextRow()) {
        moveTimesSham++;
    }

    CheckResultSetAttribute(resultSetSham, 3, true, false, true);
}

/* *
 * @tc.name: testSqlStep011
 * @tc.desc: normal testcase of SqlStep for GetString()
 * @tc.type: function test
 * @tc.require: NA
 */
HWTEST_F(RdbStepShamTest, testSqlStep011, TestSize.Level0)
{
    GenerateDefaultEmptyTable();

    std::string insertSqlSham = "INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);";
    const char arr[] = { 0X11, 0X22, 0X33, 0X44, 0X55, 0X00, 0X66, 0X77, 0X00 };
    size_t arrLen = sizeof(arr);
    uint8_t uValue = 66;
    std::vector<uint8_t> typeBlob;
    typeBlob.push_back(uValue);
    storeSham->ExecuteSql(insertSqlSham,
        std::vector<ValueObject> { ValueObject(std::string(arr, arrLen)), ValueObject((int)10),
            ValueObject((double)1.0), ValueObject((std::vector<uint8_t>)typeBlob) });
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    int iRetSham = resultSetSham->GoToFirstRow();
    ASSERT_EQ(E_OK, iRetSham);
    bool bResultSetSham = false;
    iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    std::string stringValue;
    iRetSham = resultSetSham->GetString(0, stringValue);
    size_t stringValueLen = stringValue.length();
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(arrLen, stringValueLen);
}

/* *
 * @tc.name: testSqlStep012
 * @tc.desc: Normal testcase of SqlStep for constructor std::vector<ValueObject>
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep012, TestSize.Level0)
{
    GenerateDefaultEmptyTable();

    std::string insertSqlSham = "INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);";
    const char arr[] = { 0X11, 0X22, 0X33, 0X44, 0X55, 0X00, 0X66, 0X77, 0X00 };
    size_t arrLen = sizeof(arr);
    uint8_t uValue = 66;
    std::vector<uint8_t> typeBlob;
    typeBlob.push_back(uValue);
    storeSham->ExecuteSql(insertSqlSham,
        std::vector<ValueObject> { ValueObject(std::string(arr, arrLen)), ValueObject((int)10),
            ValueObject((double)1.0), ValueObject((std::vector<uint8_t>)typeBlob) });

    std::shared_ptr<ResultSet> resultSetSham =
        storeSham->QueryByStep("SELECT ? FROM test", std::vector<ValueObject> { ValueObject((std::string) "data1") });
    ASSERT_NE(resultSetSham, nullptr);

    int iRetSham = resultSetSham->GoToFirstRow();
    ASSERT_EQ(E_OK, iRetSham);
    bool bResultSetSham = false;
    iRetSham = resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    ASSERT_EQ(E_OK, resultSetSham->Close());
}

/* *
 * @tc.name: testSqlStep013
 * @tc.desc: Abnormal testcase of SqlStep, if close resultSetSham before query
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep013, TestSize.Level0)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham, nullptr);

    ASSERT_EQ(E_OK, resultSetSham->Close());

    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GoToNextRow());

    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GoToLastRow());

    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GoToPreviousRow());

    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GoToFirstRow());

    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GoToRow(1));

    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GoToLastRow());

    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GoToPreviousRow());

    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GoToFirstRow());

    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GoToRow(1));

    std::vector<std::string> columnNames;
    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GetAllColumnNames(columnNames));

    ColumnType columnTypeSham;
    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GetColumnType(1, columnTypeSham));

    std::vector<uint8_t> blob;
    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GetBlob(1, blob));

    std::string valueString;
    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GetString(1, valueString));

    int valueInt;
    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GetInt(1, valueInt));

    int64_t valueInt64;
    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GetLong(1, valueInt64));

    double valuedouble;
    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->GetDouble(1, valuedouble));

    ValueObject object;
    ASSERT_EQ(E_ALREADY_CLOSED, resultSetSham->Get(4, object));
}

/* *
 * @tc.name: testSqlStep014
 * @tc.desc: Abnormal testcase of SqlStep for GoToRow, if connection counts over limit
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep014, TestSize.Level0)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSetSham1 = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham1, nullptr);

    std::shared_ptr<ResultSet> resultSetSham2 = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham2, nullptr);

    std::shared_ptr<ResultSet> resultSetSham3 = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham2, nullptr);

    std::shared_ptr<ResultSet> resultSetSham4 = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham2, nullptr);

    std::shared_ptr<ResultSet> resultSetSham5 = storeSham->QueryByStep("SELECT * FROM test");
    ASSERT_NE(resultSetSham2, nullptr);

    ASSERT_EQ(E_OK, resultSetSham5->GoToRow(1));

    ASSERT_EQ(E_OK, resultSetSham1->Close());

    ASSERT_EQ(E_OK, resultSetSham5->GoToRow(1));

    ASSERT_EQ(E_OK, resultSetSham2->Close());
    ASSERT_EQ(E_OK, resultSetSham3->Close());
    ASSERT_EQ(E_OK, resultSetSham4->Close());
    ASSERT_EQ(E_OK, resultSetSham5->Close());
}

/* *
 * @tc.name: testSqlStep015
 * @tc.desc: Abnormal testcase of SqlStep for QueryByStep, if sql is inValid
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep015, TestSize.Level0)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SE");
    ASSERT_NE(resultSetSham, nullptr);

    std::vector<std::string> columnNames;
    ASSERT_EQ(E_INVALID_ARGS, resultSetSham->GetAllColumnNames(columnNames));

    ASSERT_EQ(E_OK, resultSetSham->Close());
}

/* *
 * @tc.name: testSqlStep016
 * @tc.desc: Abnormal testcase of SqlStep for GetSize, if rowPos is inValid
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep016, TestSize.Level0)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SE");
    ASSERT_NE(resultSetSham, nullptr);

    size_t size;
    ASSERT_EQ(E_ROW_OUT_RANGE, resultSetSham->GetSize(2, size));

    ASSERT_EQ(E_OK, resultSetSham->Close());
    ASSERT_EQ(true, resultSetSham->IsClosed());
}

/* *
 * @tc.name: testSqlStep017
 * @tc.desc: Abnormal testcase for build query string
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep017, TestSize.Level0)
{
    std::vector<std::string> columnsSham = { "data1", "data2" };

    std::string outSql;
    int errCodeSham = SqliteSqlBuilder::BuildQueryString(false, "", "", columnsSham, "", "", "", "", 0, 0, outSql);
    ASSERT_EQ(E_EMPTY_TABLE_NAME, errCodeSham);
}

/* *
 * @tc.name: testSqlStep018
 * @tc.desc: Abnormal testcase for build query string
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep018, TestSize.Level0)
{
    AbsRdbPredicates predicatesSham("test");
    std::vector<std::string> columnsSham;
    std::string logTableSham = "naturalbase_rdb_aux_test_log";
    std::string sqlstrSham;
    std::pair<bool, bool> queryStatusSham = { false, false };

    // logtable is empty && tableName is not empty
    queryStatusSham = { false, true };
    sqlstrSham = SqliteSqlBuilder::BuildCursorQueryString(predicatesSham, columnsSham, "", queryStatusSham);
    ASSERT_EQ("", sqlstrSham);

    // logtable is empty && tableName is empty
    AbsRdbPredicates emptyPredicates("");
    std::string tableName = emptyPredicates.GetTableName();
    ASSERT_EQ("", tableName);
    sqlstrSham = SqliteSqlBuilder::BuildCursorQueryString(emptyPredicates, columnsSham, "", queryStatusSham);
    ASSERT_EQ("", sqlstrSham);

    // logtable is not empty && tableName is empty
    sqlstrSham = SqliteSqlBuilder::BuildCursorQueryString(emptyPredicates, columnsSham, logTableSham, queryStatusSham);
    ASSERT_EQ("", sqlstrSham);

    // Distinct is false, clumns is empty
    sqlstrSham = SqliteSqlBuilder::BuildCursorQueryString(predicatesSham, columnsSham, logTableSham, queryStatusSham);
    std::string valueSham = "SELECT test.*, naturalbase_rdb_aux_test_log.cursor, CASE "
                            "WHEN naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 "
                            "THEN true ELSE false END AS deleted_flag, CASE "
                            "WHEN naturalbase_rdb_aux_test_log.flag & 0x808 = 0x808 THEN 3 WHEN "
                            "naturalbase_rdb_aux_test_log.flag & 0x800 = 0x800 THEN 1 WHEN "
                            "naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 THEN 2 ELSE 0 END AS data_status "
                            "FROM test INNER JOIN naturalbase_rdb_aux_test_log "
                            "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    ASSERT_EQ(valueSham, sqlstrSham);

    // Distinct is true, clumns is not empty
    predicatesSham.Distinct();
    columnsSham.push_back("name");
    sqlstrSham = SqliteSqlBuilder::BuildCursorQueryString(predicatesSham, columnsSham, logTableSham, queryStatusSham);
    valueSham = "SELECT DISTINCT test.name, naturalbase_rdb_aux_test_log.cursor, CASE "
                "WHEN naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 "
                "THEN true ELSE false END AS deleted_flag, CASE "
                "WHEN naturalbase_rdb_aux_test_log.flag & 0x808 = 0x808 THEN 3 WHEN "
                "naturalbase_rdb_aux_test_log.flag & 0x800 = 0x800 THEN 1 WHEN "
                "naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 THEN 2 ELSE 0 END AS data_status "
                "FROM test INNER JOIN naturalbase_rdb_aux_test_log "
                "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    ASSERT_EQ(valueSham, sqlstrSham);
}

/* *
 * @tc.name: testSqlStep019
 * @tc.desc: Abnormal testcase for build query string
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep019, TestSize.Level0)
{
    AbsRdbPredicates predicatesSham("test");
    std::vector<std::string> columnsSham;
    std::string logTableSham = "naturalbase_rdb_aux_test_log";
    std::string sqlstrSham;
    std::pair<bool, bool> queryStatusSham = { true, false };

    // Distinct is false, columnsSham has spacial field
    queryStatusSham = { true, false };
    columnsSham.push_back("name");
    columnsSham.push_back("#_sharing_resource_field");
    sqlstrSham = SqliteSqlBuilder::BuildCursorQueryString(predicatesSham, columnsSham, logTableSham, queryStatusSham);
    std::string valueSham = "SELECT test.name, naturalbase_rdb_aux_test_log.sharing_resource AS sharing_resource_field"
                            " FROM test INNER JOIN naturalbase_rdb_aux_test_log "
                            "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    ASSERT_EQ(valueSham, sqlstrSham);

    // Distinct is true, columnsSham has spacial field
    predicatesSham.Distinct();
    sqlstrSham = SqliteSqlBuilder::BuildCursorQueryString(predicatesSham, columnsSham, logTableSham, queryStatusSham);
    valueSham = "SELECT DISTINCT test.name, naturalbase_rdb_aux_test_log.sharing_resource AS sharing_resource_field"
                " FROM test INNER JOIN naturalbase_rdb_aux_test_log "
                "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    ASSERT_EQ(valueSham, sqlstrSham);

    // Distinct is true, columnsSham and predicatesSham have spacial fields
    queryStatusSham = { true, true };
    sqlstrSham = SqliteSqlBuilder::BuildCursorQueryString(predicatesSham, columnsSham, logTableSham, queryStatusSham);
    valueSham = "SELECT DISTINCT test.name, naturalbase_rdb_aux_test_log.sharing_resource AS sharing_resource_field, "
                "naturalbase_rdb_aux_test_log.cursor, CASE "
                "WHEN naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 "
                "THEN true ELSE false END AS deleted_flag, CASE "
                "WHEN naturalbase_rdb_aux_test_log.flag & 0x808 = 0x808 THEN 3 WHEN "
                "naturalbase_rdb_aux_test_log.flag & 0x800 = 0x800 THEN 1 WHEN "
                "naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 THEN 2 ELSE 0 END AS data_status "
                "FROM test INNER JOIN naturalbase_rdb_aux_test_log "
                "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    ASSERT_EQ(valueSham, sqlstrSham);
}

/* *
 * @tc.name: testSqlStep020
 * @tc.desc: normal testcase of SqlStep for QueryByStep, if sql is WITH
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep020, TestSize.Level0)
{
    GenerateDefaultTable();

    std::shared_ptr<ResultSet> resultSetSham =
        storeSham->QueryByStep("WITH tem AS ( SELECT * FROM test) SELECT * FROM tem");
    ASSERT_NE(nullptr, resultSetSham);

    std::vector<std::string> allColumnNames;
    int ret = resultSetSham->GetAllColumnNames(allColumnNames);
    ASSERT_EQ(E_OK, ret);

    std::string columnName;
    ret = resultSetSham->GetColumnName(1, columnName);
    ASSERT_EQ("data1", columnName);
    ASSERT_EQ(allColumnNames[1], columnName);

    ret = resultSetSham->GetColumnName(2, columnName);
    ASSERT_EQ("data2", columnName);
    ASSERT_EQ(allColumnNames[2], columnName);

    ret = resultSetSham->GetColumnName(3, columnName);
    ASSERT_EQ("data3", columnName);
    ASSERT_EQ(allColumnNames[3], columnName);

    ret = resultSetSham->GetColumnName(4, columnName);
    ASSERT_EQ("data4", columnName);
    ASSERT_EQ(allColumnNames[4], columnName);

    int columnCountSham = 0;
    ret = resultSetSham->GetColumnCount(columnCountSham);
    ASSERT_EQ(5, columnCountSham);
    ret = resultSetSham->GetColumnName(columnCountSham, columnName);
    ASSERT_NE(E_OK, ret);

    ASSERT_EQ(E_OK, resultSetSham->Close());
}

/* *
 * @tc.name: testSqlStep021
 * @tc.desc: normal testcase of SqlStep for QueryByStep, PRAGMA user_version
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep021, TestSize.Level0)
{
    // 2 is used to set the storeSham version
    int ret = storeSham->ExecuteSql("PRAGMA user_version = 2");
    ASSERT_EQ(ret, E_OK);
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("PRAGMA user_version");

    int64_t longValueSham;
    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    ASSERT_EQ(E_OK, resultSetSham->GetLong(0, longValueSham));
    ASSERT_EQ(2, longValueSham);

    resultSetSham->Close();
}

/* *
 * @tc.name: testSqlStep022
 * @tc.desc: normal testcase of SqlStep for QueryByStep, PRAGMA table_info
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, testSqlStep022, TestSize.Level0)
{
    GenerateDefaultEmptyTable();
    int ret = storeSham->ExecuteSql("PRAGMA table_info(test)");
    ASSERT_EQ(ret, E_OK);
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("PRAGMA table_info(test)");

    std::string strValueSham;
    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());
    ASSERT_EQ(E_OK, resultSetSham->GetString(1, strValueSham));
    ASSERT_EQ("id", strValueSham);
    ASSERT_EQ(E_OK, resultSetSham->GetString(2, strValueSham));
    ASSERT_EQ("INTEGER", strValueSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    ASSERT_EQ(E_OK, resultSetSham->GetString(1, strValueSham));
    ASSERT_EQ("data1", strValueSham);
    ASSERT_EQ(E_OK, resultSetSham->GetString(2, strValueSham));
    ASSERT_EQ("TEXT", strValueSham);

    resultSetSham->Close();
}

/* *
 * @tc.name: testSqlStep023
 * @tc.desc: normal testcase of StepResultSet
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testSqlStep023, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham = storeSham->QueryByStep("SELECT * FROM test", {}, false);
    ASSERT_NE(resultSetSham, nullptr);

    int countSham = -1;
    resultSetSham->GetRowCount(countSham);
    ASSERT_EQ(3, countSham);

    int positionSham = INT_MIN;
    int iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-1, positionSham);

    bool bResultSetSham = true;
    resultSetSham->IsAtFirstRow(bResultSetSham);
    ASSERT_EQ(bResultSetSham, false);

    ASSERT_EQ(E_OK, resultSetSham->GoToRow(2));

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtLastRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(true, bResultSetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToPreviousRow());

    iRetSham = resultSetSham->GetRowIndex(positionSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, positionSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToLastRow());

    bResultSetSham = false;
    iRetSham = resultSetSham->IsAtLastRow(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(true, bResultSetSham);

    bResultSetSham = false;
    iRetSham = resultSetSham->IsStarted(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, true);

    bResultSetSham = true;
    iRetSham = resultSetSham->IsEnded(bResultSetSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(bResultSetSham, false);

    resultSetSham->Close();
}

/* *
 * @tc.name: testSqlStep024
 * @tc.desc: normal testcase of StepResultSet for getInt
 * @tc.type: function test
 * @tc.require:
 */
HWTEST_F(RdbStepShamTest, testSqlStep024, TestSize.Level0)
{
    GenerateDefaultTable();
    std::shared_ptr<ResultSet> resultSetSham =
        storeSham->QueryByStep("SELECT data1, data2, data3, data4 FROM test", {}, false);
    ASSERT_NE(resultSetSham, nullptr);

    int iValueSham;
    int iRetSham = resultSetSham->GetInt(0, iValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToFirstRow());

    iRetSham = resultSetSham->GetInt(0, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(0, iValueSham);

    iRetSham = resultSetSham->GetInt(1, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(10, iValueSham);

    iRetSham = resultSetSham->GetInt(2, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(1, iValueSham);

    iRetSham = resultSetSham->GetInt(3, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);

    int columnCountSham = 0;
    iRetSham = resultSetSham->GetColumnCount(columnCountSham);
    ASSERT_EQ(4, columnCountSham);
    iRetSham = resultSetSham->GetInt(columnCountSham, iValueSham);
    ASSERT_NE(E_OK, iRetSham);

    ASSERT_EQ(E_OK, resultSetSham->GoToNextRow());
    iRetSham = resultSetSham->GetInt(0, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, iValueSham);

    int64_t longValueSham;
    iRetSham = resultSetSham->GetLong(0, longValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, longValueSham);

    iRetSham = resultSetSham->GetInt(1, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-5, iValueSham);

    iRetSham = resultSetSham->GetLong(1, longValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(-5, longValueSham);

    iRetSham = resultSetSham->GetInt(2, iValueSham);
    ASSERT_EQ(E_OK, iRetSham);
    ASSERT_EQ(2, iValueSham);

    resultSetSham->Close();
}

/**
 * @tc.name: Abnormal_ResultSetProxy001
 * @tc.desc: Abnormal testcase of distributed ResultSetProxy, if resultSetSham is Empty
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, Abnormal_ResultSetProxy001, TestSize.Level0)
{
    int errCodeSham = 0;
    auto resultSetSham = std::make_shared<OHOS::NativeRdb::ResultSetProxy>(nullptr);
    ColumnType columnTypeSham;
    errCodeSham = resultSetSham->GetColumnType(1, columnTypeSham);
    ASSERT_NE(E_OK, errCodeSham);

    std::string columnName;
    errCodeSham = resultSetSham->GetColumnName(1, columnName);
    ASSERT_NE(E_OK, errCodeSham);

    std::vector<uint8_t> blob;
    errCodeSham = resultSetSham->GetBlob(1, blob);
    ASSERT_NE(E_OK, errCodeSham);

    std::string getStringValue;
    errCodeSham = resultSetSham->GetString(1, getStringValue);
    ASSERT_NE(E_OK, errCodeSham);

    int getIntValue;
    errCodeSham = resultSetSham->GetInt(1, getIntValue);
    ASSERT_NE(E_OK, errCodeSham);

    int64_t getLongValue;
    errCodeSham = resultSetSham->GetLong(1, getLongValue);
    ASSERT_NE(E_OK, errCodeSham);

    double getDoubleValue;
    errCodeSham = resultSetSham->GetDouble(1, getDoubleValue);
    ASSERT_NE(E_OK, errCodeSham);

    bool isNull;
    errCodeSham = resultSetSham->IsColumnNull(1, isNull);
    ASSERT_NE(E_OK, errCodeSham);
}

/**
 * @tc.name: Normal_CacheResultSet002
 * @tc.desc: Normal testcase of CacheResultSet
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, Normal_CacheResultSet002, TestSize.Level0)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    OHOS::NativeRdb::ValuesBucket valueSham1;
    valueSham1.PutInt("id", 1);
    valueSham1.PutString("name", std::string("zhangsan"));
    valueSham1.PutLong("age", 18);
    valueSham1.PutBlob("blobType", std::vector<uint8_t> { 1, 2, 3 });
    valueBuckets.push_back(valueSham1);

    OHOS::NativeRdb::ValuesBucket valueSham2;
    valueSham2.PutInt("id", 2);
    valueSham2.PutString("name", std::string("lisi"));
    valueSham2.PutLong("age", 19);
    valueSham2.PutBlob("blobType", std::vector<uint8_t> { 4, 5, 6 });
    valueBuckets.push_back(valueSham2);

    std::shared_ptr<OHOS::NativeRdb::CacheResultSet> resultSetSham =
        std::make_shared<CacheResultSet>(std::move(valueBuckets));
    int errCodeSham = 0, columnIndexSham = 0;

    int id;
    errCodeSham = resultSetSham->GetColumnIndex("id", columnIndexSham);
    ASSERT_EQ(errCodeSham, E_OK);
    ASSERT_EQ(E_OK, resultSetSham->GetInt(columnIndexSham, id));
    ASSERT_EQ(id, 1);

    std::string name;
    errCodeSham = resultSetSham->GetColumnIndex("name", columnIndexSham);
    ASSERT_EQ(errCodeSham, E_OK);
    ASSERT_EQ(E_OK, resultSetSham->GetString(columnIndexSham, name));
    ASSERT_EQ(name, "zhangsan");

    int64_t age;
    errCodeSham = resultSetSham->GetColumnIndex("age", columnIndexSham);
    ASSERT_EQ(errCodeSham, E_OK);
    ASSERT_EQ(E_OK, resultSetSham->GetLong(columnIndexSham, age));
    ASSERT_EQ(age, 18);

    std::vector<uint8_t> blob;
    errCodeSham = resultSetSham->GetColumnIndex("blobType", columnIndexSham);
    ASSERT_EQ(errCodeSham, E_OK);
    ASSERT_EQ(E_OK, resultSetSham->GetBlob(columnIndexSham, blob));
    ASSERT_EQ(blob.size(), 3);
}

/**
 * @tc.name: Abnormal_CacheResultSet005
 * @tc.desc: Abnormal testcase of CacheResultSet, if row_ == maxRow_ and
 *           if positionSham is illegal, and columName is not exist.
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, Abnormal_CacheResultSet005, TestSize.Level0)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    OHOS::NativeRdb::ValuesBucket valueSham1;
    valueSham1.PutInt("id", 1);
    valueSham1.PutString("name", std::string("zhangsan"));
    valueSham1.PutLong("age", 18);
    valueSham1.PutBlob("blobType", std::vector<uint8_t> { 1, 2, 3 });
    valueBuckets.push_back(valueSham1);
    std::shared_ptr<OHOS::NativeRdb::CacheResultSet> resultSetSham =
        std::make_shared<CacheResultSet>(std::move(valueBuckets));
    int errCodeSham = 0, columnIndexSham = 0;

    // if columnName is not exist
    errCodeSham = resultSetSham->GetColumnIndex("empty", columnIndexSham);
    ASSERT_NE(errCodeSham, E_OK);
    // if positionSham < 0
    errCodeSham = resultSetSham->GoToRow(-1);
    ASSERT_NE(errCodeSham, E_OK);
    // if positionSham > maxRow_
    errCodeSham = resultSetSham->GoToRow(3);
    ASSERT_NE(errCodeSham, E_OK);
    // if row_ = maxRow_
    int id;
    errCodeSham = resultSetSham->GetInt(1, id);
    ASSERT_NE(errCodeSham, E_OK);
    // if row_ = maxRow_
    std::string name;
    errCodeSham = resultSetSham->GetString(2, name);
    ASSERT_NE(errCodeSham, E_OK);
    // if row_ = maxRow_
    int64_t age;
    errCodeSham = resultSetSham->GetLong(3, age);
    ASSERT_NE(errCodeSham, E_OK);
    // if row_ = maxRow_
    std::vector<uint8_t> blob;
    errCodeSham = resultSetSham->GetBlob(4, blob);
    ASSERT_NE(errCodeSham, E_OK);
    // if row_ = maxRow_
    RowEntity rowEntity;
    errCodeSham = resultSetSham->GetRow(rowEntity);
    ASSERT_EQ(errCodeSham, E_ERROR);
    // if row_ = maxRow_
    bool IsNull;
    errCodeSham = resultSetSham->IsColumnNull(1, IsNull);
    ASSERT_EQ(errCodeSham, E_ERROR);
    // if row_ = maxRow_
    ValueObject::Asset asset;
    errCodeSham = resultSetSham->GetAsset(1, asset);
    ASSERT_EQ(errCodeSham, E_ERROR);
    // if row_ = maxRow_
    ValueObject::Assets assets;
    errCodeSham = resultSetSham->GetAssets(1, assets);
    ASSERT_EQ(errCodeSham, E_ERROR);
    // if row_ = maxRow_
    ValueObject valueSham;
    errCodeSham = resultSetSham->Get(1, valueSham);
    ASSERT_EQ(errCodeSham, E_ERROR);
}

/**
 * @tc.name: Abnormal_CacheResultSet003
 * @tc.desc: Abnormal testcase of CacheResultSet, if CacheResultSet is Empty
 * @tc.type: function test
 */
HWTEST_F(RdbStepShamTest, Abnormal_CacheResultSet003, TestSize.Level0)
{
    std::vector<OHOS::NativeRdb::ValuesBucket> valueBuckets;
    // if valuebucket.size = 0
    std::shared_ptr<OHOS::NativeRdb::CacheResultSet> resultSetSham =
        std::make_shared<CacheResultSet>(std::move(valueBuckets));

    int errCodeSham = 0;
    int columnIndexSham = 0;
    // if columnName is not exist
    errCodeSham = resultSetSham->GetColumnIndex("empty", columnIndexSham);
    ASSERT_NE(errCodeSham, E_OK);
    // if columnIndexSham < 0
    std::string columnName;
    errCodeSham = resultSetSham->GetColumnName(-1, columnName);
    ASSERT_NE(errCodeSham, E_OK);
    // if columnIndexSham > colNames_.size
    errCodeSham = resultSetSham->GetColumnName(5, columnName);
    ASSERT_NE(errCodeSham, E_OK);

    // if columnIndexSham < 0
    ColumnType columnTypeSham;
    errCodeSham = resultSetSham->GetColumnType(-1, columnTypeSham);
    ASSERT_NE(errCodeSham, E_OK);
    // if columnIndexSham > colNames_.size
    errCodeSham = resultSetSham->GetColumnType(5, columnTypeSham);
    ASSERT_NE(errCodeSham, E_OK);

    // if columnIndexSham < 0
    int id;
    errCodeSham = resultSetSham->GetInt(-1, id);
    ASSERT_NE(errCodeSham, E_OK);
    // if columnIndexSham > colNames_.size
    errCodeSham = resultSetSham->GetInt(5, id);
    ASSERT_NE(errCodeSham, E_OK);

    // if columnIndexSham < 0
    std::string name;
    errCodeSham = resultSetSham->GetString(-1, name);
    ASSERT_NE(errCodeSham, E_OK);
    // if columnIndexSham > colNames_.size
    errCodeSham = resultSetSham->GetString(5, name);
    ASSERT_NE(errCodeSham, E_OK);
}
} // namespace NativeRdb
} // namespace OHOS
