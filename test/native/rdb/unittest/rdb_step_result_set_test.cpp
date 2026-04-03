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
    std::string createTableSql =
        "CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, data2 INTEGER, data3 FLOAT, data4 BLOB, "
        "data5 ASSET, data6 ASSETS, data7 floatvector(128), data8 UNLIMITED INT);";
    store->ExecuteSql(createTableSql);

    std::string insertSql = "INSERT INTO test (data1, data2, data3, data4, data5, data6, data7, data8) VALUES "
                            "(?, ?, ?, ?, ?, ?, ?, ?);";
    /* insert first entry data */
    AssetValue asset {
        .version = 0,
        .name = "123",
        .uri = "my test path",
        .createTime = "12",
        .modifyTime = "12",
    };
    vector<AssetValue> assets;
    assets.push_back(asset);
    std::vector<ValueObject> args;
    args.push_back("hello");
    args.push_back(10); // set int value 10
    args.push_back(1.0);
    args.push_back(std::vector<uint8_t>(1, 66)); // set uint8_t value 66
    args.push_back(asset);
    args.push_back(assets);
    args.push_back(std::vector<float>(1, 0.5)); // set float value 0.5
    args.push_back(BigInteger(0));
    store->ExecuteSql(insertSql, args);

    /* insert second entry data */
    args.clear();
    args.push_back("2");
    args.push_back(-5); // set int value -5
    args.push_back(2.5); // set float value 2.5
    args.push_back(ValueObject());
    args.push_back(asset);
    args.push_back(assets);
    args.push_back(std::vector<float>(1, 0.5)); // set float value 0.5
    args.push_back(BigInteger(0));
    store->ExecuteSql(insertSql, args);

    /* insert third entry data */
    args.clear();
    args.push_back("hello world");
    args.push_back(3); // set int value 3
    args.push_back(1.8); // set float value 1.8
    args.push_back(ValueObject());
    args.push_back(asset);
    args.push_back(assets);
    args.push_back(std::vector<float>(1, 0.5)); // set float value 0.5
    args.push_back(BigInteger(0));
    store->ExecuteSql(insertSql, args);
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
    std::pair<bool, bool> queryStatus = { false, false };

    // logtable is empty && tableName is not empty
    queryStatus = { false, true };
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
                        "THEN true ELSE false END AS deleted_flag, CASE "
                        "WHEN naturalbase_rdb_aux_test_log.flag & 0x808 = 0x808 THEN 3 WHEN "
                        "naturalbase_rdb_aux_test_log.flag & 0x800 = 0x800 THEN 1 WHEN "
                        "naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 THEN 2 ELSE 0 END AS data_status "
                        "FROM test INNER JOIN naturalbase_rdb_aux_test_log "
                        "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    EXPECT_EQ(value, sqlstr);

    // Distinct is true, clumns is not empty
    predicates.Distinct();
    columns.push_back("name");
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, logTable, queryStatus);
    value = "SELECT DISTINCT test.name, naturalbase_rdb_aux_test_log.cursor, CASE "
            "WHEN naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 "
            "THEN true ELSE false END AS deleted_flag, CASE "
            "WHEN naturalbase_rdb_aux_test_log.flag & 0x808 = 0x808 THEN 3 WHEN "
            "naturalbase_rdb_aux_test_log.flag & 0x800 = 0x800 THEN 1 WHEN "
            "naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 THEN 2 ELSE 0 END AS data_status "
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
    std::pair<bool, bool> queryStatus = { true, false };

    //Distinct is false, columns has spacial field
    queryStatus = { true, false };
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
    queryStatus = { true, true };
    sqlstr = SqliteSqlBuilder::BuildCursorQueryString(predicates, columns, logTable, queryStatus);
    value = "SELECT DISTINCT test.name, naturalbase_rdb_aux_test_log.sharing_resource AS sharing_resource_field, "
            "naturalbase_rdb_aux_test_log.cursor, CASE "
            "WHEN naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 "
            "THEN true ELSE false END AS deleted_flag, CASE "
            "WHEN naturalbase_rdb_aux_test_log.flag & 0x808 = 0x808 THEN 3 WHEN "
            "naturalbase_rdb_aux_test_log.flag & 0x800 = 0x800 THEN 1 WHEN "
            "naturalbase_rdb_aux_test_log.flag & 0x8 = 0x8 THEN 2 ELSE 0 END AS data_status "
            "FROM test INNER JOIN naturalbase_rdb_aux_test_log "
            "ON test.ROWID = naturalbase_rdb_aux_test_log.data_key";
    EXPECT_EQ(value, sqlstr);
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
} // namespace NativeRdb
} // namespace OHOS
