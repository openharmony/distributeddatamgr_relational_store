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

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "big_integer.h"
#include "cache_result_set.h"
#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "result_set.h"
#include "value_object.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using Asset = ValueObject::Asset;
using Assets = ValueObject::Assets;
using FloatVector = ValueObject::FloatVector;
using BigInt = ValueObject::BigInt;

class DuplicateColumnDataTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    void GenerateData1() const;
    void GenerateData2() const;

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
};

class DuplicateColumnDataOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
    static const std::string CREATE_TABLE_TEST1;
    static const std::string CREATE_TABLE_TEST2;
};

const std::string DuplicateColumnDataTest::DATABASE_NAME = RDB_TEST_PATH + "duplicateColumnData1.db";
std::shared_ptr<RdbStore> DuplicateColumnDataTest::store = nullptr;
std::string const DuplicateColumnDataOpenCallback::CREATE_TABLE_TEST1 = "CREATE TABLE test1 (id INTEGER PRIMARY KEY "
    "AUTOINCREMENT, name TEXT, age INTEGER, salary FLOAT, blobType BLOB, data1 ASSET, data2 ASSETS, "
    "data3 floatvector(128), data4 UNLIMITED INT);";
std::string const DuplicateColumnDataOpenCallback::CREATE_TABLE_TEST2 = "CREATE TABLE test2 (id INTEGER PRIMARY KEY "
    "AUTOINCREMENT, name TEXT, age INTEGER, salary FLOAT, blobType BLOB, data1 ASSET, data2 ASSETS, "
    "data3 floatvector(128), data4 UNLIMITED INT);";

int DuplicateColumnDataOpenCallback::OnCreate(RdbStore &rdbStore)
{
    int errCode = rdbStore.ExecuteSql(CREATE_TABLE_TEST1);
    if (errCode != E_OK) {
        return errCode;
    }
    return rdbStore.ExecuteSql(CREATE_TABLE_TEST2);
}

int DuplicateColumnDataOpenCallback::OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion)
{
    (void) oldVersion;
    (void) newVersion;
    return E_OK;
}

void DuplicateColumnDataTest::SetUpTestCase(void)
{
    RdbStoreConfig config(DATABASE_NAME);
    DuplicateColumnDataOpenCallback helper;
    int errCode = E_ERROR;
    store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_EQ(errCode, E_OK);
    ASSERT_NE(store, nullptr);
}

void DuplicateColumnDataTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(DATABASE_NAME);
}

void DuplicateColumnDataTest::SetUp()
{
    store->ExecuteSql("DELETE FROM test1");
    store->ExecuteSql("DELETE FROM test2");
}

void DuplicateColumnDataTest::TearDown()
{
}

void DuplicateColumnDataTest::GenerateData1() const
{
    int64_t id;
    ValuesBucket values;
    AssetValue asset {
        .version = 0,
        .name = "123",
        .uri = "my test path",
        .createTime = "12",
        .modifyTime = "12",
    };
    vector<AssetValue> assets;
    assets.push_back(asset);

    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 10); // set int value 10
    values.PutDouble("salary", 2000.56); // set double value 2000.56
    values.PutBlob("blobType", std::vector<uint8_t>{1, 2, 3}); // set uint8_t value {1, 2, 3}
    values.Put("data1", asset);
    values.Put("data2", assets);
    values.Put("data3", std::vector<float>{1, 0.5}); // set float value {1, 0.5}
    values.Put("data4", BigInteger(100)); // set bigint value 100
    store->Insert(id, "test1", values);

    values.Clear();
    values.PutInt("id", 2); // set int value 2
    values.PutString("name", std::string("sss"));
    values.PutInt("age", 50);     // set int value 50
    values.PutDouble("salary", 2.5); // set float value 2.5
    values.PutBlob("blobType", std::vector<uint8_t>{});
    store->Insert(id, "test1", values);
}

void DuplicateColumnDataTest::GenerateData2() const
{
    int64_t id;
    ValuesBucket values;
    AssetValue asset {
        .version = 0,
        .name = "456",
        .uri = "my path",
        .createTime = "56",
        .modifyTime = "89",
    };
    vector<AssetValue> assets;
    assets.push_back(asset);

    values.PutInt("id", 1);
    values.PutString("name", std::string("lisi"));
    values.PutInt("age", 10); // set int value 10
    values.PutDouble("salary", 2001.56); // set double value 2001.56
    values.PutBlob("blobType", std::vector<uint8_t>{3, 4, 5}); // set uint8_t value {1, 2, 3}
    values.Put("data1", asset);
    values.Put("data2", assets);
    values.Put("data3", std::vector<float>{1, 1.5}); // set float value {1, 1.5}
    values.Put("data4", BigInteger(200)); // set bigint value 200
    store->Insert(id, "test2", values);

    values.Clear();
    values.PutInt("id", 2); // set int value 2
    values.PutString("name", std::string("kkk"));
    values.PutInt("age", 60);     // set int value 60
    values.PutDouble("salary", 3.5); // set float value 3.5
    values.PutBlob("blobType", std::vector<uint8_t>{});
    store->Insert(id, "test2", values);
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetWholeColumnNames_001
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetWholeColumnNames.
 *           1. query all fields
 *           2. get all fileds in order
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetWholeColumnNames_001, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet = store->QuerySql(
        "SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_OK);

    EXPECT_EQ(columnNames.size(), 18); // columnsSize is 18

    std::vector<std::string> columnNamesTemp{"id", "name", "age", "salary", "blobType", "data1", "data2",
        "data3", "data4", "id", "name", "age", "salary", "blobType", "data1", "data2", "data3", "data4"};
    EXPECT_EQ(columnNames, columnNamesTemp);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetWholeColumnNames_002
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetWholeColumnNames.
 *           1. query some fields
 *           2. get some fileds in order
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetWholeColumnNames_002, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::string const sql = "SELECT t1.data1, t2.data1, t1.age, t2.age, t1.name, t2.name FROM test1 t1 LEFT JOIN "
        "test2 t2 ON t1.age=t2.age";
    std::shared_ptr<ResultSet> resultSet = store->QuerySql(sql);
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_OK);

    EXPECT_EQ(columnNames.size(), 6); // columnsSize is 6

    std::vector<std::string> columnNamesTemp{"data1", "data1", "age", "age", "name", "name"};
    EXPECT_EQ(columnNames, columnNamesTemp);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetWholeColumnNames_003
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetWholeColumnNames.
 *           1. SQL length less than or equal to 3
 *           2. execute GetWholeColumnNames
 *           3. return E_INVALID_ARGS
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetWholeColumnNames_003, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();

    resultSet = store->QuerySql("SEL");
    ASSERT_NE(resultSet, nullptr);

    std::tie(ret, columnNames) = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetWholeColumnNames_004
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetWholeColumnNames.
 *           1. incomplete SQL statement
 *           2. execute GetWholeColumnNames
 *           3. return E_SQLITE_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetWholeColumnNames_004, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_SQLITE_ERROR);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetWholeColumnNames_005
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetWholeColumnNames.
 *           1. query some fields
 *           2. resultSet close
 *           3. return E_ALREADY_CLOSED
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetWholeColumnNames_005, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT t1.data1, t2.data1 FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    resultSet->Close();
    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetWholeColumnNames_006
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetWholeColumnNames.
 *           1. execute 'DROP TABLE test1'
 *           2. return E_NOT_SELECT
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetWholeColumnNames_006, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("DROP TABLE test1");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_NOT_SELECT);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetWholeColumnNames_007
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetWholeColumnNames.
 *           1. execute GetAllColumnNames, columnCount_ is greater than 0
 *           2. execute GetWholeColumnNames
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetWholeColumnNames_007, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT t1.data1, t2.data1 FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    std::vector<std::string> columnNames;
    int ret = resultSet->GetAllColumnNames(columnNames);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("data1", columnNames[0]);
    EXPECT_EQ("", columnNames[1]);

    std::tie(ret, columnNames) = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("data1", columnNames[0]);
    EXPECT_EQ("data1", columnNames[1]);
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowData_001
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetRowData.
 *           1. query all values of all fields
 *           2. get all values of all fields
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowData_001, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    resultSet->GoToFirstRow();
    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowData.size(), 18); // column size is 18

    EXPECT_EQ(rowData[0], ValueObject(1));   // index is 0, id is 1
    EXPECT_EQ(rowData[9], ValueObject(1));   // index is 9, id is 1

    EXPECT_EQ(rowData[1], ValueObject("zhangsan"));   // index is 1, name is "zhangsan"
    EXPECT_EQ(rowData[10], ValueObject("lisi"));   // index is 10, name is "lisi"

    EXPECT_EQ(rowData[2], ValueObject(10));    // index is 2, age is 10
    EXPECT_EQ(rowData[11], ValueObject(10));   // index is 11, age is 10

    EXPECT_EQ(rowData[3], ValueObject(2000.56));    // index is 2, salary is 2000.56
    EXPECT_EQ(rowData[12], ValueObject(2001.56));   // index is 12, salary is 2001.56

    EXPECT_EQ(rowData[4], ValueObject(std::vector<uint8_t>{1, 2, 3}));   // index is 4, blobType is [1, 2, 3]
    EXPECT_EQ(rowData[13], ValueObject(std::vector<uint8_t>{3, 4, 5}));   // index is 13, blobType is [3, 4, 5]

    Asset asset;
    rowData[5].GetAsset(asset);      // index is 5
    EXPECT_EQ(asset.name, "123");    // asset.name is "123"
    rowData[14].GetAsset(asset);     // index is 14
    EXPECT_EQ(asset.name, "456");    // asset.name is "456"

    Assets assets;
    rowData[6].GetAssets(assets);       // index is 6
    EXPECT_EQ(assets[0].name, "123");  // asset.name is "123"
    rowData[15].GetAssets(assets);      // index is 15
    EXPECT_EQ(assets[0].name, "456");  // asset.name is "456"

    EXPECT_EQ(rowData[7], ValueObject(std::vector<float>{1, 0.5}));    // index is 7, floatVector is [1, 0.5]
    EXPECT_EQ(rowData[16], ValueObject(std::vector<float>{1, 1.5}));   // index is 16, floatVector is [1, 1.5]

    EXPECT_EQ(rowData[8], ValueObject(BigInt(100)));       // index is 8, bigInt is 100
    EXPECT_EQ(rowData[17], ValueObject(BigInt(200)));      // index is 17, bigInt is 200
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowData_002
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetRowData.
 *           1. query some values of fields
 *           2. get some values of fields
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowData_002, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::string const sql = "SELECT t1.salary, t2.salary, t1.age, t2.age, t1.name, t2.name FROM test1 t1 LEFT JOIN "
        "test2 t2 ON t1.age=t2.age";
    std::shared_ptr<ResultSet> resultSet = store->QuerySql(sql);
    ASSERT_NE(resultSet, nullptr);

    resultSet->GoToFirstRow();
    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowData.size(), 6); // column size is 6

    EXPECT_EQ(rowData[0], ValueObject(2000.56));   // index is 1, salary is 2000.56
    EXPECT_EQ(rowData[1], ValueObject(2001.56));   // index is 2, salary is 2001.56

    EXPECT_EQ(rowData[2], ValueObject(10));    // index is 3, age is 10
    EXPECT_EQ(rowData[3], ValueObject(10));    // index is 4, age is 10

    EXPECT_EQ(rowData[4], ValueObject("zhangsan"));   // index is 5, name is "zhangsan"
    EXPECT_EQ(rowData[5], ValueObject("lisi"));   // index is 6, name is "lisi"
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowData_003
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetRowData.
 *           1. query some values of fields
 *           2. execute goToRow(1)
 *           2. get some values of fields
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowData_003, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT t1.name, t2.name, t1.age, t2.age FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    resultSet->GoToRow(1);
    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowData.size(), 4); // column size is 4

    EXPECT_EQ(rowData[0], ValueObject("sss"));   // index is 1, name is "sss"
    EXPECT_EQ(rowData[1], ValueObject());       // index is 2, name is NULL

    EXPECT_EQ(rowData[2], ValueObject(50));    // index is 3, age is 50
    EXPECT_EQ(rowData[3], ValueObject());    // index is 4, age is NULL
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowData_004
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowData.
 *           1. SQL length less than or equal to 3
 *           2. execute GetRowData
 *           3. return E_INVALID_ARGS
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowData_004, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(rowData.empty());
    resultSet->Close();

    resultSet = store->QuerySql("SEL");
    ASSERT_NE(resultSet, nullptr);

    std::tie(ret, rowData) = resultSet->GetRowData();
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(rowData.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowData_005
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowData.
 *           1. incomplete SQL statement
 *           2. execute GetRowData
 *           3. return E_SQLITE_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowData_005, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_SQLITE_ERROR);
    EXPECT_TRUE(rowData.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowData_006
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowData.
 *           1. query some fields
 *           2. resultSet close
 *           3. return E_ALREADY_CLOSED
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowData_006, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT t1.data1, t2.data1 FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    resultSet->Close();
    auto [ret, columnNames] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
    EXPECT_TRUE(columnNames.empty());
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowData_007
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowData.
 *           1. execute 'DROP TABLE test1'
 *           2. return E_NOT_SELECT
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowData_007, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("DROP TABLE test1");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_NOT_SELECT);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowData_008
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowData.
 *           1. execute GetRowData
 *           2. return E_ROW_OUT_RANGE
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowData_008, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT t1.name, t2.name FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    EXPECT_TRUE(columnNames.empty());

    resultSet->GoToRow(3);   // rowPos is 3
    std::tie(ret, columnNames) = resultSet->GetRowData();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_001
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowsData.
 *           1. SQL length less than or equal to 3, maxCount less than 0
 *           2. execute GetRowsData
 *           3. return E_INVALID_ARGS
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_001, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SE");
    ASSERT_NE(resultSet, nullptr);
    // maxCount is -1
    auto [ret, rowsData] = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(rowsData.empty());
    resultSet->Close();

    resultSet = store->QuerySql("SEL");
    ASSERT_NE(resultSet, nullptr);

    std::tie(ret, rowsData) = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(rowsData.empty());
    resultSet->Close();

    resultSet =
        store->QuerySql("SELECT t1.name, t2.name FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    std::tie(ret, rowsData) = resultSet->GetRowsData(-1, 0); // maxCount is -1, position is 0
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(rowsData.empty());

    std::tie(ret, rowsData) = resultSet->GetRowsData(1, -2); // maxCount is 1, position is -2
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(rowsData.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_002
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowData.
 *           1. incomplete SQL statement
 *           2. execute GetRowsData
 *           3. return E_SQLITE_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_002, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("SELE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_SQLITE_ERROR);
    EXPECT_TRUE(rowsData.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_003
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowsData.
 *           1. query some fields
 *           2. resultSet close
 *           3. return E_ALREADY_CLOSED
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_003, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT t1.data1, t2.data1 FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    resultSet->Close();
    auto [ret, rowsData] = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
    EXPECT_TRUE(rowsData.empty());
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_004
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowsData.
 *           1. execute 'DROP TABLE test1'
 *           2. return E_NOT_SELECT
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_004, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QuerySql("DROP TABLE test1");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_NOT_SELECT);
    EXPECT_TRUE(rowsData.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_005
 * @tc.desc: Abnormal testcase of SqliteSharedResultSet for GetRowsData.
 *           1. execute GetRowsData
 *           2. return E_ROW_OUT_RANGE
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_005, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT t1.name, t2.name FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(2, 2); // maxCount is 2, position is 2
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    EXPECT_TRUE(rowsData.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_006
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetRowsData.
 *           1. query some fields
 *           1. execute GetRowsData(2, 0)
 *           2. get some values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_006, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT t1.name, t2.name, t1.age, t2.age FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(2, 0);  // maxCount is 2
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);   // rowsData size is 2
    EXPECT_EQ(rowsData[0].size(), 4);   // rowsData size is 2
    EXPECT_EQ(rowsData[1].size(), 4);   // rowsData size is 2

    int rowPos = 0;
    resultSet->GetRowIndex(rowPos);
    EXPECT_EQ(rowPos, 2);   // rowPos is 2

    EXPECT_EQ(rowsData[0][0], ValueObject("zhangsan"));   // index is 0, name is "zhangsan"
    EXPECT_EQ(rowsData[0][1], ValueObject("lisi"));       // index is 1, name is "lisi"
    EXPECT_EQ(rowsData[0][2], ValueObject(10));           // index is 2, age is 10
    EXPECT_EQ(rowsData[0][3], ValueObject(10));           // index is 3, age is 10
    EXPECT_EQ(rowsData[1][0], ValueObject("sss"));        // index is 0, name is "sss"
    EXPECT_EQ(rowsData[1][1], ValueObject());             // index is 1, name is NULL
    EXPECT_EQ(rowsData[1][2], ValueObject(50));           // index is 2, age is 50
    EXPECT_EQ(rowsData[1][3], ValueObject());             // index is 3, age is NULL

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    resultSet->GetRowIndex(rowPos);
    EXPECT_EQ(rowPos, 0);   // rowPos is 0
    std::tie(ret, rowsData) = resultSet->GetRowsData(2, 0);  // maxCount is 2
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);   // rowsData size is 2
    EXPECT_EQ(rowsData[0].size(), 4);   // rowsData size is 4
    EXPECT_EQ(rowsData[1].size(), 4);   // rowsData size is 4

    resultSet->GetRowIndex(rowPos);
    EXPECT_EQ(rowPos, 2);   // rowPos is 2
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_007
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetRowsData.
 *           1. query some fields
 *           1. execute GetRowsData(2, -1)
 *           2. get some values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_007, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT t1.name, t2.name, t1.age, t2.age FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(2, -1);  // maxCount is 2, position is -1
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);   // rowsData size is 2
    EXPECT_EQ(rowsData[0].size(), 4);   // column size is 4
    EXPECT_EQ(rowsData[1].size(), 4);   // column size is 4

    int rowPos = 0;
    resultSet->GetRowIndex(rowPos);
    EXPECT_EQ(rowPos, 2);   // rowPos is 2

    EXPECT_EQ(rowsData[0][0], ValueObject("zhangsan"));   // index is 0, name is "zhangsan"
    EXPECT_EQ(rowsData[0][1], ValueObject("lisi"));       // index is 1, name is "lisi"
    EXPECT_EQ(rowsData[0][2], ValueObject(10));           // index is 2, age is 10
    EXPECT_EQ(rowsData[0][3], ValueObject(10));           // index is 3, age is 10
    EXPECT_EQ(rowsData[1][0], ValueObject("sss"));        // index is 0, name is "sss"
    EXPECT_EQ(rowsData[1][1], ValueObject());             // index is 1, name is NULL
    EXPECT_EQ(rowsData[1][2], ValueObject(50));           // index is 2, age is 50
    EXPECT_EQ(rowsData[1][3], ValueObject());             // index is 3, age is NULL

    std::tie(ret, rowsData) = resultSet->GetRowsData(2, -1);  // maxCount is 2, position is -1
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 0);   // rowsData size is 0

    resultSet->GetRowIndex(rowPos);
    EXPECT_EQ(rowPos, 2);   // rowPos is 2
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_008
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetRowsData.
 *           1. query all fields
 *           1. execute GetRowsData(2, 0)
 *           2. get all values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_008, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(2, 0);  // maxCount is 2, position is 0
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);       // rowsData size is 2
    EXPECT_EQ(rowsData[0].size(), 18);   // column size is 18
    EXPECT_EQ(rowsData[1].size(), 18);   // column size is 18
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_009
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetRowsData.
 *           1. query all fields
 *           1. execute GetRowsData(0, 0)
 *           2. get all values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_009, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(0, 0);  // maxCount is 0, position is 0
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 0);       // rowsData size is 2
    resultSet->Close();
}

/* *
 * @tc.name: Sqlite_Shared_Result_Set_GetRowsData_010
 * @tc.desc: Normal testcase of SqliteSharedResultSet for GetRowsData.
 *           1. query all fields
 *           1. execute GetRowsData(3, 0), rowCount is 2 acutually
 *           2. get all values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Sqlite_Shared_Result_Set_GetRowsData_010, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QuerySql("SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(3, 0);  // maxCount is 3, position is 0
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);       // rowsData size is 2
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetWholeColumnNames_001
 * @tc.desc: Normal testcase of StepResultSet for GetWholeColumnNames.
 *           1. query all fields
 *           2. get all fileds in order
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetWholeColumnNames_001, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(
        "SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_OK);

    EXPECT_EQ(columnNames.size(), 18); // columnsSize is 18

    std::vector<std::string> columnNamesTemp{"id", "name", "age", "salary", "blobType", "data1", "data2",
        "data3", "data4", "id", "name", "age", "salary", "blobType", "data1", "data2", "data3", "data4"};
    EXPECT_EQ(columnNames, columnNamesTemp);
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetWholeColumnNames_002
 * @tc.desc: Normal testcase of StepResultSet for GetWholeColumnNames.
 *           1. query some fields
 *           2. get some fileds in order
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetWholeColumnNames_002, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::string const sql = "SELECT t1.data1, t2.data1, t1.age, t2.age, t1.name, t2.name FROM test1 t1 LEFT JOIN "
        "test2 t2 ON t1.age=t2.age";
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sql);
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_OK);

    EXPECT_EQ(columnNames.size(), 6); // columnsSize is 6

    std::vector<std::string> columnNamesTemp{"data1", "data1", "age", "age", "name", "name"};
    EXPECT_EQ(columnNames, columnNamesTemp);
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetWholeColumnNames_003
 * @tc.desc: Abnormal testcase of StepResultSet for GetWholeColumnNames.
 *           1. SQL length less than or equal to 3
 *           2. execute GetWholeColumnNames
 *           3. return E_INVALID_ARGS
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetWholeColumnNames_003, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();

    resultSet = store->QuerySql("SEL");
    ASSERT_NE(resultSet, nullptr);

    std::tie(ret, columnNames) = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetWholeColumnNames_004
 * @tc.desc: Abnormal testcase of StepResultSet for GetWholeColumnNames.
 *           1. incomplete SQL statement
 *           2. execute GetWholeColumnNames
 *           3. return E_SQLITE_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetWholeColumnNames_004, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_SQLITE_ERROR);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetWholeColumnNames_005
 * @tc.desc: Abnormal testcase of StepResultSet for GetWholeColumnNames.
 *           1. query some fields
 *           2. resultSet close
 *           3. return E_ALREADY_CLOSED
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetWholeColumnNames_005, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT t1.data1, t2.data1 FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    resultSet->Close();
    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
    EXPECT_TRUE(columnNames.empty());
}

/* *
 * @tc.name: Step_Result_Set_GetWholeColumnNames_006
 * @tc.desc: Abnormal testcase of StepResultSet for GetWholeColumnNames.
 *           1. execute 'DROP TABLE test1'
 *           2. return E_NOT_SELECT
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetWholeColumnNames_006, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("DROP TABLE test1");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_NOT_SELECT);
    EXPECT_TRUE(columnNames.empty());
}

/* *
 * @tc.name: Step_Result_Set_GetWholeColumnNames_007
 * @tc.desc: Normal testcase of StepResultSet for GetWholeColumnNames.
 *           1. execute GetAllColumnNames, columnCount_ is greater than 0
 *           2. execute GetWholeColumnNames
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetWholeColumnNames_007, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT t1.data1, t2.data1 FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    std::vector<std::string> columnNames;
    int ret = resultSet->GetAllColumnNames(columnNames);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("data1", columnNames[0]);
    EXPECT_EQ("", columnNames[1]);

    std::tie(ret, columnNames) = resultSet->GetWholeColumnNames();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ("data1", columnNames[0]);
    EXPECT_EQ("data1", columnNames[1]);
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowData_001
 * @tc.desc: Normal testcase of StepResultSet for GetRowData.
 *           1. query all values of all fields
 *           2. get all values of all fields
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowData_001, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    resultSet->GoToFirstRow();
    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowData.size(), 18); // column size is 18

    EXPECT_EQ(rowData[0], ValueObject(1));   // index is 0, id is 1
    EXPECT_EQ(rowData[9], ValueObject(1));   // index is 9, id is 1

    EXPECT_EQ(rowData[1], ValueObject("zhangsan"));   // index is 1, name is "zhangsan"
    EXPECT_EQ(rowData[10], ValueObject("lisi"));   // index is 10, name is "lisi"

    EXPECT_EQ(rowData[2], ValueObject(10));    // index is 2, age is 10
    EXPECT_EQ(rowData[11], ValueObject(10));   // index is 11, age is 10

    EXPECT_EQ(rowData[3], ValueObject(2000.56));    // index is 2, salary is 2000.56
    EXPECT_EQ(rowData[12], ValueObject(2001.56));   // index is 12, salary is 2001.56

    EXPECT_EQ(rowData[4], ValueObject(std::vector<uint8_t>{1, 2, 3}));   // index is 4, blobType is [1, 2, 3]
    EXPECT_EQ(rowData[13], ValueObject(std::vector<uint8_t>{3, 4, 5}));   // index is 13, blobType is [3, 4, 5]

    Asset asset;
    rowData[5].GetAsset(asset);      // index is 5
    EXPECT_EQ(asset.name, "123");    // asset.name is "123"
    rowData[14].GetAsset(asset);     // index is 14
    EXPECT_EQ(asset.name, "456");    // asset.name is "456"

    Assets assets;
    rowData[6].GetAssets(assets);       // index is 6
    EXPECT_EQ(assets[0].name, "123");  // asset.name is "123"
    rowData[15].GetAssets(assets);      // index is 15
    EXPECT_EQ(assets[0].name, "456");  // asset.name is "456"

    EXPECT_EQ(rowData[7], ValueObject(std::vector<float>{1, 0.5}));    // index is 7, floatVector is [1, 0.5]
    EXPECT_EQ(rowData[16], ValueObject(std::vector<float>{1, 1.5}));   // index is 16, floatVector is [1, 1.5]

    EXPECT_EQ(rowData[8], ValueObject(BigInt(100)));       // index is 8, bigInt is 100
    EXPECT_EQ(rowData[17], ValueObject(BigInt(200)));      // index is 17, bigInt is 200
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowData_002
 * @tc.desc: Normal testcase of StepResultSet for GetRowData.
 *           1. query some values of fields
 *           2. get some values of fields
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowData_002, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::string const sql = "SELECT t1.salary, t2.salary, t1.age, t2.age, t1.name, t2.name FROM test1 t1 LEFT JOIN "
        "test2 t2 ON t1.age=t2.age";
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sql);
    ASSERT_NE(resultSet, nullptr);

    resultSet->GoToFirstRow();
    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowData.size(), 6); // column size is 6

    EXPECT_EQ(rowData[0], ValueObject(2000.56));   // index is 1, salary is 2000.56
    EXPECT_EQ(rowData[1], ValueObject(2001.56));   // index is 2, salary is 2001.56

    EXPECT_EQ(rowData[2], ValueObject(10));    // index is 3, age is 10
    EXPECT_EQ(rowData[3], ValueObject(10));    // index is 4, age is 10

    EXPECT_EQ(rowData[4], ValueObject("zhangsan"));   // index is 5, name is "zhangsan"
    EXPECT_EQ(rowData[5], ValueObject("lisi"));   // index is 6, name is "lisi"
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowData_003
 * @tc.desc: Normal testcase of StepResultSet for GetRowData.
 *           1. query some values of fields
 *           2. execute goToRow(1)
 *           2. get some values of fields
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowData_003, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::string const sql = "SELECT t1.name, t2.name, t1.age, t2.age "
        "FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age";
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep(sql);
    ASSERT_NE(resultSet, nullptr);

    resultSet->GoToRow(1);
    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowData.size(), 4); // column size is 4

    EXPECT_EQ(rowData[0], ValueObject("sss"));   // index is 1, name is "sss"
    EXPECT_EQ(rowData[1], ValueObject());       // index is 2, name is NULL

    EXPECT_EQ(rowData[2], ValueObject(50));    // index is 3, age is 50
    EXPECT_EQ(rowData[3], ValueObject());    // index is 4, age is NULL
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowData_004
 * @tc.desc: Abnormal testcase of StepResultSet for GetRowData.
 *           1. SQL length less than or equal to 3
 *           2. execute GetRowData
 *           3. return E_INVALID_ARGS
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowData_004, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(rowData.empty());
    resultSet->Close();

    resultSet = store->QueryByStep("SEL");
    ASSERT_NE(resultSet, nullptr);

    std::tie(ret, rowData) = resultSet->GetRowData();
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(rowData.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowData_005
 * @tc.desc: Abnormal testcase of StepResultSet for GetRowData.
 *           1. incomplete SQL statement
 *           2. execute GetRowData
 *           3. return E_SQLITE_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowData_005, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowData] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_SQLITE_ERROR);
    EXPECT_TRUE(rowData.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowData_006
 * @tc.desc: Abnormal testcase of StepResultSet for GetRowData.
 *           1. query some fields
 *           2. resultSet close
 *           3. return E_ALREADY_CLOSED
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowData_006, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT t1.data1, t2.data1 FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    resultSet->Close();
    auto [ret, columnNames] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
    EXPECT_TRUE(columnNames.empty());
}

/* *
 * @tc.name: Step_Result_Set_GetRowData_007
 * @tc.desc: Abnormal testcase of StepResultSet for GetRowData.
 *           1. execute 'DROP TABLE test1'
 *           2. return E_NOT_SELECT
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowData_007, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("DROP TABLE test1");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_NOT_SELECT);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowData_008
 * @tc.desc: Abnormal testcase of StepResultSet for GetRowData.
 *           1. execute GetRowData
 *           2. return E_ROW_OUT_RANGE
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowData_008, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT t1.name, t2.name FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetRowData();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    EXPECT_TRUE(columnNames.empty());

    resultSet->GoToRow(3);   // rowPos is 3
    std::tie(ret, columnNames) = resultSet->GetRowData();
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_001
 * @tc.desc: Normal testcase of StepResultSet for GetRowsData.
 *           1. SQL length less than or equal to 3, maxCount than 0
 *           2. execute GetRowsData
 *           3. return E_INVALID_ARGS
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_001, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SE");
    ASSERT_NE(resultSet, nullptr);
    // maxCount is -1
    auto [ret, columnNames] = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();

    resultSet = store->QueryByStep("SEL");
    ASSERT_NE(resultSet, nullptr);

    std::tie(ret, columnNames) = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();

    resultSet =
        store->QueryByStep("SELECT t1.name, t2.name FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    std::tie(ret, columnNames) = resultSet->GetRowsData(-1, 0);
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(columnNames.empty());

    std::tie(ret, columnNames) = resultSet->GetRowsData(1, -2);
    EXPECT_EQ(ret, E_INVALID_ARGS);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_002
 * @tc.desc: Abnormal testcase of StepResultSet for GetRowData.
 *           1. incomplete SQL statement
 *           2. execute GetRowsData
 *           3. return E_SQLITE_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_002, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELE");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowData] = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_SQLITE_ERROR);
    EXPECT_TRUE(rowData.empty());

    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_003
 * @tc.desc: Abnormal testcase of StepResultSet for GetRowsData.
 *           1. query some fields
 *           2. resultSet close
 *           3. return E_ALREADY_CLOSED
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_003, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT t1.data1, t2.data1 FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    resultSet->Close();
    auto [ret, columnNames] = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_ALREADY_CLOSED);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_004
 * @tc.desc: Abnormal testcase of StepResultSet for GetRowsData.
 *           1. execute 'DROP TABLE test1'
 *           2. return E_NOT_SELECT
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_004, TestSize.Level1)
{
    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("DROP TABLE test1");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetRowsData(1, 0);
    EXPECT_EQ(ret, E_NOT_SELECT);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_005
 * @tc.desc: Abnormal testcase of StepResultSet for GetRowsData.
 *           1. execute GetRowsData
 *           2. return E_ROW_OUT_RANGE
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_005, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT t1.name, t2.name FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, columnNames] = resultSet->GetRowsData(2, 2);
    EXPECT_EQ(ret, E_ROW_OUT_RANGE);
    EXPECT_TRUE(columnNames.empty());
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_006
 * @tc.desc: Normal testcase of StepResultSet for GetRowsData.
 *           1. query some fields
 *           1. execute GetRowsData
 *           2. get some values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_006, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT t1.name, t2.name, t1.age, t2.age FROM test1 t1 "
        "LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(2, 0);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);   // rowsData size is 2
    EXPECT_EQ(rowsData[0].size(), 4);   // rowsData size is 2
    EXPECT_EQ(rowsData[1].size(), 4);   // rowsData size is 2

    EXPECT_EQ(rowsData[0][0], ValueObject("zhangsan"));   // index is 0, name is "zhangsan"
    EXPECT_EQ(rowsData[0][1], ValueObject("lisi"));       // index is 1, name is "lisi"
    EXPECT_EQ(rowsData[0][2], ValueObject(10));           // index is 2, age is 10
    EXPECT_EQ(rowsData[0][3], ValueObject(10));           // index is 3, age is 10
    EXPECT_EQ(rowsData[1][0], ValueObject("sss"));        // index is 0, name is "sss"
    EXPECT_EQ(rowsData[1][1], ValueObject());             // index is 1, name is NULL
    EXPECT_EQ(rowsData[1][2], ValueObject(50));           // index is 2, age is 50
    EXPECT_EQ(rowsData[1][3], ValueObject());             // index is 3, age is NULL

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(ret, E_OK);
    int rowPos = 0;
    resultSet->GetRowIndex(rowPos);
    EXPECT_EQ(rowPos, 0);   // rowPos is 0
    std::tie(ret, rowsData) = resultSet->GetRowsData(2, 0);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);   // rowsData size is 2
    EXPECT_EQ(rowsData[0].size(), 4);   // column size is 4
    EXPECT_EQ(rowsData[1].size(), 4);   // column size is 4

    EXPECT_EQ(rowsData[0][0], ValueObject("zhangsan"));   // index is 0, name is "zhangsan"
    EXPECT_EQ(rowsData[0][1], ValueObject("lisi"));       // index is 1, name is "lisi"
    EXPECT_EQ(rowsData[0][2], ValueObject(10));           // index is 2, age is 10
    EXPECT_EQ(rowsData[0][3], ValueObject(10));           // index is 3, age is 10
    EXPECT_EQ(rowsData[1][0], ValueObject("sss"));        // index is 0, name is "sss"
    EXPECT_EQ(rowsData[1][1], ValueObject());             // index is 1, name is NULL
    EXPECT_EQ(rowsData[1][2], ValueObject(50));           // index is 2, age is 50
    EXPECT_EQ(rowsData[1][3], ValueObject());             // index is 3, age is NULL
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_007
 * @tc.desc: Normal testcase of StepResultSet for GetRowsData.
 *           1. query some fields
 *           1. execute GetRowsData(2, -1)
 *           2. get some values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_007, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet = store->QueryByStep("SELECT t1.name, t2.name, t1.age, t2.age FROM test1 t1 "
        "LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(2, -1);  // maxCount is 2, position is -1
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);   // rowsData size is 2
    EXPECT_EQ(rowsData[0].size(), 4);   // column size is 4
    EXPECT_EQ(rowsData[1].size(), 4);   // column size is 4

    int rowPos = 0;
    resultSet->GetRowIndex(rowPos);
    EXPECT_EQ(rowPos, 2);   // rowPos is 2

    EXPECT_EQ(rowsData[0][0], ValueObject("zhangsan"));   // index is 0, name is "zhangsan"
    EXPECT_EQ(rowsData[0][1], ValueObject("lisi"));       // index is 1, name is "lisi"
    EXPECT_EQ(rowsData[0][2], ValueObject(10));           // index is 2, age is 10
    EXPECT_EQ(rowsData[0][3], ValueObject(10));           // index is 3, age is 10
    EXPECT_EQ(rowsData[1][0], ValueObject("sss"));        // index is 0, name is "sss"
    EXPECT_EQ(rowsData[1][1], ValueObject());             // index is 1, name is NULL
    EXPECT_EQ(rowsData[1][2], ValueObject(50));           // index is 2, age is 50
    EXPECT_EQ(rowsData[1][3], ValueObject());             // index is 3, age is NULL

    std::tie(ret, rowsData) = resultSet->GetRowsData(2, -1);  // maxCount is 2, position is -1
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 0);   // rowsData size is 0

    resultSet->GetRowIndex(rowPos);
    EXPECT_EQ(rowPos, 2);   // rowPos is 2
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_008
 * @tc.desc: Normal testcase of StepResultSet for GetRowsData.
 *           1. query all fields
 *           1. execute GetRowsData(2, 0)
 *           2. get all values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_008, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(2, 0);  // maxCount is 2, position is 0
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);       // rowsData size is 2
    EXPECT_EQ(rowsData[0].size(), 18);   // column size is 18
    EXPECT_EQ(rowsData[1].size(), 18);   // column size is 18
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_009
 * @tc.desc: Normal testcase of StepResultSet for GetRowsData.
 *           1. query all fields
 *           1. execute GetRowsData(0, 0)
 *           2. get all values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_009, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(0, 0);  // maxCount is 0, position is 0
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 0);       // rowsData size is 2
    resultSet->Close();
}

/* *
 * @tc.name: Step_Result_Set_GetRowsData_010
 * @tc.desc: Normal testcase of StepResultSet for GetRowsData.
 *           1. query all fields
 *           1. execute GetRowsData(3, 0), rowCount is 2 acutually
 *           2. get all values
 * @tc.type: FUNC
 */
HWTEST_F(DuplicateColumnDataTest, Step_Result_Set_GetRowsData_010, TestSize.Level1)
{
    GenerateData1();
    GenerateData2();

    std::shared_ptr<ResultSet> resultSet =
        store->QueryByStep("SELECT * FROM test1 t1 LEFT JOIN test2 t2 ON t1.age=t2.age");
    ASSERT_NE(resultSet, nullptr);

    auto [ret, rowsData] = resultSet->GetRowsData(3, 0);  // maxCount is 3, position is 0
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(rowsData.size(), 2);       // rowsData size is 2
    resultSet->Close();
}