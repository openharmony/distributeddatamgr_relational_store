/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "datashare_predicates.h"
#include "rdb_logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

class RdbDataShareAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();

    void GenerateDefaultTable();

    void GenerateDefaultEmptyTable();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static const int E_SQLITE_ERROR;
    static const int E_INVALID_COLUMN_TYPE;
    static const size_t DEFAULT_BLOCK_SIZE;
    static const std::string RDB_ADAPTER_TEST_PATH;
};

const std::string RdbDataShareAdapterTest::RDB_ADAPTER_TEST_PATH = "/data/test/";
const std::string RdbDataShareAdapterTest::DATABASE_NAME = RDB_ADAPTER_TEST_PATH + "rdbDataShareAdapter_test.db";
const int RdbDataShareAdapterTest::E_SQLITE_ERROR = -1;          // errno SQLITE_ERROR
const int RdbDataShareAdapterTest::E_INVALID_COLUMN_TYPE = 1009; // errno SQLITE_NULL
const size_t RdbDataShareAdapterTest::DEFAULT_BLOCK_SIZE = 2 * 1024 * 1024;
std::shared_ptr<RdbStore> RdbDataShareAdapterTest::store = nullptr;

class RdbStepSharedResultSetOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;

    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;

    static const std::string CREATE_TABLE_TEST;
};

int RdbStepSharedResultSetOpenCallback::OnCreate(RdbStore &store)
{
    return OHOS::NativeRdb::E_OK;
}

int RdbStepSharedResultSetOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return OHOS::NativeRdb::E_OK;
}

void RdbDataShareAdapterTest::SetUpTestCase(void)
{
    int errCode = OHOS::NativeRdb::E_OK;
    RdbStoreConfig config(RdbDataShareAdapterTest::DATABASE_NAME);
    RdbStepSharedResultSetOpenCallback helper;
    RdbDataShareAdapterTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbDataShareAdapterTest::store, nullptr);
    EXPECT_EQ(errCode, OHOS::NativeRdb::E_OK);
}

void RdbDataShareAdapterTest::TearDownTestCase(void)
{
    RdbHelper::DeleteRdbStore(RdbDataShareAdapterTest::DATABASE_NAME);
}

void RdbDataShareAdapterTest::SetUp(void)
{
    store->ExecuteSql("DROP TABLE IF EXISTS test");
}

void RdbDataShareAdapterTest::TearDown(void)
{
    RdbHelper::ClearCache();
}

void RdbDataShareAdapterTest::GenerateDefaultTable()
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, ") +
                                 std::string("data2 INTEGER, data3 FLOAT, data4 BLOB);");
    store->ExecuteSql(createTableSql);

    std::string insertSql = "INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);";

    /* insert first entry data */
    uint8_t uValue = 66;
    std::vector<uint8_t> typeBlob;
    typeBlob.push_back(uValue);
    store->ExecuteSql(insertSql, std::vector<ValueObject> {
        ValueObject(std::string("hello")), ValueObject((int)10),
        ValueObject((double)1.0), ValueObject((std::vector<uint8_t>)typeBlob)
    });

    /* insert second entry data */
    typeBlob.clear();
    store->ExecuteSql(insertSql, std::vector<ValueObject> {
        ValueObject(std::string("2")), ValueObject((int)-5), ValueObject((double)2.5),
        ValueObject() // set double value 2.5
    });

    /* insert third entry data */
    store->ExecuteSql(insertSql, std::vector<ValueObject> {
        ValueObject(std::string("hello world")), ValueObject((int)3), ValueObject((double)1.8),
        ValueObject(std::vector<uint8_t> { 4, 5, 6 }) // set int value 3, double 1.8
    });

    /* insert four entry data */
    store->ExecuteSql(insertSql, std::vector<ValueObject> {
        ValueObject(std::string("new world")), ValueObject((int)5),
        ValueObject((double)5.8), ValueObject() // set int value 5, double 5.8
    });
}

void RdbDataShareAdapterTest::GenerateDefaultEmptyTable()
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 TEXT, ") +
                                 std::string("data2 INTEGER, data3 FLOAT, data4 BLOB);");
    store->ExecuteSql(createTableSql);
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_001
 * @tc.desc: test RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_001, TestSize.Level1)
{
    GenerateDefaultTable();

    std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet = store->QueryByStep("SELECT * FROM test");
    EXPECT_NE(resultSet, nullptr);
    int rowCount;
    resultSet.get()->GetRowCount(rowCount);
    LOG_INFO("result row count:  %{public}d", rowCount);
    EXPECT_NE(rowCount, 0);
    auto bridge = OHOS::RdbDataShareAdapter::RdbUtils::ToResultSetBridge(resultSet);
    EXPECT_NE(bridge, nullptr);
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_002
 * @tc.desc: normal testcase of RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_002, TestSize.Level1)
{
    GenerateDefaultTable();

    std::string table = "test";
    std::string column = "data1";
    std::string value = "hello";
    DataSharePredicates predicates;
    predicates.EqualTo(column, value);
    std::vector<std::string> columns;
    std::shared_ptr<AbsSharedResultSet> allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
    int rowCount;
    allDataTypes.get()->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 1);
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_003
 * @tc.desc: normal testcase of RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_003, TestSize.Level1)
{
    GenerateDefaultTable();

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.GreaterThan("data2", -5);
    std::vector<std::string> columns;
    std::shared_ptr<AbsSharedResultSet> allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
    int rdbRowCount;
    allDataTypes.get()->GetRowCount(rdbRowCount);
    EXPECT_EQ(rdbRowCount, 3);

    allDataTypes->GoToFirstRow();

    std::string strValue;
    allDataTypes->GetString(1, strValue);
    EXPECT_EQ("hello", strValue);

    int intValue;
    allDataTypes->GetInt(2, intValue);
    EXPECT_EQ(intValue, 10);

    std::vector<uint8_t> blobValue;
    uint8_t blobData = 66;
    allDataTypes->GetBlob(4, blobValue);
    EXPECT_EQ(blobData, blobValue[0]);

    allDataTypes->GoToNextRow();
    allDataTypes->GetBlob(4, blobValue);
    EXPECT_EQ(3, static_cast<int>(blobValue.size()));
    blobData = 5;
    EXPECT_EQ(blobData, blobValue[1]);
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_004
 * @tc.desc: normal testcase of RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_004, TestSize.Level1)
{
    GenerateDefaultTable();

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause("`data2` > ?");
    predicates.SetWhereArgs(std::vector<std::string> { "-5" });
    predicates.SetOrder("data3");
    std::vector<std::string> columns;
    std::shared_ptr<AbsSharedResultSet> allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
    int rowCount;
    allDataTypes.get()->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 3);

    allDataTypes->GoToFirstRow();

    std::string strValue;
    allDataTypes->GetString(1, strValue);
    EXPECT_EQ("hello", strValue);

    int intValue;
    allDataTypes->GetInt(2, intValue);
    EXPECT_EQ(intValue, 10);

    std::vector<uint8_t> blobValue;
    allDataTypes->GetBlob(4, blobValue);
    EXPECT_EQ(1, static_cast<int>(blobValue.size()));

    allDataTypes->GoToNextRow();

    allDataTypes->GetString(1, strValue);
    EXPECT_EQ("hello world", strValue);

    allDataTypes->GetInt(2, intValue);
    EXPECT_EQ(intValue, 3);

    allDataTypes->GetBlob(4, blobValue);
    EXPECT_EQ(3, static_cast<int>(blobValue.size()));
    uint8_t blobData = 5;
    EXPECT_EQ(blobData, blobValue[1]);
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_005
 * @tc.desc: normal testcase of RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_005, TestSize.Level1)
{
    GenerateDefaultTable();
    DataShareValuesBucket values;
    int64_t id;
    int changedRows;
    values.Put("data1", std::string("tulip"));
    values.Put("data2", 100);
    values.Put("data3", 50.5);
    values.Put("data4", std::vector<uint8_t> { 20, 21, 22 });

    int ret = store->Insert(id, "test", RdbUtils::ToValuesBucket(values));
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(5, id);

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates;
    std::string value = "tulip";
    predicates.EqualTo("data1", value);
    std::vector<std::string> columns;
    std::shared_ptr<AbsSharedResultSet> allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
    int rowCount;
    allDataTypes.get()->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 1);

    allDataTypes.get()->Close();

    values.Clear();
    values.Put("data3", 300.5);
    values.Put("data4", std::vector<uint8_t> { 17, 18, 19 });
    ret = store->Update(
        changedRows, "test", RdbUtils::ToValuesBucket(values), "data1 = ?", std::vector<std::string> { "tulip" });
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(1, changedRows);

    allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
    allDataTypes->GoToFirstRow();

    double doubleVal;
    allDataTypes->GetDouble(3, doubleVal);
    EXPECT_EQ(300.5, doubleVal);

    int deletedRows;
    ret = store->Delete(deletedRows, RdbUtils::ToPredicates(predicates, table));
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(1, deletedRows);
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_006
 * @tc.desc: normal testcase of RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_006, TestSize.Level1)
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT,") +
                                 std::string("age INTEGER);");
    store->ExecuteSql(createTableSql);

    DataShareValuesBucket values;
    int64_t id;
    values.Put("name", std::string("lisi"));
    int64_t ageValue = 0x80001000;
    values.Put("age", ageValue);

    ValuesBucket valuesBucket = RdbUtils::ToValuesBucket(values);
    ValueObject valueObject;
    valuesBucket.GetObject("age", valueObject);
    int64_t res;
    int ret = valueObject.GetLong(res);
    LOG_INFO("Rdb_DataShare_Adapter_006 res is: %{public}" PRId64, res);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(res, ageValue);

    int ret1 = store->Insert(id, "test", valuesBucket);
    EXPECT_EQ(ret1, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(1, id);

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates;
    std::string value = "lisi";
    predicates.EqualTo("name", value);
    std::vector<std::string> columns;
    std::shared_ptr<AbsSharedResultSet> allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
    allDataTypes->GoToFirstRow();
    int64_t intValue;
    allDataTypes->GetLong(2, intValue);
    EXPECT_EQ(intValue, ageValue);
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_007
 * @tc.desc: normal testcase of RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_007, TestSize.Level1)
{
    GenerateDefaultTable();

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.Limit(1, 2);
    std::vector<std::string> columns;
    std::shared_ptr<AbsSharedResultSet> allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
    int rdbRowCount;
    allDataTypes.get()->GetRowCount(rdbRowCount);
    EXPECT_EQ(rdbRowCount, 1);

    allDataTypes->GoToFirstRow();

    std::string strValue;
    allDataTypes->GetString(1, strValue);
    EXPECT_EQ("hello world", strValue);

    int intValue;
    allDataTypes->GetInt(2, intValue);
    EXPECT_EQ(intValue, 3);

    double doubleValue;
    allDataTypes->GetDouble(3, doubleValue);
    EXPECT_EQ(doubleValue, 1.8);

    std::vector<uint8_t> blobValue;
    uint8_t blobData1 = 4;
    uint8_t blobData2 = 5;
    uint8_t blobData3 = 6;
    allDataTypes->GetBlob(4, blobValue);
    EXPECT_EQ(3, static_cast<int>(blobValue.size()));
    EXPECT_EQ(blobData1, blobValue[0]);
    EXPECT_EQ(blobData2, blobValue[1]);
    EXPECT_EQ(blobData3, blobValue[2]);
}