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
#define LOG_TAG "RdbDataShareAdapterTest"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>

#include "datashare_predicates.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_utils.h"

using namespace testing::ext;
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::RdbDataShareAdapter;

class MockRdbPredicates : public RdbPredicates {
public:
    explicit MockRdbPredicates(const std::string &table) : RdbPredicates(table)
    {
    }
    MOCK_METHOD(AbsRdbPredicates *, EqualTo, (const std::string &field, const ValueObject &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, NotEqualTo, (const std::string &column, const OHOS::NativeRdb::ValueObject &value),
        (override));
    MOCK_METHOD(AbsRdbPredicates *, GreaterThan,
        (const std::string &column, const OHOS::NativeRdb::ValueObject &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, LessThan, (const std::string &field, const ValueObject &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, GreaterThanOrEqualTo,
        (const std::string &column, const OHOS::NativeRdb::ValueObject &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, LessThanOrEqualTo,
        (const std::string &column, const OHOS::NativeRdb::ValueObject &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, And, (), (override));
    MOCK_METHOD(AbsRdbPredicates *, Or, (), (override));
    MOCK_METHOD(AbsRdbPredicates *, IsNull, (const std::string &column), (override));
    MOCK_METHOD(AbsRdbPredicates *, IsNotNull, (const std::string &column), (override));
    MOCK_METHOD(AbsRdbPredicates *, In, (const std::string &field, const std::vector<ValueObject> &values), (override));
    MOCK_METHOD(
        AbsRdbPredicates *, NotIn, (const std::string &field, const std::vector<ValueObject> &values), (override));
    MOCK_METHOD(AbsRdbPredicates *, Like, (const std::string &field, const std::string &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, NotLike, (const std::string &field, const std::string &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, OrderByAsc, (const std::string &field), (override));
    MOCK_METHOD(AbsRdbPredicates *, OrderByDesc, (const std::string &field), (override));
    MOCK_METHOD(AbsRdbPredicates *, Offset, (const int offset), (override));
    MOCK_METHOD(AbsRdbPredicates *, BeginsWith, (const std::string &field, const std::string &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, EndsWith, (const std::string &field, const std::string &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, GroupBy, (const std::vector<std::string> &fields), (override));
    MOCK_METHOD(AbsRdbPredicates *, IndexedBy, (const std::string &indexName), (override));
    MOCK_METHOD(AbsRdbPredicates *, Contains, (const std::string &field, const std::string &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, NotContains, (const std::string &field, const std::string &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, Glob, (const std::string &field, const std::string &value), (override));
    MOCK_METHOD(AbsRdbPredicates *, Between,
        (const std::string &field, const ValueObject &low, const ValueObject &high), (override));
    MOCK_METHOD(AbsRdbPredicates *, NotBetween,
        (const std::string &field, const ValueObject &low, const ValueObject &high), (override));
};
class RdbDataShareAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void GenerateDefaultTable();
    void GenerateDefaultEmptyTable();
    int ResultSize(std::shared_ptr<ResultSet> resultSet);
    OperationItem CreateOperationItem(int operation, const std::vector<SingleValue::Type> &singleParams,
        const std::vector<MutliValue::Type> &multiParams);
    void LessThanTest(MockRdbPredicates &predicates);
    void GreaterThanOrEqualTo(MockRdbPredicates &predicates);
    void LessThanOrEqualTo(MockRdbPredicates &predicates);
    void IsNull(MockRdbPredicates &predicates);
    void IsNotNull(MockRdbPredicates &predicates);
    void In(MockRdbPredicates &predicates);
    void NotIn(MockRdbPredicates &predicates);
    void Like(MockRdbPredicates &predicates);
    void NotLike(MockRdbPredicates &predicates);
    void OrderByAsc(MockRdbPredicates &predicates);
    void OrderByDesc(MockRdbPredicates &predicates);
    void Offset(MockRdbPredicates &predicates);
    void BeginsWith(MockRdbPredicates &predicates);
    void EndsWith(MockRdbPredicates &predicates);
    void GroupBy(MockRdbPredicates &predicates);
    void IndexedBy(MockRdbPredicates &predicates);
    void Contains(MockRdbPredicates &predicates);
    void NotContains(MockRdbPredicates &predicates);
    void Glob(MockRdbPredicates &predicates);
    void Between(MockRdbPredicates &predicates);
    void NotBetween(MockRdbPredicates &predicates);
    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;
    static const std::string RDB_ADAPTER_TEST_PATH;
};
const std::string RdbDataShareAdapterTest::RDB_ADAPTER_TEST_PATH = "/data/test/";
const std::string RdbDataShareAdapterTest::DATABASE_NAME = RDB_ADAPTER_TEST_PATH + "rdbDataShareAdapter_test.db";
std::shared_ptr<RdbStore> RdbDataShareAdapterTest::store = nullptr;

class RdbStepSharedResultSetOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;

    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;

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
    store->ExecuteSql(insertSql, std::vector<ValueObject>{ ValueObject(std::string("hello")), ValueObject((int)10),
                                     ValueObject((double)1.0), ValueObject((std::vector<uint8_t>)typeBlob) });

    /* insert second entry data */
    typeBlob.clear();
    store->ExecuteSql(insertSql, std::vector<ValueObject>{
                                     ValueObject(std::string("2")), ValueObject((int)-5), ValueObject((double)2.5),
                                     ValueObject() // set double value 2.5
                                 });

    /* insert third entry data */
    store->ExecuteSql(
        insertSql, std::vector<ValueObject>{
            ValueObject(std::string("hello world")), ValueObject((int)3), ValueObject((double)1.8),
                ValueObject(std::vector<uint8_t>{ 4, 5, 6 }) // set int value 3, double 1.8
    });

    /* insert four entry data */
    store->ExecuteSql(insertSql, std::vector<ValueObject>{
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

int RdbDataShareAdapterTest::ResultSize(std::shared_ptr<ResultSet> resultSet)
{
    if (resultSet->GoToFirstRow() != OHOS::NativeRdb::E_OK) {
        return 0;
    }
    int count = 1;
    while (resultSet->GoToNextRow() == OHOS::NativeRdb::E_OK) {
        count++;
    }
    return count;
}

OperationItem RdbDataShareAdapterTest::CreateOperationItem(int operation,
    const std::vector<SingleValue::Type> &singleParams = {}, const std::vector<MutliValue::Type> &multiParams = {})
{
    OperationItem item;
    item.operation = operation;
    item.singleParams = singleParams;
    item.multiParams = multiParams;
    return item;
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
    auto allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
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
    auto allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
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
    predicates.SetWhereArgs(std::vector<std::string>{ "-5" });
    predicates.SetOrder("data3");
    std::vector<std::string> columns;
    auto allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
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
    values.Put("data4", std::vector<uint8_t>{ 20, 21, 22 });

    int ret = store->Insert(id, "test", RdbUtils::ToValuesBucket(values));
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(5, id);

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates;
    std::string value = "tulip";
    predicates.EqualTo("data1", value);
    std::vector<std::string> columns;
    auto allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
    int rowCount;
    allDataTypes.get()->GetRowCount(rowCount);
    EXPECT_EQ(rowCount, 1);

    allDataTypes.get()->Close();

    values.Clear();
    values.Put("data3", 300.5);
    values.Put("data4", std::vector<uint8_t>{ 17, 18, 19 });
    ret = store->Update(
        changedRows, "test", RdbUtils::ToValuesBucket(values), "data1 = ?", std::vector<std::string>{ "tulip" });
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
    GenerateDefaultTable();

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates;
    predicates.Limit(1, 2);
    std::vector<std::string> columns;
    auto allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
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

/* *
 * @tc.name: Rdb_DataShare_Adapter_007
 * @tc.desc: normal testcase of RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_007, TestSize.Level1)
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT,") +
                                 std::string("age INTEGER, salary REAL);");
    store->ExecuteSql(createTableSql);

    DataShareValuesBucket values;
    int64_t id;
    values.Put("name", std::string("zhangsan"));
    values.Put("age", INT64_MIN);
    values.Put("salary", DBL_MIN);
    int ret1 = store->Insert(id, "test", RdbUtils::ToValuesBucket(values));
    EXPECT_EQ(ret1, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.Put("name", std::string("lisi"));
    values.Put("age", INT64_MAX);
    values.Put("salary", DBL_MAX);
    int ret2 = store->Insert(id, "test", RdbUtils::ToValuesBucket(values));
    EXPECT_EQ(ret2, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(2, id);

    std::string table = "test";
    OHOS::DataShare::DataSharePredicates predicates;
    std::vector<std::string> columns;
    auto allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, table), columns);

    allDataTypes->GoToFirstRow();
    int64_t int64Value;
    allDataTypes->GetLong(2, int64Value);
    EXPECT_EQ(int64Value, INT64_MIN);

    double doubleVal;
    allDataTypes->GetDouble(3, doubleVal);
    EXPECT_EQ(doubleVal, DBL_MIN);

    allDataTypes->GoToNextRow();

    allDataTypes->GetLong(2, int64Value);
    EXPECT_EQ(int64Value, INT64_MAX);

    allDataTypes->GetDouble(3, doubleVal);
    EXPECT_EQ(doubleVal, DBL_MAX);
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_008
 * @tc.desc: normal testcase of query double
 * @tc.type: test double for high accuracy
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_008, TestSize.Level1)
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, data1 double,") +
                                 std::string("data2 double, data3 TEXT);");
    store->ExecuteSql(createTableSql);

    ValuesBucket values;
    int64_t id;
    double data1 = 1.777777777777;
    double data2 = 1.888888888888;
    std::string data3 = "zh-has";
    std::string tableName = "test";

    values.PutDouble("data1", data1);
    values.PutDouble("data2", data2);
    values.PutString("data3", data3);
    int ret = store->Insert(id, tableName, values);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(1, id);

    OHOS::DataShare::DataSharePredicates predicates;
    predicates.BeginWrap()
        ->EqualTo("data1", data1)
        ->And()
        ->EqualTo("data2", data2)
        ->And()
        ->EqualTo("data3", data3)
        ->EndWrap();
    std::vector<std::string> columns;
    auto allDataTypes = store->Query(RdbUtils::ToPredicates(predicates, tableName), columns);
    int rowCount;
    int ok = allDataTypes->GetRowCount(rowCount);
    EXPECT_EQ(ok, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(1, rowCount);
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_009
 * @tc.desc: normal testcase of RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_009, TestSize.Level1)
{
    std::string createTableSql = std::string("CREATE TABLE test (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT,") +
                                 std::string("age INTEGER, salary REAL);");
    store->ExecuteSql(createTableSql);

    DataShareValuesBucket values;
    int64_t id;
    values.Put("name", std::string("zhangsan"));
    values.Put("age", INT64_MIN);
    values.Put("salary", DBL_MIN);
    int ret1 = store->Insert(id, "test", RdbUtils::ToValuesBucket(values));
    EXPECT_EQ(ret1, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.Put("name", std::string("lisi"));
    values.Put("age", INT64_MAX);
    values.Put("salary", DBL_MAX);
    int ret2 = store->Insert(id, "test", RdbUtils::ToValuesBucket(values));
    EXPECT_EQ(ret2, OHOS::NativeRdb::E_OK);
    EXPECT_EQ(2, id);

    std::string table = "test";
    OHOS::DataShare::OperationItem item;
    item.singleParams = {};
    RdbPredicates predicates("test");
    RdbUtils::EqualTo(item, predicates);
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allPerson = store->Query(predicates, columns);
    EXPECT_EQ(2, ResultSize(allPerson));

    RdbUtils::GreaterThan(item, predicates);
    allPerson = store->Query(predicates, columns);
    EXPECT_EQ(2, ResultSize(allPerson));

    RdbUtils::Limit(item, predicates);
    allPerson = store->Query(predicates, columns);
    EXPECT_EQ(2, ResultSize(allPerson));

    RdbUtils::NotEqualTo(item, predicates);
    allPerson = store->Query(predicates, columns);
    EXPECT_EQ(2, ResultSize(allPerson));

    RdbUtils::LessThan(item, predicates);
    allPerson = store->Query(predicates, columns);
    EXPECT_EQ(2, ResultSize(allPerson));
}

/* *
 * @tc.name: Rdb_DataShare_Adapter_010
 * @tc.desc: normal testcase of RdbDataShareAdapter
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, Rdb_DataShare_Adapter_010, TestSize.Level1)
{
    GenerateDefaultTable();

    std::string table = "test";
    std::string column = "data1";
    std::string value = "%hello%";
    DataSharePredicates predicates;
    predicates.Unlike(column, value);
    std::vector<std::string> columns;
    auto result = store->Query(RdbUtils::ToPredicates(predicates, table), columns);
    int rowCount = 0;
    if (result.get() != nullptr) {
        result.get()->GetRowCount(rowCount);
    }
    EXPECT_EQ(rowCount, 2);
}

void RdbDataShareAdapterTest::LessThanTest(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, LessThan(testing::_, testing::_)).Times(1);
    auto item = CreateOperationItem(0, { "name", "John" });
    RdbUtils::LessThan(item, predicates);
}

void RdbDataShareAdapterTest::GreaterThanOrEqualTo(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, GreaterThanOrEqualTo(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, { "John" });
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::GreaterThanOrEqualTo(item1, predicates);
    RdbUtils::GreaterThanOrEqualTo(item2, predicates);
}

void RdbDataShareAdapterTest::LessThanOrEqualTo(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, LessThanOrEqualTo(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, { "John" });
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::LessThanOrEqualTo(item1, predicates);
    RdbUtils::LessThanOrEqualTo(item2, predicates);
}

void RdbDataShareAdapterTest::IsNull(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, IsNull(testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::IsNull(item1, predicates);
    RdbUtils::IsNull(item2, predicates);
}

void RdbDataShareAdapterTest::IsNotNull(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, IsNotNull(testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::IsNotNull(item1, predicates);
    RdbUtils::IsNotNull(item2, predicates);
}

void RdbDataShareAdapterTest::In(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, In(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0);
    auto item2 = CreateOperationItem(0, { "test_table", "John" });
    auto item3 = CreateOperationItem(0, {}, { std::vector<std::string>{ "zhangSan" }, std::vector<int>{ 1, 2, 3 } });
    auto item4 = CreateOperationItem(
        0, { "test_table", 2 }, { std::vector<std::string>{ "zhangSan" }, std::vector<int>{ 1, 2, 3 } });
    RdbUtils::In(item1, predicates);
    RdbUtils::In(item2, predicates);
    RdbUtils::In(item3, predicates);
    RdbUtils::In(item4, predicates);
}

void RdbDataShareAdapterTest::NotIn(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, NotIn(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0);
    auto item2 = CreateOperationItem(0, { "test_table", "John" });
    auto item3 = CreateOperationItem(0, {}, { std::vector<std::string>{ "zhangSan" }, std::vector<int>{ 1, 2, 3 } });
    auto item4 = CreateOperationItem(
        0, { "test_table", 2 }, { std::vector<std::string>{ "zhangSan" }, std::vector<int>{ 1, 2, 3 } });
    RdbUtils::NotIn(item1, predicates);
    RdbUtils::NotIn(item2, predicates);
    RdbUtils::NotIn(item3, predicates);
    RdbUtils::NotIn(item4, predicates);
}

void RdbDataShareAdapterTest::Like(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, Like(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::Like(item1, predicates);
    RdbUtils::Like(item2, predicates);
}

void RdbDataShareAdapterTest::NotLike(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, NotLike(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::NotLike(item1, predicates);
    RdbUtils::NotLike(item2, predicates);
}

void RdbDataShareAdapterTest::OrderByAsc(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, OrderByAsc(testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::OrderByAsc(item1, predicates);
    RdbUtils::OrderByAsc(item2, predicates);
}

void RdbDataShareAdapterTest::OrderByDesc(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, OrderByDesc(testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::OrderByDesc(item1, predicates);
    RdbUtils::OrderByDesc(item2, predicates);
}

void RdbDataShareAdapterTest::Offset(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, Offset(testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::Offset(item1, predicates);
    RdbUtils::Offset(item2, predicates);
}

void RdbDataShareAdapterTest::BeginsWith(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, BeginsWith(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::BeginsWith(item1, predicates);
    RdbUtils::BeginsWith(item2, predicates);
}

void RdbDataShareAdapterTest::EndsWith(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, EndsWith(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::EndsWith(item1, predicates);
    RdbUtils::EndsWith(item2, predicates);
}

void RdbDataShareAdapterTest::GroupBy(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, GroupBy(testing::_)).Times(1);
    auto item1 = CreateOperationItem(0);
    auto item2 = CreateOperationItem(0, {}, { std::vector<std::string>{ "zhangSan" }, std::vector<int>{ 1, 2, 3 } });
    RdbUtils::GroupBy(item1, predicates);
    RdbUtils::GroupBy(item2, predicates);
}

void RdbDataShareAdapterTest::IndexedBy(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, IndexedBy(testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::IndexedBy(item1, predicates);
    RdbUtils::IndexedBy(item2, predicates);
}

void RdbDataShareAdapterTest::Contains(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, Contains(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::Contains(item1, predicates);
    RdbUtils::Contains(item2, predicates);
}

void RdbDataShareAdapterTest::NotContains(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, NotContains(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::NotContains(item1, predicates);
    RdbUtils::NotContains(item2, predicates);
}

void RdbDataShareAdapterTest::Glob(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, Glob(testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", "John" });
    RdbUtils::Glob(item1, predicates);
    RdbUtils::Glob(item2, predicates);
}

void RdbDataShareAdapterTest::Between(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, Between(testing::_, testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", 1, true });
    RdbUtils::Between(item1, predicates);
    RdbUtils::Between(item2, predicates);
}

void RdbDataShareAdapterTest::NotBetween(MockRdbPredicates &predicates)
{
    EXPECT_CALL(predicates, NotBetween(testing::_, testing::_, testing::_)).Times(1);
    auto item1 = CreateOperationItem(0, {});
    auto item2 = CreateOperationItem(0, { "name", 1, true });
    RdbUtils::NotBetween(item1, predicates);
    RdbUtils::NotBetween(item2, predicates);
}

/**
 * @tc.name: RdbUtils_Operation_Test
 * @tc.desc: Test all operation handlers in RdbUtils
 * @tc.type: FUNC
 */
HWTEST_F(RdbDataShareAdapterTest, RdbUtils_Operation_Test, TestSize.Level1)
{
    LOG_INFO("RdbUtils_Operation_Test start");
    MockRdbPredicates predicates("test_table");
    LessThanTest(predicates);
    GreaterThanOrEqualTo(predicates);
    LessThanOrEqualTo(predicates);
    IsNull(predicates);
    IsNotNull(predicates);
    In(predicates);
    NotIn(predicates);
    Like(predicates);
    NotLike(predicates);
    OrderByAsc(predicates);
    OrderByDesc(predicates);
    Offset(predicates);
    BeginsWith(predicates);
    EndsWith(predicates);
    GroupBy(predicates);
    IndexedBy(predicates);
    Contains(predicates);
    NotContains(predicates);
    Glob(predicates);
    Between(predicates);
    NotBetween(predicates);
}
