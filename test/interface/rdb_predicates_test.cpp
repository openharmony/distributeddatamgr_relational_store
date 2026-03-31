/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "rdb_predicates.h"

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <climits>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

#include "abs_rdb_predicates.h"
#include "rdb_test_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

// Blob test data
constexpr int BLOB_VALUE_2 = 2;

// Test data counts
constexpr int EXPECTED_TWO_ROWS = 2;
constexpr int EXPECTED_THREE_ROWS = 3;

// Date related constants
constexpr int BASE_YEAR_OFFSET = 1990;

class RdbTestDataEntity {
public:
    int GetId() const
    {
        return id;
    }

    void SetId(int id)
    {
        this->id = id;
    }

    int GetIntegerValue() const
    {
        return integerValue;
    }

    void SetIntegerValue(int integerValue)
    {
        this->integerValue = integerValue;
    }

    int64_t GetLongValue() const
    {
        return longValue;
    }

    void SetLongValue(int64_t longValue)
    {
        this->longValue = longValue;
    }

    short GetShortValue() const
    {
        return shortValue;
    }

    void SetShortValue(short shortValue)
    {
        this->shortValue = shortValue;
    }

    bool GetBooleanValue() const
    {
        return booleanValue;
    }

    void SetBooleanValue(bool booleanValue)
    {
        this->booleanValue = booleanValue;
    }

    double GetDoubleValue() const
    {
        return doubleValue;
    }

    void SetDoubleValue(double doubleValue)
    {
        this->doubleValue = doubleValue;
    }

    float GetFloatValue() const
    {
        return floatValue;
    }

    void SetFloatValue(float floatValue)
    {
        this->floatValue = floatValue;
    }

    std::string GetStringValue() const
    {
        return stringValue;
    }

    void SetStringValue(std::string stringValue)
    {
        this->stringValue = stringValue;
    }

    std::vector<uint8_t> GetBlobValue() const
    {
        return blobValue;
    }

    void SetBlobValue(std::vector<uint8_t> blobValue)
    {
        this->blobValue = blobValue;
    }

    std::string GetClobValue() const
    {
        return clobValue;
    }

    void SetClobValue(std::string clobValue)
    {
        this->clobValue = clobValue;
    }

    int8_t GetByteValue() const
    {
        return byteValue;
    }

    void SetByteValue(int8_t byteValue)
    {
        this->byteValue = byteValue;
    }

    time_t GetTimeValue() const
    {
        return timeValue;
    }

    void SetTimeValue(time_t timeValue)
    {
        this->timeValue = timeValue;
    }

    char GetCharacterValue() const
    {
        return characterValue;
    }

    void SetCharacterValue(char characterValue)
    {
        this->characterValue = characterValue;
    }

    int GetPrimIntValue() const
    {
        return primIntValue;
    }

    void SetPrimIntValue(int primIntValue)
    {
        this->primIntValue = primIntValue;
    }

    int64_t GetPrimLongValue() const
    {
        return primLongValue;
    }

    void SetPrimLongValue(int64_t primLongValue)
    {
        this->primLongValue = primLongValue;
    }

    short GetPrimShortValue() const
    {
        return primShortValue;
    }

    void SetPrimShortValue(short primShortValue)
    {
        this->primShortValue = primShortValue;
    }

    float GetPrimFloatValue() const
    {
        return primFloatValue;
    }

    void SetPrimFloatValue(float primFloatValue)
    {
        this->primFloatValue = primFloatValue;
    }

    double GetPrimDoubleValue() const
    {
        return primDoubleValue;
    }

    void SetPrimDoubleValue(double primDoubleValue)
    {
        this->primDoubleValue = primDoubleValue;
    }

    bool IsPrimBooleanValue() const
    {
        return primBooleanValue;
    }

    void SetPrimBooleanValue(bool primBooleanValue)
    {
        this->primBooleanValue = primBooleanValue;
    }

    int8_t GetPrimByteValue() const
    {
        return primByteValue;
    }

    void SetPrimByteValue(int8_t primByteValue)
    {
        this->primByteValue = primByteValue;
    }

    char GetPrimCharValue() const
    {
        return primCharValue;
    }

    void SetPrimCharValue(char primCharValue)
    {
        this->primCharValue = primCharValue;
    }

    int GetOrder() const
    {
        return order;
    }

    void SetOrder(int order)
    {
        this->order = order;
    }

private:
    int id;

    int integerValue;

    int64_t longValue;

    short shortValue;

    bool booleanValue = false;

    double doubleValue;

    float floatValue;

    std::string stringValue;

    std::vector<uint8_t> blobValue;

    std::string clobValue;

    int8_t byteValue;

    time_t timeValue;

    int primIntValue;

    char characterValue;

    int64_t primLongValue;

    short primShortValue;

    float primFloatValue;

    double primDoubleValue;

    bool primBooleanValue = false;

    int8_t primByteValue;

    char primCharValue;

    int order;
};

class RdbPredicatesInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;

    time_t DateMakeTime(std::vector<int> data);
    void InsertDates(std::vector<RdbTestDataEntity> dataTypes);
    RdbTestDataEntity BuildRdbTestDataEntityBase(int id);
    RdbTestDataEntity BuildRdbTestDataEntity1();
    RdbTestDataEntity BuildRdbTestDataEntity2();
    RdbTestDataEntity BuildRdbTestDataEntity3();
    void GenerateRdbTestDataEntityTable();
    void BasicDataTypeTest(RdbPredicates predicates);
    int ResultSize(std::shared_ptr<ResultSet> &resultSet);
    void BasicDataTypeTest002(RdbPredicates predicates);
    void SetJionList(RdbPredicates &predicates);
    void SetEntityTimeValue(RdbTestDataEntity& dataType, const std::vector<int>& date);
};

std::shared_ptr<RdbStore> RdbPredicatesInterfaceTest::store = nullptr;
const std::string RdbPredicatesInterfaceTest::DATABASE_NAME = RDB_TEST_PATH + "predicates_test.db";
const std::string CREATE_TABLE_ALL_DATA_TYPE_SQL =
    "CREATE TABLE IF NOT EXISTS RdbTestDataEntity "
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, integerValue INTEGER , longValue INTEGER , "
    "shortValue INTEGER , booleanValue INTEGER , doubleValue REAL , floatValue REAL , "
    "stringValue TEXT , blobValue BLOB , clobValue TEXT , byteValue INTEGER , "
    "timeValue INTEGER , characterValue TEXT , primIntValue INTEGER ,"
    "primLongValue INTEGER  NOT NULL, primShortValue INTEGER  NOT NULL, "
    "primFloatValue REAL  NOT NULL, primDoubleValue REAL  NOT NULL, "
    "primBooleanValue INTEGER  NOT NULL, primByteValue INTEGER  NOT NULL, "
    "primCharValue TEXT, `orderr` INTEGER);";

const std::string CREATE_TABLE_PERSON_SQL =
    "CREATE TABLE IF NOT EXISTS person "
    "(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT , age INTEGER , REAL INTEGER, attachments ASSETS,"
    "attachment ASSET);";

const std::string ALL_DATA_TYPE_INSERT_SQL =
    "INSERT INTO RdbTestDataEntity (id, integerValue, longValue, "
    "shortValue, booleanValue, doubleValue, floatValue, stringValue, blobValue, "
    "clobValue, byteValue, timeValue, characterValue, primIntValue, primLongValue, "
    "primShortValue, primFloatValue, primDoubleValue, "
    "primBooleanValue, primByteValue, primCharValue, `orderr`) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";
const std::string HAVING_CREATE_SQL =
    "CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER, amount INTEGER)";
const std::string HAVING_INSERT_SQL =
    "INSERT INTO orders (customer_id, amount) VALUES (1, 1500), (1, 2000), (1, 3000), (2, 800), (2, 1200), (3, 1500),"
    " (3, 2000), (3, 2500), (3, 1000)";
const std::string HAVING_DROP_SQL = "DROP TABLE IF EXISTS orders";
class RdbPredicatesTestCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override;
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override;
};

int RdbPredicatesTestCallback::OnCreate(RdbStore &rdbStore)
{
    return E_OK;
}

int RdbPredicatesTestCallback::OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbPredicatesInterfaceTest::SetUpTestCase()
{
}

void RdbPredicatesInterfaceTest::TearDownTestCase()
{
    RdbHelper::DeleteRdbStore(RdbPredicatesInterfaceTest::DATABASE_NAME);
}

void RdbPredicatesInterfaceTest::SetUp()
{
    if (access(RdbPredicatesInterfaceTest::DATABASE_NAME.c_str(), F_OK) != 0) {
        remove(RdbPredicatesInterfaceTest::DATABASE_NAME.c_str());
    }

    int errCode = E_OK;
    RdbStoreConfig config(RdbPredicatesInterfaceTest::DATABASE_NAME);
    RdbPredicatesTestCallback helper;
    RdbPredicatesInterfaceTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbPredicatesInterfaceTest::store, nullptr);

    RdbPredicatesInterfaceTest::GenerateRdbTestDataEntityTable();
}

void RdbPredicatesInterfaceTest::TearDown(void)
{
}

void RdbPredicatesInterfaceTest::GenerateRdbTestDataEntityTable()
{
    RdbPredicatesInterfaceTest::store->ExecuteSql(CREATE_TABLE_ALL_DATA_TYPE_SQL);
    RdbPredicatesInterfaceTest::store->ExecuteSql(CREATE_TABLE_PERSON_SQL);

    RdbTestDataEntity dataType1 = RdbPredicatesInterfaceTest::BuildRdbTestDataEntity1();
    RdbTestDataEntity dataType2 = RdbPredicatesInterfaceTest::BuildRdbTestDataEntity2();
    RdbTestDataEntity dataType3 = RdbPredicatesInterfaceTest::BuildRdbTestDataEntity3();

    std::vector<RdbTestDataEntity> dataTypes;
    dataTypes.push_back(dataType1);
    dataTypes.push_back(dataType2);
    dataTypes.push_back(dataType3);
    RdbPredicatesInterfaceTest::InsertDates(dataTypes);
}

RdbTestDataEntity RdbPredicatesInterfaceTest::BuildRdbTestDataEntityBase(int id)
{
    std::vector<uint8_t> blob = { 1, 2, 3 };
    RdbTestDataEntity dataType;
    dataType.SetId(id);
    dataType.SetCharacterValue(' ');
    dataType.SetStringValue("ABCDEFGHIJKLMN");
    dataType.SetBlobValue(blob);
    dataType.SetClobValue("ABCDEFGHIJKLMN");
    dataType.SetPrimCharValue(' ');
    return dataType;
}

void RdbPredicatesInterfaceTest::SetEntityTimeValue(RdbTestDataEntity& dataType, const std::vector<int>& date)
{
    time_t timeValue = DateMakeTime(date);
    dataType.SetTimeValue(timeValue);
}

RdbTestDataEntity RdbPredicatesInterfaceTest::BuildRdbTestDataEntity1()
{
    RdbTestDataEntity dataType = BuildRdbTestDataEntityBase(1);
    dataType.SetIntegerValue(INT_MAX);
    dataType.SetDoubleValue(DBL_MAX);
    dataType.SetBooleanValue(true);
    dataType.SetFloatValue(FLT_MAX);
    dataType.SetLongValue(LONG_MAX);
    dataType.SetShortValue(SHRT_MAX);
    dataType.SetByteValue(INT8_MAX);

    std::vector<int> date = { 2019, 7, 10 };
    SetEntityTimeValue(dataType, date);

    dataType.SetPrimIntValue(INT_MAX);
    dataType.SetPrimDoubleValue(DBL_MAX);
    dataType.SetPrimFloatValue(FLT_MAX);
    dataType.SetPrimBooleanValue(true);
    dataType.SetPrimByteValue(INT8_MAX);
    dataType.SetPrimLongValue(LONG_MAX);
    dataType.SetPrimShortValue(SHRT_MAX);
    return dataType;
}

RdbTestDataEntity RdbPredicatesInterfaceTest::BuildRdbTestDataEntity2()
{
    RdbTestDataEntity dataType = BuildRdbTestDataEntityBase(2);
    dataType.SetIntegerValue(1);
    dataType.SetDoubleValue(1.0);
    dataType.SetBooleanValue(false);
    dataType.SetFloatValue(1.0);
    dataType.SetLongValue(static_cast<int64_t>(1));
    dataType.SetShortValue(static_cast<short>(1));
    dataType.SetByteValue(INT8_MIN);

    std::vector<int> date = { 2019, 7, 17 };
    SetEntityTimeValue(dataType, date);

    dataType.SetPrimIntValue(1);
    dataType.SetPrimDoubleValue(1.0);
    dataType.SetPrimFloatValue(1.0);
    dataType.SetPrimBooleanValue(false);
    dataType.SetPrimByteValue(static_cast<char>(1));
    dataType.SetPrimLongValue(static_cast<int64_t>(1));
    dataType.SetPrimShortValue(static_cast<short>(1));
    return dataType;
}

RdbTestDataEntity RdbPredicatesInterfaceTest::BuildRdbTestDataEntity3()
{
    RdbTestDataEntity dataType = BuildRdbTestDataEntityBase(3);
    dataType.SetIntegerValue(INT_MIN);
    dataType.SetDoubleValue(DBL_MIN);
    dataType.SetBooleanValue(false);
    dataType.SetFloatValue(FLT_MIN);
    dataType.SetLongValue(LONG_MIN);
    dataType.SetShortValue(SHRT_MIN);
    dataType.SetByteValue(INT8_MIN);

    std::vector<int> date = { 2019, 6, 10 };
    SetEntityTimeValue(dataType, date);

    dataType.SetPrimIntValue(INT_MIN);
    dataType.SetPrimDoubleValue(DBL_MIN);
    dataType.SetPrimFloatValue(FLT_MIN);
    dataType.SetPrimBooleanValue(false);
    dataType.SetPrimByteValue(INT8_MIN);
    dataType.SetPrimLongValue(LONG_MIN);
    dataType.SetPrimShortValue(SHRT_MIN);
    return dataType;
}

void RdbPredicatesInterfaceTest::InsertDates(std::vector<RdbTestDataEntity> dataTypes)
{
    for (size_t i = 0; i < dataTypes.size(); i++) {
        char characterValue = dataTypes[i].GetCharacterValue();
        char primCharValue = dataTypes[i].GetPrimCharValue();
        std::stringstream strByte;
        std::vector<ValueObject> objects;
        objects.push_back(ValueObject(dataTypes[i].GetId()));
        objects.push_back(ValueObject(dataTypes[i].GetIntegerValue()));
        objects.push_back(ValueObject(dataTypes[i].GetLongValue()));
        objects.push_back(ValueObject(dataTypes[i].GetShortValue()));
        objects.push_back(ValueObject(dataTypes[i].GetBooleanValue()));

        strByte << dataTypes[i].GetDoubleValue();
        objects.push_back(ValueObject(strByte.str()));

        strByte.str("");
        strByte << dataTypes[i].GetFloatValue();
        objects.push_back(ValueObject(strByte.str()));
        objects.push_back(ValueObject(dataTypes[i].GetStringValue()));
        objects.push_back(ValueObject(dataTypes[i].GetBlobValue()));
        objects.push_back(ValueObject(dataTypes[i].GetClobValue()));
        objects.push_back(ValueObject(dataTypes[i].GetByteValue()));
        objects.push_back(ValueObject(static_cast<int64_t>(dataTypes[i].GetTimeValue())));

        strByte.str("");
        strByte << characterValue;
        string str1 = strByte.str();
        objects.push_back(ValueObject(str1));
        objects.push_back(ValueObject(dataTypes[i].GetPrimIntValue()));
        objects.push_back(ValueObject(dataTypes[i].GetPrimLongValue()));
        objects.push_back(ValueObject(dataTypes[i].GetPrimShortValue()));

        strByte.str("");
        strByte << dataTypes[i].GetPrimFloatValue();
        objects.push_back(ValueObject(strByte.str()));

        strByte.str("");
        strByte << dataTypes[i].GetPrimDoubleValue();
        objects.push_back(ValueObject(strByte.str()));
        objects.push_back(ValueObject(dataTypes[i].IsPrimBooleanValue() ? (char)1 : (char)0));
        objects.push_back(ValueObject(dataTypes[i].GetPrimByteValue()));

        strByte.str("");
        strByte << primCharValue;
        string str2 = strByte.str();
        objects.push_back(ValueObject(str2));
        objects.push_back(ValueObject());
        RdbPredicatesInterfaceTest::store->ExecuteSql(ALL_DATA_TYPE_INSERT_SQL, objects);
    }
}

time_t RdbPredicatesInterfaceTest::DateMakeTime(std::vector<int> data)
{
    struct tm t = { 0 };
    t.tm_year = data[0] - BASE_YEAR_OFFSET;
    t.tm_mon = data[1] - 1;
    t.tm_hour = data[BLOB_VALUE_2];
    t.tm_sec = 0;
    t.tm_min = 0;
    t.tm_mday = 0;
    time_t time = mktime(&t);
    return time;
}

/* *
 * @tc.name: RdbStore_RdbPredicates_001
 * @tc.desc: Abnormal testCase of RdbPredicates, if tableName is ""
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_RdbPredicates_001, TestSize.Level1)
{
    AbsRdbPredicates predicates("");
    predicates.EqualTo("integerValue", "1");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();

    // if predicates HasSpecificField
    predicates.OrderByAsc("#_number");
    bool hasSpecificField = predicates.HasSpecificField();
    EXPECT_EQ(true, hasSpecificField);
    std::shared_ptr<AbsSharedResultSet> resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_NE(nullptr, resultSet);
    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_RdbPredicates_002
 * @tc.desc: Abnormal testCase of RdbPredicates, if tableNames is [] or counts is rather than 1
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_RdbPredicates_002, TestSize.Level1)
{
    std::vector<std::string> tableEmpty;
    std::vector<std::string> tables({ "RdbTestDataEntity", "person" });

    AbsRdbPredicates predicatesEmpty(tableEmpty);
    AbsRdbPredicates predicates(tables);
    predicates.EqualTo("id", "1");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_EqualTo_001
 * @tc.desc: Normal testCase of RdbPredicates for EqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_EqualTo_001, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");

    BasicDataTypeTest(predicates);

    // Calendar test: Query records where timeValue equals specific date
    std::vector<std::string> columns;
    predicates.Clear();
    std::vector<int> date = { 2019, 7, 17 };
    time_t calendarTime = RdbPredicatesInterfaceTest::DateMakeTime(date);
    predicates.EqualTo("timeValue", std::to_string(calendarTime));
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());
    int valueInt = 0;
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(BLOB_VALUE_2, valueInt);
}

/* *
 * @tc.name: RdbStore_EqualTo_002
 * @tc.desc: Normal testCase of RdbPredicates for EqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_EqualTo_002, TestSize.Level1)
{
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsi"));
    values.PutInt("age", 18);
    values.PutInt("REAL", 100);
    int ret = store->Insert(id, "person", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("zhangsi"));
    values.PutInt("age", 18);
    values.PutInt("REAL", 100);
    ret = store->Insert(id, "person", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(BLOB_VALUE_2, id);

    RdbPredicates predicates("person");
    predicates.EqualTo("name", "");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allPerson = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allPerson));

    predicates = RdbPredicates("person");
    predicates.EqualTo("name", "zhangsi");
    allPerson = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allPerson));
    RdbPredicatesInterfaceTest::store->ExecuteSql("delete from person where id < 3;");
}

void RdbPredicatesInterfaceTest::BasicDataTypeTest(RdbPredicates predicates)
{
    std::vector<std::string> columns;
    std::stringstream tempValue;
    predicates.EqualTo("booleanValue", "1");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.EqualTo("byteValue", std::to_string(INT8_MIN))->Or()->EqualTo("byteValue", std::to_string(1));
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates.EqualTo("doubleValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.EqualTo("shortValue", std::to_string(SHRT_MIN));
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.EqualTo("integerValue", std::to_string(1));
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());
    int valueInt = 0;
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(BLOB_VALUE_2, valueInt);

    predicates.Clear();
    predicates.EqualTo("longValue", std::to_string(1));
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(BLOB_VALUE_2, valueInt);

    predicates.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates.EqualTo("floatValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(EXPECTED_THREE_ROWS, valueInt);

    predicates.Clear();
    predicates.EqualTo("blobValue", std::vector<uint8_t>{ 1, 2, 3 });
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    // 3 rows in the resultSet when blobValue={1, 2, 3}
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

int RdbPredicatesInterfaceTest::ResultSize(std::shared_ptr<ResultSet> &resultSet)
{
    if (resultSet->GoToFirstRow() != E_OK) {
        return 0;
    }
    int count = 1;
    while (resultSet->GoToNextRow() == E_OK) {
        count++;
    }
    return count;
}

/* *
 * @tc.name: RdbStore_NotEqualTo_001
 * @tc.desc: Abnormal testCase of RdbPredicates for NotEqualTo, if field is ""
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_NotEqualTo_001, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.NotEqualTo("", "1");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_NotEqualTo_002
 * @tc.desc: Normal testCase of RdbPredicates for NotEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_NotEqualTo_002, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");

    BasicDataTypeTest002(predicates);

    // Calendar test: Query records where timeValue not equals specific date
    std::vector<std::string> columns;
    predicates.Clear();
    std::vector<int> date = { 2019, 7, 17 };
    time_t calendarTime = RdbPredicatesInterfaceTest::DateMakeTime(date);
    predicates.NotEqualTo("timeValue", std::to_string(calendarTime));
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_NotEqualTo_003
 * @tc.desc: Normal testCase of RdbPredicates for EqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_NotEqualTo_003, TestSize.Level1)
{
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsi"));
    values.PutInt("age", 18);
    values.PutInt("REAL", 100);
    int ret = store->Insert(id, "person", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    values.Clear();
    values.PutInt("id", 2);
    values.PutString("name", std::string("zhangsi"));
    values.PutInt("age", 18);
    values.PutInt("REAL", 100);
    ret = store->Insert(id, "person", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(BLOB_VALUE_2, id);

    values.Clear();
    values.PutInt("id", 3);
    values.PutString("name", std::string(""));
    values.PutInt("age", 18);
    values.PutInt("REAL", 100);
    ret = store->Insert(id, "person", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(3, id);

    RdbPredicates predicates("person");
    predicates.NotEqualTo("name", "");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allPerson = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allPerson));

    predicates = RdbPredicates("person");
    predicates.NotEqualTo("name", "zhangsi");

    allPerson = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allPerson));

    RdbPredicatesInterfaceTest::store->ExecuteSql("delete from person where id < 4;");
}

void RdbPredicatesInterfaceTest::BasicDataTypeTest002(RdbPredicates predicates)
{
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates.NotEqualTo("primBooleanValue", "1");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.NotEqualTo("primByteValue", std::to_string(INT8_MIN))->NotEqualTo("primByteValue", std::to_string(1));
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.NotEqualTo("stringValue", "ABCDEFGHIJKLMN");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates.NotEqualTo("doubleValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.NotEqualTo("shortValue", std::to_string(SHRT_MIN));
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.NotEqualTo("integerValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.NotEqualTo("longValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates.NotEqualTo("floatValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_IsNull_003
 * @tc.desc: Normal testCase of RdbPredicates for IsNull
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_IsNull_003, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.IsNull("primLongValue");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_NotNull_004
 * @tc.desc: Normal testCase of RdbPredicates for NotNull
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_NotNull_003, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.IsNotNull("primLongValue");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_GreaterThan_005
 * @tc.desc: Normal testCase of RdbPredicates for GreaterThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_GreaterThan_005, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates.GreaterThan("stringValue", "ABC");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates.GreaterThan("doubleValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.GreaterThan("integerValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.GreaterThan("longValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates.GreaterThan("floatValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    std::vector<int> date = { 2019, 6, 9 };
    time_t calendarTime = RdbPredicatesInterfaceTest::DateMakeTime(date);
    predicates.GreaterThan("timeValue", std::to_string(calendarTime).c_str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_GreaterThanOrEqualTo_006
 * @tc.desc: Normal testCase of RdbPredicates for GreaterThanOrEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_GreaterThanOrEqualTo_006, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates.GreaterThanOrEqualTo("stringValue", "ABC");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates.GreaterThanOrEqualTo("doubleValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.GreaterThanOrEqualTo("integerValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.GreaterThanOrEqualTo("longValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates.GreaterThanOrEqualTo("floatValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    std::vector<int> date = { 2019, 6, 9 };
    time_t calendarTime = RdbPredicatesInterfaceTest::DateMakeTime(date);
    predicates.GreaterThanOrEqualTo("timeValue", std::to_string(calendarTime).c_str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    // Abnormal testCase of RdbPredicates for GreaterThanOrEqualTo if field is empty
    predicates.Clear();
    predicates.GreaterThanOrEqualTo("", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_lessThan_007
 * @tc.desc: Normal testCase of RdbPredicates for LessThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_lessThan_007, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates.LessThan("stringValue", "ABD");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates.LessThan("doubleValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.LessThan("integerValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.LessThan("longValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates.LessThan("floatValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));

    predicates.Clear();
    std::vector<int> date = { 2019, 6, 9 };
    time_t calendarTime = RdbPredicatesInterfaceTest::DateMakeTime(date);
    predicates.LessThan("timeValue", std::to_string(calendarTime).c_str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_LessThanOrEqualTo_008
 * @tc.desc: Normal testCase of RdbPredicates for LessThanOrEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_LessThanOrEqualTo_008, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates.LessThanOrEqualTo("stringValue", "ABD");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates.LessThanOrEqualTo("doubleValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.LessThanOrEqualTo("integerValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.LessThanOrEqualTo("longValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates.LessThanOrEqualTo("floatValue", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    std::vector<int> date = { 2019, 6, 9 };
    time_t calendarTime = RdbPredicatesInterfaceTest::DateMakeTime(date);
    predicates.LessThanOrEqualTo("timeValue", std::to_string(calendarTime).c_str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_Between_009
 * @tc.desc: Normal testCase of RdbPredicates for Between
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_Between_009, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates.Between("stringValue", "ABB", "ABD");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << DBL_MAX;
    predicates.Between("doubleValue", "0.0", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.Between("integerValue", "0", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.Between("longValue", "0", "2");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << FLT_MAX;
    std::string floatMax = tempValue.str();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates.Between("floatValue", tempValue.str(), floatMax);
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    std::vector<int> lowCalendar = { 2019, 6, 9 };
    time_t lowCalendarTime = RdbPredicatesInterfaceTest::DateMakeTime(lowCalendar);
    std::vector<int> highCalendar = { 2019, 7, 17 };
    time_t highCalendarTime = RdbPredicatesInterfaceTest::DateMakeTime(highCalendar);
    predicates.Between("timeValue", std::to_string(lowCalendarTime).c_str(), std::to_string(highCalendarTime).c_str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_Contain_010
 * @tc.desc: Normal testCase of RdbPredicates for Contain
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_Contain_010, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.Contains("stringValue", "DEF");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_BeginsWith_011
 * @tc.desc: Normal testCase of RdbPredicates for BeginsWith
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_BeginsWith_011, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.BeginsWith("stringValue", "ABC");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_EndsWith_012
 * @tc.desc: Normal testCase of RdbPredicates for EndsWith
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_EndsWith_012, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.EndsWith("stringValue", "LMN");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_Like_013
 * @tc.desc: Normal testCase of RdbPredicates for Like
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_Like_013, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.Like("stringValue", "%LMN%");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_BeginEndWrap_014
 * @tc.desc: Normal testCase of RdbPredicates for BeginEndWrap
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_BeginEndWrap_014, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap();
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")->And()->EqualTo("integerValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_AndOR_015
 * @tc.desc: Normal testCase of RdbPredicates for AndOR
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_AndOR_015, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap();

    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")->And()->EqualTo("integerValue", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_Order_016
 * @tc.desc: Normal testCase of RdbPredicates for Order
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_Order_016, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")->OrderByAsc("integerValue")->Distinct();
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());
    int valueInt = 0;
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(EXPECTED_THREE_ROWS, valueInt);
    EXPECT_EQ(E_OK, allDataTypes->GoToNextRow());
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(BLOB_VALUE_2, valueInt);
    EXPECT_EQ(E_OK, allDataTypes->GoToNextRow());
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(1, valueInt);

    predicates.Clear();
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")->OrderByDesc("integerValue")->Distinct();
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(E_OK, allDataTypes->GoToFirstRow());
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(1, valueInt);
    EXPECT_EQ(E_OK, allDataTypes->GoToNextRow());
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(BLOB_VALUE_2, valueInt);
    EXPECT_EQ(E_OK, allDataTypes->GoToNextRow());
    allDataTypes->GetInt(0, valueInt);
    EXPECT_EQ(EXPECTED_THREE_ROWS, valueInt);
}

/* *
 * @tc.name: RdbStore_Limit_017
 * @tc.desc: Normal testCase of RdbPredicates for Limit
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_Limit_017, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")->Limit(1);
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_JoinTypes_018
 * @tc.desc: Normal testCase of RdbPredicates for JoinTypes
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_JoinTypes_018, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> joinEntityNames;

    joinEntityNames.push_back("RdbTestDataEntity");
    predicates.SetJoinTableNames(joinEntityNames);

    std::vector<std::string> joinTypes;
    joinTypes.push_back("INNER JOIN");
    predicates.SetJoinTypes(joinTypes);

    std::vector<std::string> joinConditions;
    joinConditions.push_back("ON");
    predicates.SetJoinConditions(joinConditions);
    predicates.SetJoinCount(1);

    EXPECT_EQ(joinConditions, predicates.GetJoinConditions());
    EXPECT_EQ(joinEntityNames, predicates.GetJoinTableNames());
    EXPECT_EQ(joinTypes, predicates.GetJoinTypes());
    EXPECT_EQ(1, predicates.GetJoinCount());
}

/* *
 * @tc.name: RdbStore_Glob_019
 * @tc.desc: Normal testCase of RdbPredicates for Glob
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_Glob_019, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.Glob("stringValue", "ABC*");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.Glob("stringValue", "*EFG*");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.Glob("stringValue", "?B*");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.Glob("stringValue", "A????????????N");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.Glob("stringValue", "A?????????????N");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.Glob("stringValue", "?B*N");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_NotBetween_020
 * @tc.desc: Normal testCase of RdbPredicates for NotBetween
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_NotBetween_020, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates.NotBetween("stringValue", "ABB", "ABD");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << DBL_MAX;
    predicates.NotBetween("doubleValue", "0.0", tempValue.str());
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.NotBetween("integerValue", "0", "1");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    predicates.NotBetween("longValue", "0", "2");
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    predicates.Clear();
    tempValue.str("");
    tempValue << FLT_MAX;
    std::string floatMax = tempValue.str();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates.NotBetween("floatValue", tempValue.str(), floatMax);
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));

    std::vector<int> lowCalendar = { 2019, 6, 9 };
    time_t lowCalendarTime = RdbPredicatesInterfaceTest::DateMakeTime(lowCalendar);
    std::vector<int> highCalendar = { 2019, 7, 17 };
    time_t highCalendarTime = RdbPredicatesInterfaceTest::DateMakeTime(highCalendar);
    predicates.Clear();
    predicates.NotBetween("timeValue", std::to_string(lowCalendarTime), std::to_string(highCalendarTime));
    allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_ComplexPredicate_021
 * @tc.desc: Normal testCase of RdbPredicates for complex combine sql
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_ComplexPredicate_021, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.Glob("stringValue", "ABC*")->EqualTo("booleanValue", "1")->NotBetween("longValue", "0", "2");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));
}

void RdbPredicatesInterfaceTest::SetJionList(RdbPredicates &predicates)
{
    std::vector<std::string> lists = { "ohos", "bazhahei", "zhaxidelie" };
    predicates.SetJoinTableNames(lists);
    predicates.SetJoinCount(1);
    predicates.SetJoinConditions(lists);
    predicates.SetJoinTypes(lists);
    predicates.SetOrder("ohos");
    predicates.Distinct();
}

/* *
 * @tc.name: RdbStore_ClearMethod_022
 * @tc.desc: Normal testCase of RdbPredicates for Clear Method
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_ClearMethod_022, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap()
        ->OrderByDesc("integerValue")
        ->Limit(2);

    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_TWO_ROWS, ResultSize(allDataTypes));

    EXPECT_EQ("RdbTestDataEntity", predicates.GetTableName());
    EXPECT_EQ(EXPECTED_TWO_ROWS, predicates.GetLimit());
    EXPECT_EQ(true, predicates.GetWhereClause().find("stringValue") != std::string::npos);

    std::vector<std::string> agrs = predicates.GetWhereArgs();
    auto ret = find(agrs.begin(), agrs.end(), "ABCDEFGHIJKLMN");
    EXPECT_EQ(true, ret != agrs.end());

    SetJionList(predicates);

    agrs = predicates.GetJoinTableNames();
    ret = find(agrs.begin(), agrs.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != agrs.end());
    EXPECT_EQ(1, predicates.GetJoinCount());

    agrs = predicates.GetJoinConditions();
    ret = find(agrs.begin(), agrs.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != agrs.end());

    agrs = predicates.GetJoinTypes();
    ret = find(agrs.begin(), agrs.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != agrs.end());
    EXPECT_EQ(true, predicates.GetJoinClause().find("ohos") != std::string::npos);
    EXPECT_EQ("ohos", predicates.GetOrder());
    EXPECT_EQ(true, predicates.IsDistinct());

    predicates.Clear();
    EXPECT_EQ("RdbTestDataEntity", predicates.GetTableName());
    EXPECT_EQ(-2147483648, predicates.GetLimit());
    EXPECT_EQ(true, predicates.GetWhereClause().empty());
    EXPECT_EQ(true, predicates.GetWhereArgs().empty());

    EXPECT_EQ(true, predicates.GetJoinTableNames().empty());
    EXPECT_EQ(0, predicates.GetJoinCount());
    EXPECT_EQ(true, predicates.GetJoinConditions().empty());
    EXPECT_EQ(true, predicates.GetJoinTypes().empty());
    EXPECT_EQ("", predicates.GetJoinClause());
    EXPECT_EQ(true, predicates.GetOrder().empty());
    EXPECT_EQ(false, predicates.IsDistinct());
}

/* *
 * @tc.name: RdbStore_InMethod_023
 * @tc.desc: Normal testCase of RdbPredicates for in method
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_InMethod_023, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;
    std::vector<std::string> agrs = { std::to_string(INT_MAX) };
    int count = 0;

    predicates.In("integerValue", agrs);
    std::shared_ptr<ResultSet> resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);

    predicates = RdbPredicates("RdbTestDataEntity");
    agrs[0] = "1";
    predicates.In("longValue", agrs);
    resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);

    predicates = RdbPredicates("RdbTestDataEntity");
    agrs[0] = "1.0";
    predicates.In("doubleValue", agrs);
    resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);

    predicates = RdbPredicates("RdbTestDataEntity");
    predicates.In("floatValue", agrs);
    resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);

    predicates = RdbPredicates("RdbTestDataEntity");
    std::vector<int> date = { 2019, 6, 10 };
    time_t calendarTime = RdbPredicatesInterfaceTest::DateMakeTime(date);
    agrs[0] = std::to_string(calendarTime);
    predicates.In("timeValue", agrs);
    resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);
}

/* *
 * @tc.name: RdbStore_NotInMethod_023
 * @tc.desc: Normal testCase of RdbPredicates for notIn method
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_NotInMethod_023, TestSize.Level1)
{
    std::vector<std::string> columns;
    std::vector<std::string> agrs = { std::to_string(INT_MAX), std::to_string(INT_MIN) };
    std::stringstream tempValue;
    int count = 0;

    RdbPredicates predicates("RdbTestDataEntity");
    predicates.NotIn("integerValue", agrs);
    std::shared_ptr<ResultSet> resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);

    predicates = RdbPredicates("RdbTestDataEntity");
    agrs[0] = "1";
    agrs[1] = std::to_string(LONG_MAX);
    predicates.NotIn("longValue", agrs);
    resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);

    predicates = RdbPredicates("RdbTestDataEntity");
    tempValue.str("");
    tempValue << DBL_MIN;
    agrs[0] = "1.0";
    agrs[1] = tempValue.str();
    predicates.NotIn("doubleValue", agrs);
    resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);

    predicates = RdbPredicates("RdbTestDataEntity");
    tempValue.str("");
    tempValue << FLT_MAX;
    agrs[0] = "1.0";
    agrs[1] = tempValue.str();
    predicates.NotIn("floatValue", agrs);
    resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);
}

/* *
 * @tc.name: RdbStore_KeywordMethod_024
 * @tc.desc: Normal testCase of RdbPredicates for clear method
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_KeywordMethod_024, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap()
        ->OrderByDesc("integerValue")
        ->Limit(2);

    std::vector<std::string> columns = { "booleanValue", "doubleValue", "orderr" };
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    allDataTypes->GoToFirstRow();
    int count = ResultSize(allDataTypes);
    EXPECT_EQ(EXPECTED_TWO_ROWS, count);

    EXPECT_EQ("RdbTestDataEntity", predicates.GetTableName());
    EXPECT_EQ(EXPECTED_TWO_ROWS, predicates.GetLimit());

    EXPECT_EQ(true, predicates.GetWhereClause().find("stringValue") != std::string::npos);
    std::vector<std::string> args = predicates.GetWhereArgs();
    auto ret = find(args.begin(), args.end(), "ABCDEFGHIJKLMN");
    EXPECT_EQ(true, ret != args.end());

    SetJionList(predicates);

    args = predicates.GetJoinTableNames();
    ret = find(args.begin(), args.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != args.end());
    EXPECT_EQ(1, predicates.GetJoinCount());

    args = predicates.GetJoinConditions();
    ret = find(args.begin(), args.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != args.end());

    args = predicates.GetJoinTypes();
    ret = find(args.begin(), args.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != args.end());
    EXPECT_EQ(true, predicates.GetJoinClause().find("ohos") != std::string::npos);
    EXPECT_EQ("ohos", predicates.GetOrder());
    EXPECT_EQ(true, predicates.IsDistinct());

    predicates.Clear();
    EXPECT_EQ("RdbTestDataEntity", predicates.GetTableName());
    EXPECT_EQ(-2147483648, predicates.GetLimit());
    EXPECT_EQ(true, predicates.GetWhereClause().empty());
    EXPECT_EQ(true, predicates.GetWhereArgs().empty());

    EXPECT_EQ(true, predicates.GetJoinTableNames().empty());
    EXPECT_EQ(0, predicates.GetJoinCount());
    EXPECT_EQ(true, predicates.GetJoinConditions().empty());
    EXPECT_EQ(true, predicates.GetJoinTypes().empty());
    EXPECT_EQ("", predicates.GetJoinClause());
    EXPECT_EQ(true, predicates.GetOrder().empty());
    EXPECT_EQ(false, predicates.IsDistinct());
}

/* *
 * @tc.name: RdbStore_ToString_025
 * @tc.desc: Normal testCase of RdbPredicates for clear method
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_ToString_025, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap()
        ->OrderByDesc("integerValue")
        ->Limit(2);
    std::string toString = predicates.ToString();
    std::string result = "TableName = RdbTestDataEntity, {WhereClause:stringValue = ? AND  ( integerValue = ?  OR "
                         "integerValue = ?  ) , bindArgs:{ABCDEFGHIJKLMN, 1, 2147483647, }, order:integerValue "
                         "DESC , group:, index:, limit:2, offset:-2147483648, distinct:0, isNeedAnd:1, isSorted:1}";
    EXPECT_EQ(result, toString);
}

/* *
 * @tc.name: RdbStore_InDevices_InAllDevices_026
 * @tc.desc: Normal testCase of RdbPredicates for InDevices and InAllDevices method
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_InDevices_InAllDevices_026, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> devices;
    devices.push_back("7001005458323933328a071dab423800");
    devices.push_back("7001005458323933328a268fa2fa3900");
    AbsRdbPredicates *absPredInDevices = predicates.InDevices(devices);
    EXPECT_NE(absPredInDevices, nullptr);
    AbsRdbPredicates *absPredInAllDevices = predicates.InAllDevices();
    EXPECT_NE(absPredInAllDevices, nullptr);
    EXPECT_EQ(absPredInDevices, absPredInAllDevices);
}

/* *
 * @tc.name: RdbStore_GetDistributedPredicates_027
 * @tc.desc: Normal testCase of RdbPredicates for GetDistributedPredicates method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_GetDistributedPredicates_027, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")->OrderByDesc("integerValue")->Limit(2);
    auto distributedRdbPredicates = predicates.GetDistributedPredicates();
    EXPECT_EQ(*(distributedRdbPredicates.tables_.begin()), "RdbTestDataEntity");
    EXPECT_EQ(distributedRdbPredicates.operations_.size(), 3UL);
    EXPECT_EQ(distributedRdbPredicates.operations_[0].operator_, OHOS::DistributedRdb::EQUAL_TO);
    EXPECT_EQ(distributedRdbPredicates.operations_[0].field_, "stringValue");
    EXPECT_EQ(distributedRdbPredicates.operations_[0].values_[0], "ABCDEFGHIJKLMN");
}

/* *
 * @tc.name: RdbStore_NotInMethod_028
 * @tc.desc: Abnormal testCase of RdbPredicates for notIn method
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_NotInMethod_028, TestSize.Level1)
{
    std::vector<std::string> columns;
    std::vector<ValueObject> arg;
    int count = 0;

    // RdbPredicates field is empty
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.NotIn("", arg);
    std::shared_ptr<ResultSet> resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(3, count);
    resultSet->Close();

    // RdbPredicates values is empty
    predicates = RdbPredicates("RdbTestDataEntity");
    predicates.NotIn("integerValue", arg);
    resultSet = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(3, count);
    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_NotContain_029
 * @tc.desc: Normal testCase of RdbPredicates for Not Contain
 * @tc.type: FUNC
 * @tc.require: #I9EMOO
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_NotContain_029, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.NotContains("stringValue", "OPQ");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_NotLike_030
 * @tc.desc: Normal testCase of RdbPredicates for Not Like
 * @tc.type: FUNC
 * @tc.require: #I9EMOO
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_NotLike_030, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    std::vector<std::string> columns;

    predicates.NotLike("stringValue", "OPQ");
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_EndWrap_001
 * @tc.desc: Abnormal testCase of RdbPredicates for EndWrap, fail to add ')'
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_EndWrap_001, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.NotEqualTo("id", "1")->BeginWrap()->EndWrap();

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Or_001
 * @tc.desc: Abnormal testCase of RdbPredicates for Or, fail to add 'OR'
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_Or_001, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.EqualTo("id", "1")->BeginWrap()->Or();

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_And_001
 * @tc.desc: Abnormal testCase of RdbPredicates for And, fail to add 'AND'
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_And_001, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.EqualTo("id", "1")->BeginWrap()->And();

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Contain_001
 * @tc.desc: Abnormal testCase of RdbPredicates for Contain, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbPredicatesInterfaceTest, RdbStore_Contain_001, TestSize.Level1)
{
    RdbPredicates predicates("RdbTestDataEntity");
    predicates.Contains("", "1");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbPredicatesInterfaceTest::store->Query(predicates, columns);
    EXPECT_EQ(EXPECTED_THREE_ROWS, ResultSize(allDataTypes));
    allDataTypes->Close();
}