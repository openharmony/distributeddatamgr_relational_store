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
#include "common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class AllDataType {
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

class RdbStorePredicateTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static const std::string DATABASE_NAME;
    static std::shared_ptr<RdbStore> store;

    time_t DateMakeTime(std::vector<int> data);
    void InsertDates(std::vector<AllDataType> dataTypes);
    AllDataType BuildAllDataType1();
    AllDataType BuildAllDataType2();
    AllDataType BuildAllDataType3();
    void GenerateAllDataTypeTable();
    void CalendarTest(RdbPredicates predicates1);
    void BasicDataTypeTest(RdbPredicates predicates1);
    int ResultSize(std::shared_ptr<ResultSet> &resultSet);
    void BasicDataTypeTest002(RdbPredicates predicates1);
    void CalendarTest002(RdbPredicates predicates1);
    void SetJionList(RdbPredicates &predicates1);
};

std::shared_ptr<RdbStore> RdbStorePredicateTest::store = nullptr;
const std::string RdbStorePredicateTest::DATABASE_NAME = RDB_TEST_PATH + "predicates_test.db";
const std::string CREATE_TABLE_ALL_DATA_TYPE_SQL =
    "CREATE TABLE IF NOT EXISTS AllDataType "
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
    "INSERT INTO AllDataType (id, integerValue, longValue, "
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
class PredicateTestOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override;
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override;
};

int PredicateTestOpenCallback::OnCreate(RdbStore &store)
{
    return E_OK;
}

int PredicateTestOpenCallback::OnUpgrade(RdbStore &store, int oldVersion, int newVersion)
{
    return E_OK;
}

void RdbStorePredicateTest::SetUpTestCase()
{
}

void RdbStorePredicateTest::TearDownTestCase()
{
    RdbHelper::DeleteRdbStore(RdbStorePredicateTest::DATABASE_NAME);
}

void RdbStorePredicateTest::SetUp()
{
    if (access(RdbStorePredicateTest::DATABASE_NAME.c_str(), F_OK) != 0) {
        remove(RdbStorePredicateTest::DATABASE_NAME.c_str());
    }

    int errCode = E_OK;
    RdbStoreConfig config(RdbStorePredicateTest::DATABASE_NAME);
    PredicateTestOpenCallback helper;
    RdbStorePredicateTest::store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    EXPECT_NE(RdbStorePredicateTest::store, nullptr);

    RdbStorePredicateTest::GenerateAllDataTypeTable();
}

void RdbStorePredicateTest::TearDown(void)
{
}

void RdbStorePredicateTest::GenerateAllDataTypeTable()
{
    RdbStorePredicateTest::store->ExecuteSql(CREATE_TABLE_ALL_DATA_TYPE_SQL);
    RdbStorePredicateTest::store->ExecuteSql(CREATE_TABLE_PERSON_SQL);

    AllDataType dataType1 = RdbStorePredicateTest::BuildAllDataType1();
    AllDataType dataType2 = RdbStorePredicateTest::BuildAllDataType2();
    AllDataType dataType3 = RdbStorePredicateTest::BuildAllDataType3();

    std::vector<AllDataType> dataTypes;
    dataTypes.push_back(dataType1);
    dataTypes.push_back(dataType2);
    dataTypes.push_back(dataType3);
    RdbStorePredicateTest::InsertDates(dataTypes);
}

AllDataType RdbStorePredicateTest::RdbStorePredicateTest::BuildAllDataType1()
{
    std::vector<uint8_t> blob = { 1, 2, 3 };
    AllDataType dataType;
    dataType.SetId(1); // 1 means Id of the AllDataType object is 1
    dataType.SetIntegerValue(INT_MAX);
    dataType.SetDoubleValue(DBL_MAX);
    dataType.SetBooleanValue(true);
    dataType.SetFloatValue(FLT_MAX);
    dataType.SetLongValue(LONG_MAX);
    dataType.SetShortValue(SHRT_MAX);
    dataType.SetCharacterValue(' ');
    dataType.SetStringValue("ABCDEFGHIJKLMN");
    dataType.SetBlobValue(blob);
    dataType.SetClobValue("ABCDEFGHIJKLMN");
    dataType.SetByteValue(INT8_MAX);

    std::vector<int> date = { 2019, 7, 10 };
    time_t timeValue = RdbStorePredicateTest::DateMakeTime(date);
    dataType.SetTimeValue(timeValue);

    dataType.SetPrimIntValue(INT_MAX);
    dataType.SetPrimDoubleValue(DBL_MAX);
    dataType.SetPrimFloatValue(FLT_MAX);
    dataType.SetPrimBooleanValue(true);
    dataType.SetPrimByteValue(INT8_MAX);
    dataType.SetPrimCharValue(' ');
    dataType.SetPrimLongValue(LONG_MAX);
    dataType.SetPrimShortValue(SHRT_MAX);
    return dataType;
}

AllDataType RdbStorePredicateTest::BuildAllDataType2()
{
    std::vector<uint8_t> blob = { 1, 2, 3 };
    AllDataType dataType2;
    dataType2.SetId(2); // 2 means Id of the AllDataType object is 2
    dataType2.SetIntegerValue(1);
    dataType2.SetDoubleValue(1.0);
    dataType2.SetBooleanValue(false);
    dataType2.SetFloatValue(1.0);
    dataType2.SetLongValue(static_cast<int64_t>(1));
    dataType2.SetShortValue(static_cast<short>(1));
    dataType2.SetCharacterValue(' ');
    dataType2.SetStringValue("ABCDEFGHIJKLMN");
    dataType2.SetBlobValue(blob);
    dataType2.SetClobValue("ABCDEFGHIJKLMN");
    dataType2.SetByteValue(INT8_MIN);

    std::vector<int> date = { 2019, 7, 17 };
    time_t timeValue2 = RdbStorePredicateTest::DateMakeTime(date);
    dataType2.SetTimeValue(timeValue2);

    dataType2.SetPrimIntValue(1);
    dataType2.SetPrimDoubleValue(1.0);
    dataType2.SetPrimFloatValue(1.0);
    dataType2.SetPrimBooleanValue(false);
    dataType2.SetPrimByteValue(static_cast<char>(1));
    dataType2.SetPrimCharValue(' ');
    dataType2.SetPrimLongValue(static_cast<int64_t>(1));
    dataType2.SetPrimShortValue(static_cast<short>(1));
    return dataType2;
}

AllDataType RdbStorePredicateTest::BuildAllDataType3()
{
    std::vector<uint8_t> blob = { 1, 2, 3 };
    AllDataType dataType3;
    dataType3.SetId(3); // 3 means Id of the AllDataType object is 3
    dataType3.SetIntegerValue(INT_MIN);
    dataType3.SetDoubleValue(DBL_MIN);
    dataType3.SetBooleanValue(false);
    dataType3.SetFloatValue(FLT_MIN);
    dataType3.SetLongValue(LONG_MIN);
    dataType3.SetShortValue(SHRT_MIN);
    dataType3.SetCharacterValue(' ');
    dataType3.SetStringValue("ABCDEFGHIJKLMN");
    dataType3.SetBlobValue(blob);
    dataType3.SetClobValue("ABCDEFGHIJKLMN");
    dataType3.SetByteValue(INT8_MIN);

    std::vector<int> date = { 2019, 6, 10 };
    time_t timeValue3 = RdbStorePredicateTest::DateMakeTime(date);
    dataType3.SetTimeValue(timeValue3);

    dataType3.SetPrimIntValue(INT_MIN);
    dataType3.SetPrimDoubleValue(DBL_MIN);
    dataType3.SetPrimFloatValue(FLT_MIN);
    dataType3.SetPrimBooleanValue(false);
    dataType3.SetPrimByteValue(INT8_MIN);
    dataType3.SetPrimCharValue(' ');
    dataType3.SetPrimLongValue(LONG_MIN);
    dataType3.SetPrimShortValue(SHRT_MIN);
    return dataType3;
}

void RdbStorePredicateTest::InsertDates(std::vector<AllDataType> dataTypes)
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
        RdbStorePredicateTest::store->ExecuteSql(ALL_DATA_TYPE_INSERT_SQL, objects);
    }
}

time_t RdbStorePredicateTest::DateMakeTime(std::vector<int> data)
{
    struct tm t1 = { 0 };
    t1.tm_year = data[0] - 1990;
    t1.tm_mon = data[1] - 1;
    t1.tm_hour = data[2];
    t1.tm_sec = 0;
    t1.tm_min = 0;
    t1.tm_mday = 0;
    time_t time = mktime(&t1);
    return time;
}

/* *
 * @tc.name: RdbStore_RdbPredicates_001
 * @tc.desc: Abnormal testCase of RdbPredicates, if tableName is ""
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_RdbPredicates_001, TestSize.Level1)
{
    AbsRdbPredicates predicates("");
    predicates.EqualTo("integerValue", "1");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();

    // if predicates HasSpecificField
    predicates.OrderByAsc("#_number");
    bool hasSpecificField = predicates.HasSpecificField();
    EXPECT_EQ(true, hasSpecificField);
    std::shared_ptr<AbsSharedResultSet> resultSet = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_NE(nullptr, resultSet);
    resultSet->Close();
}

/* *
 * @tc.name: RdbStore_RdbPredicates_002
 * @tc.desc: Abnormal testCase of RdbPredicates, if tableNames is [] or counts is rather than 1
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_RdbPredicates_002, TestSize.Level1)
{
    std::vector<std::string> tableEmpty;
    std::vector<std::string> tables({ "AllDataType", "person" });

    AbsRdbPredicates predicates1(tableEmpty);
    AbsRdbPredicates predicates2(tables);
    predicates2.EqualTo("id", "1");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates2, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_EqualTo_001
 * @tc.desc: Normal testCase of RdbPredicates for EqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_EqualTo_001, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");

    BasicDataTypeTest(predicates1);

    CalendarTest(predicates1);
}

/* *
 * @tc.name: RdbStore_EqualTo_002
 * @tc.desc: Normal testCase of RdbPredicates for EqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_EqualTo_002, TestSize.Level1)
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
    EXPECT_EQ(2, id);

    RdbPredicates predicates("person");
    predicates.EqualTo("name", "");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allPerson = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allPerson));

    RdbPredicates predicates1("person");
    predicates1.EqualTo("name", "zhangsi");
    allPerson = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allPerson));
    RdbStorePredicateTest::store->ExecuteSql("delete from person where id < 3;");
}

/* *
 * @tc.name: RdbStore_EqualTo_003
 * @tc.desc: Normal testCase of RdbPredicates for EqualTo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_EqualTo_003, TestSize.Level1)
{
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    std::vector<OHOS::NativeRdb::AssetValue> assets;
    OHOS::NativeRdb::AssetValue asset{ .name = "asset" };
    assets.push_back(std::move(asset));
    ValueObject object(assets);
    values.Put("attachments", object);
    int ret = store->Insert(id, "person", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    RdbPredicates predicates("person");
    predicates.EqualTo("attachments", object);

    if (predicates.predicates_.operations_.size() != 0) {
        EXPECT_EQ(
            predicates.predicates_.operations_[0].operator_, OHOS::DistributedRdb::RdbPredicateOperator::ASSETS_ONLY);
    } else {
        EXPECT_TRUE(false);
    }
    RdbStorePredicateTest::store->ExecuteSql("delete from person where id < 2;");
}

/* *
 * @tc.name: RdbStore_EqualTo_004
 * @tc.desc: Normal testCase of RdbPredicates for EqualTo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_EqualTo_004, TestSize.Level1)
{
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);;
    OHOS::NativeRdb::AssetValue asset{ .name = "asset" };
    ValueObject object(asset);
    values.Put("attachment", object);
    int ret = store->Insert(id, "person", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    RdbPredicates predicates("person");
    predicates.EqualTo("attachment", object);
    if (predicates.predicates_.operations_.size() != 0) {
        EXPECT_EQ(
            predicates.predicates_.operations_[0].operator_, OHOS::DistributedRdb::RdbPredicateOperator::ASSETS_ONLY);
    } else {
        EXPECT_TRUE(false);
    }
    RdbStorePredicateTest::store->ExecuteSql("delete from person where id < 2;");
}

void RdbStorePredicateTest::CalendarTest(RdbPredicates predicates1)
{
    std::vector<std::string> columns;

    predicates1.Clear();
    std::vector<int> date = { 2019, 7, 17 };
    time_t calendarTime = RdbStorePredicateTest::DateMakeTime(date);

    predicates1.EqualTo("timeValue", std::to_string(calendarTime));
    std::shared_ptr<ResultSet> allDataTypes9 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(E_OK, allDataTypes9->GoToFirstRow());
    int valueInt = 0;
    allDataTypes9->GetInt(0, valueInt);
    EXPECT_EQ(2, valueInt);
}

void RdbStorePredicateTest::BasicDataTypeTest(RdbPredicates predicates1)
{
    std::vector<std::string> columns;
    std::stringstream tempValue;
    predicates1.EqualTo("booleanValue", "1");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes1));

    predicates1.Clear();
    predicates1.EqualTo("byteValue", std::to_string(INT8_MIN))->Or()->EqualTo("byteValue", std::to_string(1));
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes2));

    predicates1.Clear();
    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN");
    std::shared_ptr<ResultSet> allDataTypes3 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes3));

    predicates1.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates1.EqualTo("doubleValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes4 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes4));

    predicates1.Clear();
    predicates1.EqualTo("shortValue", std::to_string(SHRT_MIN));
    std::shared_ptr<ResultSet> allDataTypes5 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes5));

    predicates1.Clear();
    predicates1.EqualTo("integerValue", std::to_string(1));
    std::shared_ptr<ResultSet> allDataTypes6 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(E_OK, allDataTypes6->GoToFirstRow());
    int valueInt = 0;
    allDataTypes6->GetInt(0, valueInt);
    EXPECT_EQ(2, valueInt);

    predicates1.Clear();
    predicates1.EqualTo("longValue", std::to_string(1));
    std::shared_ptr<ResultSet> allDataTypes7 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(E_OK, allDataTypes7->GoToFirstRow());
    allDataTypes7->GetInt(0, valueInt);
    EXPECT_EQ(2, valueInt);

    predicates1.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates1.EqualTo("floatValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes8 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(E_OK, allDataTypes8->GoToFirstRow());
    allDataTypes8->GetInt(0, valueInt);
    EXPECT_EQ(3, valueInt);

    predicates1.Clear();
    predicates1.EqualTo("blobValue", std::vector<uint8_t>{ 1, 2, 3 });
    std::shared_ptr<ResultSet> allDataTypes9 = RdbStorePredicateTest::store->Query(predicates1, columns);
    // 3 rows in the resultSet when blobValue={1, 2, 3}
    EXPECT_EQ(3, ResultSize(allDataTypes9));
}

int RdbStorePredicateTest::ResultSize(std::shared_ptr<ResultSet> &resultSet)
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
HWTEST_F(RdbStorePredicateTest, RdbStore_NotEqualTo_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.NotEqualTo("", "1");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
}

/* *
 * @tc.name: RdbStore_NotEqualTo_002
 * @tc.desc: Normal testCase of RdbPredicates for NotEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_NotEqualTo_002, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");

    BasicDataTypeTest002(predicates1);

    CalendarTest002(predicates1);
}

/* *
 * @tc.name: RdbStore_NotEqualTo_003
 * @tc.desc: Normal testCase of RdbPredicates for EqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_NotEqualTo_003, TestSize.Level1)
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
    EXPECT_EQ(2, id);

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
    std::shared_ptr<ResultSet> allPerson = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(2, ResultSize(allPerson));

    RdbPredicates predicates1("person");
    predicates1.NotEqualTo("name", "zhangsi");

    allPerson = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allPerson));

    RdbStorePredicateTest::store->ExecuteSql("delete from person where id < 4;");
}

void RdbStorePredicateTest::CalendarTest002(RdbPredicates predicates1)
{
    std::vector<std::string> columns;

    predicates1.Clear();
    std::vector<int> date = { 2019, 7, 17 };
    time_t calendarTime = RdbStorePredicateTest::DateMakeTime(date);

    predicates1.NotEqualTo("timeValue", std::to_string(calendarTime));
    std::shared_ptr<ResultSet> allDataTypes9 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes9));
}

void RdbStorePredicateTest::BasicDataTypeTest002(RdbPredicates predicates1)
{
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates1.NotEqualTo("primBooleanValue", "1");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes1));

    predicates1.Clear();
    predicates1.NotEqualTo("primByteValue", std::to_string(INT8_MIN))->NotEqualTo("primByteValue", std::to_string(1));
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes2));

    predicates1.Clear();
    predicates1.NotEqualTo("stringValue", "ABCDEFGHIJKLMN");
    std::shared_ptr<ResultSet> allDataTypes3 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes3));

    predicates1.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates1.NotEqualTo("doubleValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes4 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes4));

    predicates1.Clear();
    predicates1.NotEqualTo("shortValue", std::to_string(SHRT_MIN));
    std::shared_ptr<ResultSet> allDataTypes5 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes5));

    predicates1.Clear();
    predicates1.NotEqualTo("integerValue", "1");
    std::shared_ptr<ResultSet> allDataTypes6 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes6));

    predicates1.Clear();
    predicates1.NotEqualTo("longValue", "1");
    std::shared_ptr<ResultSet> allDataTypes7 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes7));

    predicates1.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates1.NotEqualTo("floatValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes8 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes8));
}

/* *
 * @tc.name: RdbStore_IsNull_003
 * @tc.desc: Normal testCase of RdbPredicates for IsNull
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_IsNull_003, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    predicates1.IsNull("primLongValue");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes1));
}

/* *
 * @tc.name: RdbStore_NotNull_004
 * @tc.desc: Normal testCase of RdbPredicates for NotNull
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_NotNull_003, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    predicates1.IsNotNull("primLongValue");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));
}

/* *
 * @tc.name: RdbStore_GreaterThan_005
 * @tc.desc: Normal testCase of RdbPredicates for GreaterThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GreaterThan_005, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates1.GreaterThan("stringValue", "ABC");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));

    predicates1.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates1.GreaterThan("doubleValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes2));

    predicates1.Clear();
    predicates1.GreaterThan("integerValue", "1");
    std::shared_ptr<ResultSet> allDataTypes3 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes3));

    predicates1.Clear();
    predicates1.GreaterThan("longValue", "1");
    std::shared_ptr<ResultSet> allDataTypes4 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes4));

    predicates1.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates1.GreaterThan("floatValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes5 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes5));

    predicates1.Clear();
    std::vector<int> date = { 2019, 6, 9 };
    time_t calendarTime = RdbStorePredicateTest::DateMakeTime(date);
    predicates1.GreaterThan("timeValue", std::to_string(calendarTime).c_str());
    std::shared_ptr<ResultSet> allDataTypes6 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes6));
}

/* *
 * @tc.name: RdbStore_GreaterThanOrEqualTo_006
 * @tc.desc: Normal testCase of RdbPredicates for GreaterThanOrEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GreaterThanOrEqualTo_006, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates1.GreaterThanOrEqualTo("stringValue", "ABC");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));

    predicates1.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates1.GreaterThanOrEqualTo("doubleValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes2));

    predicates1.Clear();
    predicates1.GreaterThanOrEqualTo("integerValue", "1");
    std::shared_ptr<ResultSet> allDataTypes3 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes3));

    predicates1.Clear();
    predicates1.GreaterThanOrEqualTo("longValue", "1");
    std::shared_ptr<ResultSet> allDataTypes4 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes4));

    predicates1.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates1.GreaterThanOrEqualTo("floatValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes5 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes5));

    predicates1.Clear();
    std::vector<int> date = { 2019, 6, 9 };
    time_t calendarTime = RdbStorePredicateTest::DateMakeTime(date);
    predicates1.GreaterThanOrEqualTo("timeValue", std::to_string(calendarTime).c_str());
    std::shared_ptr<ResultSet> allDataTypes6 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes6));

    // Abnormal testCase of RdbPredicates for GreaterThanOrEqualTo if field is empty
    predicates1.Clear();
    predicates1.GreaterThanOrEqualTo("", "1");
    std::shared_ptr<ResultSet> allDataTypes7 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes7));
}

/* *
 * @tc.name: RdbStore_lessThan_007
 * @tc.desc: Normal testCase of RdbPredicates for LessThan
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_lessThan_007, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates1.LessThan("stringValue", "ABD");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));

    predicates1.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates1.LessThan("doubleValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes2));

    predicates1.Clear();
    predicates1.LessThan("integerValue", "1");
    std::shared_ptr<ResultSet> allDataTypes3 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes3));

    predicates1.Clear();
    predicates1.LessThan("longValue", "1");
    std::shared_ptr<ResultSet> allDataTypes4 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes4));

    predicates1.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates1.LessThan("floatValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes5 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes5));

    predicates1.Clear();
    std::vector<int> date = { 2019, 6, 9 };
    time_t calendarTime = RdbStorePredicateTest::DateMakeTime(date);
    predicates1.LessThan("timeValue", std::to_string(calendarTime).c_str());
    std::shared_ptr<ResultSet> allDataTypes6 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes6));
}

/* *
 * @tc.name: RdbStore_LessThanOrEqualTo_008
 * @tc.desc: Normal testCase of RdbPredicates for LessThanOrEqualTo
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_LessThanOrEqualTo_008, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates1.LessThanOrEqualTo("stringValue", "ABD");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));

    predicates1.Clear();
    tempValue.str("");
    tempValue << DBL_MIN;
    predicates1.LessThanOrEqualTo("doubleValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes2));

    predicates1.Clear();
    predicates1.LessThanOrEqualTo("integerValue", "1");
    std::shared_ptr<ResultSet> allDataTypes3 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes3));

    predicates1.Clear();
    predicates1.LessThanOrEqualTo("longValue", "1");
    std::shared_ptr<ResultSet> allDataTypes4 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes4));

    predicates1.Clear();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates1.LessThanOrEqualTo("floatValue", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes5 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes5));

    predicates1.Clear();
    std::vector<int> date = { 2019, 6, 9 };
    time_t calendarTime = RdbStorePredicateTest::DateMakeTime(date);
    predicates1.LessThanOrEqualTo("timeValue", std::to_string(calendarTime).c_str());
    std::shared_ptr<ResultSet> allDataTypes6 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes6));
}

/* *
 * @tc.name: RdbStore_Between_009
 * @tc.desc: Normal testCase of RdbPredicates for Between
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Between_009, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates1.Between("stringValue", "ABB", "ABD");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));

    predicates1.Clear();
    tempValue.str("");
    tempValue << DBL_MAX;
    predicates1.Between("doubleValue", "0.0", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes2));

    predicates1.Clear();
    predicates1.Between("integerValue", "0", "1");
    std::shared_ptr<ResultSet> allDataTypes3 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes3));

    predicates1.Clear();
    predicates1.Between("longValue", "0", "2");
    std::shared_ptr<ResultSet> allDataTypes4 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes4));

    predicates1.Clear();
    tempValue.str("");
    tempValue << FLT_MAX;
    std::string floatMax = tempValue.str();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates1.Between("floatValue", tempValue.str(), floatMax);
    std::shared_ptr<ResultSet> allDataTypes5 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes5));

    predicates1.Clear();
    std::vector<int> lowCalendar = { 2019, 6, 9 };
    time_t lowCalendarTime = RdbStorePredicateTest::DateMakeTime(lowCalendar);
    std::vector<int> highCalendar = { 2019, 7, 17 };
    time_t highCalendarTime = RdbStorePredicateTest::DateMakeTime(highCalendar);
    predicates1.Between("timeValue", std::to_string(lowCalendarTime).c_str(), std::to_string(highCalendarTime).c_str());
    std::shared_ptr<ResultSet> allDataTypes6 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes6));
}

/* *
 * @tc.name: RdbStore_Contain_010
 * @tc.desc: Normal testCase of RdbPredicates for Contain
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Contain_010, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.Contains("stringValue", "DEF");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));
}

/* *
 * @tc.name: RdbStore_BeginsWith_011
 * @tc.desc: Normal testCase of RdbPredicates for BeginsWith
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_BeginsWith_011, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.BeginsWith("stringValue", "ABC");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));
}

/* *
 * @tc.name: RdbStore_EndsWith_012
 * @tc.desc: Normal testCase of RdbPredicates for EndsWith
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_EndsWith_012, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.EndsWith("stringValue", "LMN");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));
}

/* *
 * @tc.name: RdbStore_Like_013
 * @tc.desc: Normal testCase of RdbPredicates for Like
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Like_013, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.Like("stringValue", "%LMN%");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));
}

/* *
 * @tc.name: RdbStore_BeginEndWrap_014
 * @tc.desc: Normal testCase of RdbPredicates for BeginEndWrap
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_BeginEndWrap_014, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap();
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes1));

    predicates1.Clear();
    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")->And()->EqualTo("integerValue", "1");
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes2));
}

/* *
 * @tc.name: RdbStore_AndOR_015
 * @tc.desc: Normal testCase of RdbPredicates for AndOR
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_AndOR_015, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap();

    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes1));

    predicates1.Clear();
    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")->And()->EqualTo("integerValue", "1");
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes2));
}

/* *
 * @tc.name: RdbStore_Order_016
 * @tc.desc: Normal testCase of RdbPredicates for Order
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Order_016, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")->OrderByAsc("integerValue")->Distinct();
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(E_OK, allDataTypes1->GoToFirstRow());
    int valueInt = 0;
    allDataTypes1->GetInt(0, valueInt);
    EXPECT_EQ(3, valueInt);
    EXPECT_EQ(E_OK, allDataTypes1->GoToNextRow());
    allDataTypes1->GetInt(0, valueInt);
    EXPECT_EQ(2, valueInt);
    EXPECT_EQ(E_OK, allDataTypes1->GoToNextRow());
    allDataTypes1->GetInt(0, valueInt);
    EXPECT_EQ(1, valueInt);

    predicates1.Clear();
    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")->OrderByDesc("integerValue")->Distinct();
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(E_OK, allDataTypes2->GoToFirstRow());
    allDataTypes2->GetInt(0, valueInt);
    EXPECT_EQ(1, valueInt);
    EXPECT_EQ(E_OK, allDataTypes2->GoToNextRow());
    allDataTypes2->GetInt(0, valueInt);
    EXPECT_EQ(2, valueInt);
    EXPECT_EQ(E_OK, allDataTypes2->GoToNextRow());
    allDataTypes2->GetInt(0, valueInt);
    EXPECT_EQ(3, valueInt);
}

/* *
 * @tc.name: RdbStore_Limit_017
 * @tc.desc: Normal testCase of RdbPredicates for Limit
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Limit_017, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")->Limit(1);
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes1));
}

/* *
 * @tc.name: RdbStore_JoinTypes_018
 * @tc.desc: Normal testCase of RdbPredicates for JoinTypes
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_JoinTypes_018, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> joinEntityNames;

    joinEntityNames.push_back("AllDataType");
    predicates1.SetJoinTableNames(joinEntityNames);

    std::vector<std::string> joinTypes;
    joinTypes.push_back("INNER JOIN");
    predicates1.SetJoinTypes(joinTypes);

    std::vector<std::string> joinConditions;
    joinConditions.push_back("ON");
    predicates1.SetJoinConditions(joinConditions);
    predicates1.SetJoinCount(1);

    EXPECT_EQ(joinConditions, predicates1.GetJoinConditions());
    EXPECT_EQ(joinEntityNames, predicates1.GetJoinTableNames());
    EXPECT_EQ(joinTypes, predicates1.GetJoinTypes());
    EXPECT_EQ(1, predicates1.GetJoinCount());
}

/* *
 * @tc.name: RdbStore_Glob_019
 * @tc.desc: Normal testCase of RdbPredicates for Glob
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Glob_019, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.Glob("stringValue", "ABC*");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));

    predicates1.Clear();
    predicates1.Glob("stringValue", "*EFG*");
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes2));

    predicates1.Clear();
    predicates1.Glob("stringValue", "?B*");
    std::shared_ptr<ResultSet> allDataTypes3 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes3));

    predicates1.Clear();
    predicates1.Glob("stringValue", "A????????????N");
    std::shared_ptr<ResultSet> allDataTypes4 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes4));

    predicates1.Clear();
    predicates1.Glob("stringValue", "A?????????????N");
    std::shared_ptr<ResultSet> allDataTypes5 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes5));

    predicates1.Clear();
    predicates1.Glob("stringValue", "?B*N");
    std::shared_ptr<ResultSet> allDataTypes6 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes6));
}

/* *
 * @tc.name: RdbStore_NotBetween_020
 * @tc.desc: Normal testCase of RdbPredicates for NotBetween
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_NotBetween_020, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;
    std::stringstream tempValue;

    predicates1.NotBetween("stringValue", "ABB", "ABD");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes1));

    predicates1.Clear();
    tempValue.str("");
    tempValue << DBL_MAX;
    predicates1.NotBetween("doubleValue", "0.0", tempValue.str());
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes2));

    predicates1.Clear();
    predicates1.NotBetween("integerValue", "0", "1");
    std::shared_ptr<ResultSet> allDataTypes3 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes3));

    predicates1.Clear();
    predicates1.NotBetween("longValue", "0", "2");
    std::shared_ptr<ResultSet> allDataTypes4 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes4));

    predicates1.Clear();
    tempValue.str("");
    tempValue << FLT_MAX;
    std::string floatMax = tempValue.str();
    tempValue.str("");
    tempValue << FLT_MIN;
    predicates1.NotBetween("floatValue", tempValue.str(), floatMax);
    std::shared_ptr<ResultSet> allDataTypes5 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes5));

    std::vector<int> lowCalendar = { 2019, 6, 9 };
    time_t lowCalendarTime = RdbStorePredicateTest::DateMakeTime(lowCalendar);
    std::vector<int> highCalendar = { 2019, 7, 17 };
    time_t highCalendarTime = RdbStorePredicateTest::DateMakeTime(highCalendar);
    predicates1.Clear();
    predicates1.NotBetween("timeValue", std::to_string(lowCalendarTime), std::to_string(highCalendarTime));
    std::shared_ptr<ResultSet> allDataTypes6 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes6));
}

/* *
 * @tc.name: RdbStore_ComplexPredicate_021
 * @tc.desc: Normal testCase of RdbPredicates for complex combine sql
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_ComplexPredicate_021, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.Glob("stringValue", "ABC*")->EqualTo("booleanValue", "1")->NotBetween("longValue", "0", "2");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(1, ResultSize(allDataTypes1));
}

void RdbStorePredicateTest::SetJionList(RdbPredicates &predicates1)
{
    std::vector<std::string> lists = { "ohos", "bazhahei", "zhaxidelie" };
    predicates1.SetJoinTableNames(lists);
    predicates1.SetJoinCount(1);
    predicates1.SetJoinConditions(lists);
    predicates1.SetJoinTypes(lists);
    predicates1.SetOrder("ohos");
    predicates1.Distinct();
}

/* *
 * @tc.name: RdbStore_ClearMethod_022
 * @tc.desc: Normal testCase of RdbPredicates for Clear Method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_ClearMethod_022, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap()
        ->OrderByDesc("integerValue")
        ->Limit(2);

    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes1));

    EXPECT_EQ("AllDataType", predicates1.GetTableName());
    EXPECT_EQ(2, predicates1.GetLimit());
    EXPECT_EQ(true, predicates1.GetWhereClause().find("stringValue") != std::string::npos);

    std::vector<std::string> agrs = predicates1.GetWhereArgs();
    auto ret = find(agrs.begin(), agrs.end(), "ABCDEFGHIJKLMN");
    EXPECT_EQ(true, ret != agrs.end());

    SetJionList(predicates1);

    agrs = predicates1.GetJoinTableNames();
    ret = find(agrs.begin(), agrs.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != agrs.end());
    EXPECT_EQ(1, predicates1.GetJoinCount());

    agrs = predicates1.GetJoinConditions();
    ret = find(agrs.begin(), agrs.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != agrs.end());

    agrs = predicates1.GetJoinTypes();
    ret = find(agrs.begin(), agrs.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != agrs.end());
    EXPECT_EQ(true, predicates1.GetJoinClause().find("ohos") != std::string::npos);
    EXPECT_EQ("ohos", predicates1.GetOrder());
    EXPECT_EQ(true, predicates1.IsDistinct());

    predicates1.Clear();
    EXPECT_EQ("AllDataType", predicates1.GetTableName());
    EXPECT_EQ(-2147483648, predicates1.GetLimit());
    EXPECT_EQ(true, predicates1.GetWhereClause().empty());
    EXPECT_EQ(true, predicates1.GetWhereArgs().empty());

    EXPECT_EQ(true, predicates1.GetJoinTableNames().empty());
    EXPECT_EQ(0, predicates1.GetJoinCount());
    EXPECT_EQ(true, predicates1.GetJoinConditions().empty());
    EXPECT_EQ(true, predicates1.GetJoinTypes().empty());
    EXPECT_EQ("", predicates1.GetJoinClause());
    EXPECT_EQ(true, predicates1.GetOrder().empty());
    EXPECT_EQ(false, predicates1.IsDistinct());
}

/* *
 * @tc.name: RdbStore_InMethod_023
 * @tc.desc: Normal testCase of RdbPredicates for in method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_InMethod_023, TestSize.Level1)
{
    RdbPredicates rdbPredicates1("AllDataType");
    std::vector<std::string> columns;
    std::vector<std::string> agrs = { std::to_string(INT_MAX) };
    rdbPredicates1.In("integerValue", agrs);
    std::shared_ptr<ResultSet> resultSet1 = RdbStorePredicateTest::store->Query(rdbPredicates1, columns);
    int count = 0;
    resultSet1->GetRowCount(count);
    EXPECT_EQ(1, count);

    RdbPredicates rdbPredicates2("AllDataType");
    agrs[0] = "1";
    rdbPredicates2.In("longValue", agrs);
    std::shared_ptr<ResultSet> resultSet2 = RdbStorePredicateTest::store->Query(rdbPredicates2, columns);
    resultSet2->GetRowCount(count);
    EXPECT_EQ(1, count);

    RdbPredicates rdbPredicates3("AllDataType");
    agrs[0] = "1.0";
    rdbPredicates3.In("doubleValue", agrs);
    std::shared_ptr<ResultSet> resultSet3 = RdbStorePredicateTest::store->Query(rdbPredicates3, columns);
    resultSet3->GetRowCount(count);
    EXPECT_EQ(1, count);

    RdbPredicates rdbPredicates4("AllDataType");
    rdbPredicates4.In("floatValue", agrs);
    std::shared_ptr<ResultSet> resultSet4 = RdbStorePredicateTest::store->Query(rdbPredicates4, columns);
    resultSet4->GetRowCount(count);
    EXPECT_EQ(1, count);

    std::vector<int> date = { 2019, 6, 10 };
    time_t calendarTime = RdbStorePredicateTest::DateMakeTime(date);
    RdbPredicates rdbPredicates5("AllDataType");
    agrs[0] = std::to_string(calendarTime);
    rdbPredicates5.In("timeValue", agrs);
    std::shared_ptr<ResultSet> resultSet5 = RdbStorePredicateTest::store->Query(rdbPredicates5, columns);
    resultSet5->GetRowCount(count);
    EXPECT_EQ(1, count);
}

/* *
 * @tc.name: RdbStore_NotInMethod_023
 * @tc.desc: Normal testCase of RdbPredicates for notIn method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_NotInMethod_023, TestSize.Level1)
{
    std::vector<std::string> columns;
    std::vector<std::string> agrs = { std::to_string(INT_MAX), std::to_string(INT_MIN) };
    std::stringstream tempValue;

    RdbPredicates rdbPredicates1("AllDataType");
    rdbPredicates1.NotIn("integerValue", agrs);
    std::shared_ptr<ResultSet> resultSet1 = RdbStorePredicateTest::store->Query(rdbPredicates1, columns);
    int count = 0;
    resultSet1->GetRowCount(count);
    EXPECT_EQ(1, count);

    RdbPredicates rdbPredicates2("AllDataType");
    agrs[0] = "1";
    agrs[1] = std::to_string(LONG_MAX);
    rdbPredicates2.NotIn("longValue", agrs);
    std::shared_ptr<ResultSet> resultSet2 = RdbStorePredicateTest::store->Query(rdbPredicates2, columns);
    resultSet2->GetRowCount(count);
    EXPECT_EQ(1, count);

    RdbPredicates rdbPredicates3("AllDataType");
    tempValue.str("");
    tempValue << DBL_MIN;
    agrs[0] = "1.0";
    agrs[1] = tempValue.str();
    rdbPredicates3.NotIn("doubleValue", agrs);
    std::shared_ptr<ResultSet> resultSet3 = RdbStorePredicateTest::store->Query(rdbPredicates3, columns);
    resultSet3->GetRowCount(count);
    EXPECT_EQ(1, count);

    RdbPredicates rdbPredicates4("AllDataType");
    tempValue.str("");
    tempValue << FLT_MAX;
    agrs[0] = "1.0";
    agrs[1] = tempValue.str();
    rdbPredicates4.NotIn("floatValue", agrs);
    std::shared_ptr<ResultSet> resultSet4 = RdbStorePredicateTest::store->Query(rdbPredicates4, columns);
    resultSet4->GetRowCount(count);
    EXPECT_EQ(1, count);
}

/* *
 * @tc.name: RdbStore_KeywordMethod_024
 * @tc.desc: Normal testCase of RdbPredicates for clear method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_KeywordMethod_024, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap()
        ->OrderByDesc("integerValue")
        ->Limit(2);

    std::vector<std::string> columns = { "booleanValue", "doubleValue", "orderr" };
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    allDataTypes1->GoToFirstRow();
    int count = ResultSize(allDataTypes1);
    EXPECT_EQ(2, count);

    EXPECT_EQ("AllDataType", predicates1.GetTableName());
    EXPECT_EQ(2, predicates1.GetLimit());

    EXPECT_EQ(true, predicates1.GetWhereClause().find("stringValue") != std::string::npos);
    std::vector<std::string> args = predicates1.GetWhereArgs();
    auto ret = find(args.begin(), args.end(), "ABCDEFGHIJKLMN");
    EXPECT_EQ(true, ret != args.end());

    SetJionList(predicates1);

    args = predicates1.GetJoinTableNames();
    ret = find(args.begin(), args.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != args.end());
    EXPECT_EQ(1, predicates1.GetJoinCount());

    args = predicates1.GetJoinConditions();
    ret = find(args.begin(), args.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != args.end());

    args = predicates1.GetJoinTypes();
    ret = find(args.begin(), args.end(), "zhaxidelie");
    EXPECT_EQ(true, ret != args.end());
    EXPECT_EQ(true, predicates1.GetJoinClause().find("ohos") != std::string::npos);
    EXPECT_EQ("ohos", predicates1.GetOrder());
    EXPECT_EQ(true, predicates1.IsDistinct());

    predicates1.Clear();
    EXPECT_EQ("AllDataType", predicates1.GetTableName());
    EXPECT_EQ(-2147483648, predicates1.GetLimit());
    EXPECT_EQ(true, predicates1.GetWhereClause().empty());
    EXPECT_EQ(true, predicates1.GetWhereArgs().empty());

    EXPECT_EQ(true, predicates1.GetJoinTableNames().empty());
    EXPECT_EQ(0, predicates1.GetJoinCount());
    EXPECT_EQ(true, predicates1.GetJoinConditions().empty());
    EXPECT_EQ(true, predicates1.GetJoinTypes().empty());
    EXPECT_EQ("", predicates1.GetJoinClause());
    EXPECT_EQ(true, predicates1.GetOrder().empty());
    EXPECT_EQ(false, predicates1.IsDistinct());
}

/* *
 * @tc.name: RdbStore_ToString_025
 * @tc.desc: Normal testCase of RdbPredicates for clear method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_ToString_025, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    predicates1.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", "1")
        ->Or()
        ->EqualTo("integerValue", std::to_string(INT_MAX))
        ->EndWrap()
        ->OrderByDesc("integerValue")
        ->Limit(2);
    std::string toString = predicates1.ToString();
    std::string result = "TableName = AllDataType, {WhereClause:stringValue = ? AND  ( integerValue = ?  OR "
                         "integerValue = ?  ) , bindArgs:{ABCDEFGHIJKLMN, 1, 2147483647, }, order:integerValue "
                         "DESC , group:, index:, limit:2, offset:-2147483648, distinct:0, isNeedAnd:1, isSorted:1}";
    EXPECT_EQ(result, toString);
}

/* *
 * @tc.name: RdbStore_InDevices_InAllDevices_026
 * @tc.desc: Normal testCase of RdbPredicates for InDevices and InAllDevices method
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_InDevices_InAllDevices_026, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    std::vector<std::string> devices;
    devices.push_back("7001005458323933328a071dab423800");
    devices.push_back("7001005458323933328a268fa2fa3900");
    AbsRdbPredicates *absRdbPredicates = predicates.InDevices(devices);
    EXPECT_NE(absRdbPredicates, nullptr);
    AbsRdbPredicates *absRdbPredicates1 = predicates.InAllDevices();
    EXPECT_NE(absRdbPredicates1, nullptr);
    EXPECT_EQ(absRdbPredicates, absRdbPredicates1);
}

/* *
 * @tc.name: RdbStore_GetDistributedPredicates_027
 * @tc.desc: Normal testCase of RdbPredicates for GetDistributedPredicates method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GetDistributedPredicates_027, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")->OrderByDesc("integerValue")->Limit(2);
    auto distributedRdbPredicates = predicates.GetDistributedPredicates();
    EXPECT_EQ(*(distributedRdbPredicates.tables_.begin()), "AllDataType");
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
HWTEST_F(RdbStorePredicateTest, RdbStore_NotInMethod_028, TestSize.Level1)
{
    std::vector<std::string> columns;
    std::vector<ValueObject> arg;
    int count = 0;

    // RdbPredicates field is empty
    RdbPredicates rdbPredicates1("AllDataType");
    rdbPredicates1.NotIn("", arg);
    std::shared_ptr<ResultSet> resultSet1 = RdbStorePredicateTest::store->Query(rdbPredicates1, columns);
    resultSet1->GetRowCount(count);
    EXPECT_EQ(3, count);
    resultSet1->Close();

    // RdbPredicates values is empty
    RdbPredicates rdbPredicates2("AllDataType");
    rdbPredicates2.NotIn("integerValue", arg);
    std::shared_ptr<ResultSet> resultSet2 = RdbStorePredicateTest::store->Query(rdbPredicates2, columns);
    resultSet2->GetRowCount(count);
    EXPECT_EQ(3, count);
    resultSet2->Close();
}

/* *
 * @tc.name: RdbStore_NotContain_029
 * @tc.desc: Normal testCase of RdbPredicates for Not Contain
 * @tc.type: FUNC
 * @tc.require: #I9EMOO
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_NotContain_029, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.NotContains("stringValue", "OPQ");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));
}

/* *
 * @tc.name: RdbStore_NotLike_030
 * @tc.desc: Normal testCase of RdbPredicates for Not Like
 * @tc.type: FUNC
 * @tc.require: #I9EMOO
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_NotLike_030, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    std::vector<std::string> columns;

    predicates1.NotLike("stringValue", "OPQ");
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes1));
}

/* *
 * @tc.name: RdbStore_EndWrap_001
 * @tc.desc: Abnormal testCase of RdbPredicates for EndWrap, fail to add ')'
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_EndWrap_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.NotEqualTo("id", "1")->BeginWrap()->EndWrap();

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Or_001
 * @tc.desc: Abnormal testCase of RdbPredicates for Or, fail to add 'OR'
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Or_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.EqualTo("id", "1")->BeginWrap()->Or();

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_And_001
 * @tc.desc: Abnormal testCase of RdbPredicates for And, fail to add 'AND'
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_And_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.EqualTo("id", "1")->BeginWrap()->And();

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Contain_001
 * @tc.desc: Abnormal testCase of RdbPredicates for Contain, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Contain_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.Contains("", "1");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_BeginsWith_001
 * @tc.desc: Abnormal testCase of RdbPredicates for BeginsWith, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_BeginsWith_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.BeginsWith("", "s");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_EndsWith_001
 * @tc.desc: Abnormal testCase of RdbPredicates for EndsWith, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_EndsWith_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.EndsWith("", "s");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_IsNull_001
 * @tc.desc: Abnormal testCase of RdbPredicates for IsNull, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_IsNull_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.IsNull("");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_IsNotNull_001
 * @tc.desc: Abnormal testCase of RdbPredicates for IsNotNull, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_IsNotNull_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.IsNotNull("");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Like_001
 * @tc.desc: Abnormal testCase of RdbPredicates for Like, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Like_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.Like("", "wks");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Glob_001
 * @tc.desc: Abnormal testCase of RdbPredicates for Glob, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Glob_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.Glob("", "wks");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Between_001
 * @tc.desc: Abnormal testCase of RdbPredicates for Between, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Between_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.Between("", "1", "4");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_NotBetween_001
 * @tc.desc: Abnormal testCase of RdbPredicates for NotBetween, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_NotBetween_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.NotBetween("", "1", "4");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_GreaterThan_001
 * @tc.desc: Abnormal testCase of RdbPredicates for GreaterThan, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GreaterThan_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.GreaterThan("", "1");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_LessThan_001
 * @tc.desc: Abnormal testCase of RdbPredicates for LessThan, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_LessThan_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.LessThan("", "4");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_GreaterThanOrEqualTo_001
 * @tc.desc: Abnormal testCase of RdbPredicates for GreaterThanOrEqualTo, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GreaterThanOrEqualTo_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.LessThan("", "1");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_LessThanOrEqualTo_001
 * @tc.desc: Abnormal testCase of RdbPredicates for LessThanOrEqualTo, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_LessThanOrEqualTo_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.LessThanOrEqualTo("", "1");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_OrderByDesc_001
 * @tc.desc: Abnormal testCase of RdbPredicates for OrderByDesc, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_OrderByDesc_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.OrderByDesc("");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_OrderByDesc_002
 * @tc.desc: Normal testCase of RdbPredicates for OrderByDesc
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_OrderByDesc_002, TestSize.Level2)
{
    RdbPredicates predicates("AllDataType");
    predicates.OrderByDesc("id");
    predicates.OrderByDesc("integerValue");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_OrderByAsc_001
 * @tc.desc: Abnormal testCase of RdbPredicates for OrderByAsc, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_OrderByAsc_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.OrderByAsc("");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_OrderByAsc_002
 * @tc.desc: Normal testCase of RdbPredicates for OrderByAsc
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_OrderByAsc_002, TestSize.Level2)
{
    RdbPredicates predicates("AllDataType");
    predicates.OrderByAsc("id");
    predicates.OrderByAsc("integerValue");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Limit_001
 * @tc.desc: Abnormal testCase of RdbPredicates for OrderByAsc, if set limit param twice
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Limit_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.Limit(2)->Limit(2);

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Offset_001
 * @tc.desc: Abnormal testCase of RdbPredicates for Offset, if set Offset param twice
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Offset_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.Limit(2)->Offset(1)->Offset(1);

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(2, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_Offset_002
 * @tc.desc: Abnormal testCase of RdbPredicates for Offset, if Offset param is less than 1
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Offset_002, TestSize.Level1)
{
    RdbPredicates predicates1("AllDataType");
    predicates1.Limit(2)->Offset(0);

    std::vector<std::string> columns1;
    std::shared_ptr<ResultSet> allDataTypes1 = RdbStorePredicateTest::store->Query(predicates1, columns1);
    EXPECT_EQ(2, ResultSize(allDataTypes1));
    allDataTypes1->Close();

    RdbPredicates predicates2("AllDataType");
    predicates2.Limit(2)->Offset(-1);

    std::vector<std::string> columns2;
    std::shared_ptr<ResultSet> allDataTypes2 = RdbStorePredicateTest::store->Query(predicates2, columns2);
    EXPECT_EQ(2, ResultSize(allDataTypes2));
    allDataTypes2->Close();
}

/* *
 * @tc.name: RdbStore_GroupBy_001
 * @tc.desc: Abnormal testCase of RdbPredicates for GroupBy, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GroupBy_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.GroupBy({});

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_GroupBy_002
 * @tc.desc: Abnormal testCase of RdbPredicates for GroupBy, if param is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GroupBy_002, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.GroupBy({ "idx" });

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_GroupBy_003
 * @tc.desc: Abnormal testCase of RdbPredicates for GroupBy, if fields is invalid
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GroupBy_003, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.GroupBy({ "" });

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_IndexedBy_001
 * @tc.desc: Abnormal testCase of RdbPredicates for IndexedBy, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_IndexedBy_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.IndexedBy("");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_IndexedBy_002
 * @tc.desc: Normal testCase of RdbPredicates for IndexedBy
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_IndexedBy_002, TestSize.Level1)
{
    RdbStorePredicateTest::store->ExecuteSql("CREATE INDEX orderr_index ON AllDataType(orderr)");

    RdbPredicates predicates("AllDataType");
    predicates.IndexedBy("orderr_index");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_In_001
 * @tc.desc: Abnormal testCase of RdbPredicates for In, if field is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_In_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.In("", std::vector<std::string>{ "1", "3" });

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_In_002
 * @tc.desc: Abnormal testCase of RdbPredicates for In, if values is []
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_In_002, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.In("id", std::vector<std::string>{});

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(0, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_SetOrder_001
 * @tc.desc: Abnormal testCase of RdbPredicates for SetOrder, if order is ''
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_SetOrder_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.SetOrder("");

    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> allDataTypes = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(3, ResultSize(allDataTypes));
    allDataTypes->Close();
}

/* *
 * @tc.name: RdbStore_GetStatement_GetBindArgs_001
 * @tc.desc: Normal testCase of RdbPredicates for GetStatement and GetBindArgs method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GetStatement_GetBnidArgs_001, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN")
        ->BeginWrap()
        ->EqualTo("integerValue", 1)
        ->Or()
        ->EqualTo("integerValue", INT_MAX)
        ->EndWrap()
        ->OrderByDesc("integerValue")
        ->Limit(-1, -1);

    std::vector<std::string> columns;
    int count = 0;
    std::shared_ptr<ResultSet> resultSet = RdbStorePredicateTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(2, count);

    std::string statement = predicates.GetStatement();
    std::vector<ValueObject> bindArgs = predicates.GetBindArgs();
    EXPECT_EQ(statement, " WHERE stringValue = ? AND  ( integerValue = ?  OR integerValue = ?  )  ORDER BY "
                         "integerValue DESC  LIMIT -1 OFFSET -1");
    EXPECT_EQ(bindArgs.size(), 3);
}

/* *
 * @tc.name: RdbStore_GetStatement_GetBindArgs_002
 * @tc.desc: Normal testCase of RdbPredicates for GetStatement and GetBindArgs method
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GetStatement_GetBnidArgs_002, TestSize.Level1)
{
    RdbPredicates predicates("AllDataType");
    predicates.SetWhereClause("integerValue = 1 and ");
    predicates.EqualTo("stringValue", "ABCDEFGHIJKLMN");

    std::string statement = predicates.GetStatement();
    EXPECT_EQ(statement, " WHERE integerValue = 1 and stringValue = ? ");

    std::vector<std::string> columns;
    int count = 0;
    std::shared_ptr<ResultSet> resultSet = RdbStorePredicateTest::store->Query(predicates, columns);
    resultSet->GetRowCount(count);
    EXPECT_EQ(1, count);
}

/* *
 * @tc.name: RdbStore_GetString_001
 * @tc.desc: Normal testCase of RdbPredicates for GetString
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GetString_001, TestSize.Level1)
{
    ValuesBucket values;
    int64_t id;
    values.PutInt("id", 1);
    values.PutString("name", std::string(""));
    values.PutInt("age", 18);
    values.PutInt("REAL", 100);
    int ret = store->Insert(id, "person", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    int errCode = 0;
    int columnIndex = 0;
    RdbPredicates predicates("person");
    predicates.EqualTo("name", "");
    std::vector<std::string> columns;
    std::shared_ptr<ResultSet> resultSet = RdbStorePredicateTest::store->Query(predicates, columns);
    EXPECT_EQ(1, ResultSize(resultSet));

    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(E_OK, ret);

    std::string name;
    errCode = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(errCode, E_OK);
    ret = resultSet->GetString(columnIndex, name);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(name, "");
    resultSet->Close();

    store->ExecuteSql("DELETE FROM person");
}

/**
 * @tc.name: RdbStore_GetString_002
 * @tc.desc: Normal testCase of RdbPredicates for GetString
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_GetString_002, TestSize.Level1)
{
    ValuesBucket values;
    int64_t id;
    values.Clear();
    values.PutInt("id", 1);
    values.PutString("name", std::string(""));
    values.PutInt("age", 18);
    values.PutInt("REAL", 100);
    int ret = store->Insert(id, "person", values);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(1, id);

    std::shared_ptr<ResultSet> resultSet = RdbStorePredicateTest::store->QueryByStep("SELECT * FROM person");
    EXPECT_EQ(1, ResultSize(resultSet));

    int errCode = 0;
    int columnIndex = 0;
    ret = resultSet->GoToFirstRow();
    EXPECT_EQ(E_OK, ret);

    std::string name;
    errCode = resultSet->GetColumnIndex("name", columnIndex);
    EXPECT_EQ(errCode, E_OK);
    ret = resultSet->GetString(columnIndex, name);
    EXPECT_EQ(E_OK, ret);
    EXPECT_EQ(name, "");
    resultSet->Close();

    store->ExecuteSql("DELETE FROM person");
}

/**
 * @tc.name: RdbStore_Having_001
 * @tc.desc: Verify scenarios without placeholders and without passing values
 * 1.Execute Having("total > 5000 AND count >= 3")
 * 2.Query data
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Having_001, TestSize.Level1)
{
    store->Execute(HAVING_CREATE_SQL);
    store->Execute(HAVING_INSERT_SQL);
    RdbPredicates predicates("orders");
    predicates.GroupBy({ "customer_id" });
    predicates.Having("total > 5000 AND count >= 3");
    auto resultSet = store->Query(predicates, { "customer_id", "COUNT(*) AS count", "SUM(amount) AS total" });
    EXPECT_EQ(resultSet->GoToNextRow(), E_OK);
    RowEntity rowEntity;
    EXPECT_EQ(resultSet->GetRow(rowEntity), E_OK);
    EXPECT_TRUE(rowEntity.Get("customer_id") == ValueObject(1));
    EXPECT_TRUE(rowEntity.Get("total") == ValueObject(6500)); // 6500 means total price.

    EXPECT_EQ(resultSet->GoToNextRow(), E_OK);
    RowEntity rowEntity1;
    EXPECT_EQ(resultSet->GetRow(rowEntity1), E_OK);
    EXPECT_TRUE(rowEntity1.Get("customer_id") == ValueObject(3)); // 3 means customer id.
    EXPECT_TRUE(rowEntity1.Get("total") == ValueObject(7000)); // 7000 means total price.
    store->ExecuteSql(HAVING_DROP_SQL);
}

/**
 * @tc.name: RdbStore_Having_002
 * @tc.desc: Verify scenarios without placeholders and without passing args.
 * 1.Execute having("")
 * 2.Query data
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Having_002, TestSize.Level1)
{
    store->Execute(HAVING_CREATE_SQL);
    store->Execute(HAVING_INSERT_SQL);
    RdbPredicates predicates("orders");
    predicates.GroupBy({ "customer_id" });
    // When conditions are passed empty, 'having' does not take effect.
    predicates.Having("");
    auto resultSet = store->Query(predicates, { "customer_id", "COUNT(*) AS count", "SUM(amount) AS total" });
    int count;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 3); // 3 means row count.
    store->ExecuteSql(HAVING_DROP_SQL);
}

 /**
 * @tc.name: RdbStore_Having_003
 * @tc.desc: Test conditions for passing in illegal SQL
 * 1.Execute Having("SALARY == 1.2")
 * 2.Query data
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Having_003, TestSize.Level1)
{
    store->Execute(HAVING_CREATE_SQL);
    store->Execute(HAVING_INSERT_SQL);
    RdbPredicates predicates("orders");
    predicates.GroupBy({ "customer_id" });
    predicates.Having("SALARY == 1.2");
    auto resultSet = store->Query(predicates, { "customer_id", "COUNT(*) AS count", "SUM(amount) AS total" });
    int count;
    EXPECT_EQ(resultSet->GetRowCount(count), E_SQLITE_ERROR);
    store->ExecuteSql(HAVING_DROP_SQL);
}

/**
 * @tc.name: RdbStore_Having_004
 * @tc.desc: Verify scenarios without placeholders and without passing values
 * 1.Execute Having(total > ? AND count >= ?", {5000})
 * 2.Query data
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Having_004, TestSize.Level1)
{
    store->Execute(HAVING_CREATE_SQL);
    store->Execute(HAVING_INSERT_SQL);
    RdbPredicates predicates("orders");
    predicates.GroupBy({ "customer_id" });
    predicates.Having("total > ? AND count >= ?", { 5000 });
    auto resultSet = store->Query(predicates, { "customer_id", "COUNT(*) AS count", "SUM(amount) AS total" });
    int count = -1;
    resultSet->GetRowCount(count);
    EXPECT_EQ(count, 0);
    store->ExecuteSql(HAVING_DROP_SQL);
}

/**
 * @tc.name: RdbStore_Having_005
 * @tc.desc: Test using placeholder scenarios.
 * 1.Execute Having(total > ? AND count >= ?", {5000, 3})
 * 2.Query data
 * @tc.type: FUNC
 */
HWTEST_F(RdbStorePredicateTest, RdbStore_Having_005, TestSize.Level1)
{
    store->Execute(HAVING_CREATE_SQL);
    store->Execute(HAVING_INSERT_SQL);
    RdbPredicates predicates("orders");
    predicates.GroupBy({ "customer_id" });
    predicates.Having("total > ? AND count >= ?", {5000, 3}); // 5000 means lower limit of total price.
    auto resultSet = store->Query(predicates, { "customer_id", "COUNT(*) AS count", "SUM(amount) AS total" });
    EXPECT_EQ(resultSet->GoToNextRow(), E_OK);
    RowEntity rowEntity;
    EXPECT_EQ(resultSet->GetRow(rowEntity), E_OK);
    EXPECT_TRUE(rowEntity.Get("customer_id") == ValueObject(1));
    EXPECT_TRUE(rowEntity.Get("total") == ValueObject(6500)); // 6500 means total price.

    EXPECT_EQ(resultSet->GoToNextRow(), E_OK);
    RowEntity rowEntity1;
    EXPECT_EQ(resultSet->GetRow(rowEntity1), E_OK);
    EXPECT_TRUE(rowEntity1.Get("customer_id") == ValueObject(3)); // 3 means customer id.
    EXPECT_TRUE(rowEntity1.Get("total") == ValueObject(7000)); // 7000 means total price.
    store->ExecuteSql(HAVING_DROP_SQL);
}