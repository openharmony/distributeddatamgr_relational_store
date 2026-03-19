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