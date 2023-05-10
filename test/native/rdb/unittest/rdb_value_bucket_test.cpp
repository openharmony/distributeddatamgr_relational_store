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

#include "logger.h"
#include "parcel.h"
#include "value_object.h"
#include "values_bucket.h"
#include "message_parcel.h"
#include "sqlite_global_config.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativeRdb;

class ValuesBucketTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ValuesBucketTest::SetUpTestCase(void)
{
}

void ValuesBucketTest::TearDownTestCase(void)
{
}

void ValuesBucketTest::SetUp(void)
{
}

void ValuesBucketTest::TearDown(void)
{
}

/**
 * @tc.name: Values_Bucket_001
 * @tc.desc: test Values Bucket parcel
 * @tc.type: FUNC
 * @tc.require: AR000CU2BO
 * @tc.author: zengmin
 */
HWTEST_F(ValuesBucketTest, Values_Bucket_001, TestSize.Level1)
{
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutLong("No.", 9223372036854775807L);
    values.PutDouble("salary", 100.5);
    values.PutBool("graduated", true);
    values.PutBlob("codes", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutNull("mark");

    OHOS::MessageParcel data;
    data.WriteParcelable(&values);

    ValuesBucket *valuesBucket = data.ReadParcelable<ValuesBucket>();
    ValueObject valueObject;

    valuesBucket->GetObject("id", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_INT, valueObject.GetType());
    int intVal;
    valueObject.GetInt(intVal);
    EXPECT_EQ(1, intVal);

    valuesBucket->GetObject("name", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_STRING, valueObject.GetType());
    std::string strVal;
    valueObject.GetString(strVal);
    EXPECT_EQ("zhangsan", strVal);

    valuesBucket->GetObject("No.", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_INT64, valueObject.GetType());
    int64_t int64Val;
    valueObject.GetLong(int64Val);
    EXPECT_EQ(9223372036854775807L, int64Val);

    valuesBucket->GetObject("salary", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_DOUBLE, valueObject.GetType());
    double doubleVal;
    valueObject.GetDouble(doubleVal);
    EXPECT_EQ(100.5, doubleVal);

    valuesBucket->GetObject("graduated", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_BOOL, valueObject.GetType());
    bool boolVal = false;
    valueObject.GetBool(boolVal);
    EXPECT_EQ(true, boolVal);

    valuesBucket->GetObject("codes", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_BLOB, valueObject.GetType());
    std::vector<uint8_t> blobVal;
    valueObject.GetBlob(blobVal);
    EXPECT_EQ((uint32_t)3, blobVal.size());
    EXPECT_EQ(1, blobVal.at(0));
    EXPECT_EQ(2, blobVal.at(1));
    EXPECT_EQ(3, blobVal.at(2));

    valuesBucket->GetObject("mark", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_NULL, valueObject.GetType());
}

/**
 * @tc.name: Values_Bucket_002
 * @tc.desc: test Values Bucket HasColumn
 * @tc.type: FUNC
 */
HWTEST_F(ValuesBucketTest, Values_Bucket_002, TestSize.Level1)
{
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutLong("No.", 9223372036854775807L);
    values.PutDouble("salary", 100.5);
    values.PutBool("graduated", true);
    values.PutBlob("codes", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutNull("mark");

    EXPECT_EQ(true, values.HasColumn("id"));
    EXPECT_EQ(true, values.HasColumn("name"));
    EXPECT_EQ(true, values.HasColumn("No."));
    EXPECT_EQ(true, values.HasColumn("salary"));
    EXPECT_EQ(true, values.HasColumn("graduated"));
    EXPECT_EQ(true, values.HasColumn("codes"));
    EXPECT_EQ(true, values.HasColumn("mark"));

    values.Delete("id");
    values.Delete("name");
    values.Delete("No.");
    values.Delete("salary");
    values.Delete("graduated");
    values.Delete("codes");
    values.Delete("mark");

    EXPECT_EQ(false, values.HasColumn("id"));
    EXPECT_EQ(false, values.HasColumn("name"));
    EXPECT_EQ(false, values.HasColumn("No."));
    EXPECT_EQ(false, values.HasColumn("salary"));
    EXPECT_EQ(false, values.HasColumn("graduated"));
    EXPECT_EQ(false, values.HasColumn("codes"));
    EXPECT_EQ(false, values.HasColumn("mark"));
}

/**
 * @tc.name: Values_Bucket_003
 * @tc.desc: test Values Bucket GetAll
 * @tc.type: FUNC
 */
HWTEST_F(ValuesBucketTest, Values_Bucket_003, TestSize.Level1)
{
    ValuesBucket values;
    std::map<std::string, ValueObject> getAllValuesMap;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutLong("No.", 9223372036854775807L);
    values.PutDouble("salary", 100.5);
    values.PutBool("graduated", true);
    values.PutBlob("codes", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutNull("mark");

    values.GetAll(getAllValuesMap);
    EXPECT_EQ(7, getAllValuesMap.size());
    getAllValuesMap.clear();
    EXPECT_EQ(true, getAllValuesMap.empty());

    EXPECT_EQ(7, values.Size());
    values.Clear();
    EXPECT_EQ(true, values.IsEmpty());
}

/**
 * @tc.name: Values_Bucket_004
 * @tc.desc: test Values Bucket Marshalling
 * @tc.type: FUNC
 */
HWTEST_F(ValuesBucketTest, Values_Bucket_004, TestSize.Level1)
{
    Parcel parcel;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutLong("No.", 9223372036854775807L);
    values.PutDouble("salary", 100.5);
    values.PutBool("graduated", true);
    values.PutBlob("codes", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutNull("mark");

    EXPECT_EQ(true, values.Marshalling(parcel));
    EXPECT_EQ(7, values.Unmarshalling(parcel)->Size());
    values.Unmarshalling(parcel)->Clear();
    EXPECT_EQ(true, values.Unmarshalling(parcel)->IsEmpty());
}

/**
 * @tc.name: Values_Bucket_005
 * @tc.desc: test Values Bucket Unmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(ValuesBucketTest, Values_Bucket_005, TestSize.Level1)
{
    Parcel parcel;
    ValuesBucket values;
    for (int i = 0; i < GlobalExpr::SQLITE_MAX_COLUMN + 1; i++) {
        values.PutInt("id" + std::to_string(i), i);
    }

    EXPECT_EQ(true, values.Marshalling(parcel));
    auto valuesBucket = std::shared_ptr<ValuesBucket>(ValuesBucket::Unmarshalling(parcel));
    EXPECT_EQ(true, valuesBucket->IsEmpty());
}

/**
 * @tc.name: Values_Object_001
 * @tc.desc: test ValuesObject operator
 * @tc.type: FUNC
 */
HWTEST_F(ValuesBucketTest, Values_Object_001, TestSize.Level1)
{
    int valueInt = 1;
    int retInt = ValueObject(valueInt);
    EXPECT_EQ(valueInt, retInt);

    int64_t valueInt64 = 1;
    int64_t retInt64 = ValueObject(valueInt64);
    EXPECT_EQ(valueInt64, retInt64);

    double valueDouble = 1.0;
    double retDouble = ValueObject(valueDouble);
    EXPECT_EQ(valueDouble, retDouble);

    bool valueBool = true;
    bool retBool = ValueObject(valueBool);
    EXPECT_EQ(valueBool, retBool);

    string valueString = "test";
    string retString = ValueObject(valueString);
    EXPECT_EQ(valueString, retString);

    std::vector<uint8_t> valueVectorUint8(2, 1);
    std::vector<uint8_t> retVectorUint8 = ValueObject(valueVectorUint8);
    EXPECT_EQ(valueVectorUint8, retVectorUint8);
}