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
#define private public
#include "rdb_types_util.h"

#include <gtest/gtest.h>

#include "message_parcel.h"
#include "rdb_types.h"
#include "value_object.h"
#include "values_bucket.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DistributedRdb;
using namespace OHOS::NativeRdb;

namespace Test {
class RdbTypesUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(void){};
    void TearDown(void){};
};

/**
 * @tc.name: MarshallingSyncerParam_001
 * @tc.desc: Test Marshalling and Unmarshalling for RdbSyncerParam
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, MarshallingSyncerParam_001, TestSize.Level1)
{
    RdbSyncerParam param;
    param.bundleName_ = "com.example.test";
    param.storeName_ = "test.db";
    param.area_ = 1;
    
    MessageParcel data;
    bool ret = ITypesUtil::Marshalling(param, data);
    EXPECT_TRUE(ret);
    
    RdbSyncerParam output;
    ret = ITypesUtil::Unmarshalling(output, data);
    EXPECT_TRUE(ret);
    EXPECT_EQ(output.bundleName_, param.bundleName_);
    EXPECT_EQ(output.storeName_, param.storeName_);
}

/**
 * @tc.name: MarshallingValueObject_001
 * @tc.desc: Test Marshalling and Unmarshalling for ValueObject with int value
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, MarshallingValueObject_001, TestSize.Level1)
{
    ValueObject value(123);
    
    MessageParcel data;
    bool ret = ITypesUtil::Marshalling(value, data);
    EXPECT_TRUE(ret);
    
    ValueObject output;
    ret = ITypesUtil::Unmarshalling(output, data);
    EXPECT_TRUE(ret);
    
    int result;
    output.GetInt(result);
    EXPECT_EQ(result, 123);
}

/**
 * @tc.name: MarshallingValueObject_002
 * @tc.desc: Test Marshalling and Unmarshalling for ValueObject with string value
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, MarshallingValueObject_002, TestSize.Level1)
{
    std::string testStr = "test_string";
    ValueObject value(testStr);
    
    MessageParcel data;
    bool ret = ITypesUtil::Marshalling(value, data);
    EXPECT_TRUE(ret);
    
    ValueObject output;
    ret = ITypesUtil::Unmarshalling(output, data);
    EXPECT_TRUE(ret);
    
    std::string result;
    output.GetString(result);
    EXPECT_EQ(result, testStr);
}

/**
 * @tc.name: MarshallingValueObject_003
 * @tc.desc: Test Marshalling and Unmarshalling for ValueObject with double value
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, MarshallingValueObject_003, TestSize.Level1)
{
    ValueObject value(123.456);
    
    MessageParcel data;
    bool ret = ITypesUtil::Marshalling(value, data);
    EXPECT_TRUE(ret);
    
    ValueObject output;
    ret = ITypesUtil::Unmarshalling(output, data);
    EXPECT_TRUE(ret);
    
    double result;
    output.GetDouble(result);
    EXPECT_DOUBLE_EQ(result, 123.456);
}

/**
 * @tc.name: MarshallingValuesBucket_001
 * @tc.desc: Test Marshalling and Unmarshalling for ValuesBucket
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, MarshallingValuesBucket_001, TestSize.Level1)
{
    ValuesBucket bucket;
    bucket.Put("key1", 123);
    bucket.Put("key2", "value2");
    bucket.Put("key3", 456.789);
    
    MessageParcel data;
    bool ret = ITypesUtil::Marshalling(bucket, data);
    EXPECT_TRUE(ret);
    
    ValuesBucket output;
    ret = ITypesUtil::Unmarshalling(output, data);
    EXPECT_TRUE(ret);
    
    int val1;
    ValueObject obj1;
    output.GetObject("key1", obj1);
    obj1.GetInt(val1);
    EXPECT_EQ(val1, 123);
    
    std::string val2;
    ValueObject obj2;
    output.GetObject("key2", obj2);
    obj2.GetString(val2);
    EXPECT_EQ(val2, "value2");
}

/**
 * @tc.name: MarshallingRdbPredicates_001
 * @tc.desc: Test Marshalling and Unmarshalling for RdbPredicates
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, MarshallingRdbPredicates_001, TestSize.Level2)
{
    PredicatesMemo predicates;
    predicates.tables_.push_back("test_table");
    
    MessageParcel data;
    bool ret = ITypesUtil::Marshalling(predicates, data);
    EXPECT_TRUE(ret);
    
    PredicatesMemo output;
    ret = ITypesUtil::Unmarshalling(output, data);
    EXPECT_TRUE(ret);
    EXPECT_EQ(output.tables_, predicates.tables_);
}

/**
 * @tc.name: MarshallingOrigin_001
 * @tc.desc: Test Marshalling and Unmarshalling for Origin
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, MarshallingOrigin_001, TestSize.Level2)
{
    Origin origin;
    origin.origin = Origin::ORIGIN_CLOUD;
    origin.store = "test_store";
    
    MessageParcel data;
    bool ret = ITypesUtil::Marshalling(origin, data);
    EXPECT_TRUE(ret);
    
    Origin output;
    ret = ITypesUtil::Unmarshalling(output, data);
    EXPECT_TRUE(ret);
    EXPECT_EQ(output.origin, origin.origin);
    EXPECT_EQ(output.store, origin.store);
}

/**
 * @tc.name: MarshallingOption_001
 * @tc.desc: Test Marshalling for Option
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, MarshallingOption_001, TestSize.Level2)
{
    RdbService::Option option;
    option.mode = PUSH;
    option.isAsync = true;
    option.seqNum = 123;
    
    MessageParcel data;
    bool ret = ITypesUtil::Marshalling(option, data);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: MarshallingSubscribeOption_001
 * @tc.desc: Test Marshalling for SubscribeOption
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, MarshallingSubscribeOption_001, TestSize.Level2)
{
    SubscribeOption option;
    option.mode = SubscribeMode::REMOTE;
    
    MessageParcel data;
    bool ret = ITypesUtil::Marshalling(option, data);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: Values_Bucket_001
 * @tc.desc: test Values Bucket parcel
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, Values_Bucket_001, TestSize.Level1)
{
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutLong("No.", 9223372036854775807L);
    values.PutDouble("salary", 100.5);
    values.PutBool("graduated", true);
    values.PutBlob("codes", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutNull("mark");

    MessageParcel data;
    ITypesUtil::Marshalling(values, data);
    ValuesBucket valuesBucket;

    ITypesUtil::Unmarshalling(valuesBucket, data);
    ValueObject valueObject;
    valuesBucket.GetObject("id", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_INT, valueObject.GetType());
    int intVal;
    valueObject.GetInt(intVal);
    EXPECT_EQ(1, intVal);

    valuesBucket.GetObject("name", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_STRING, valueObject.GetType());
    std::string strVal;
    valueObject.GetString(strVal);
    EXPECT_EQ("zhangsan", strVal);

    valuesBucket.GetObject("No.", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_INT, valueObject.GetType());
    int64_t int64Val;
    valueObject.GetLong(int64Val);
    EXPECT_EQ(9223372036854775807L, int64Val);

    valuesBucket.GetObject("salary", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_DOUBLE, valueObject.GetType());
    double doubleVal;
    valueObject.GetDouble(doubleVal);
    EXPECT_EQ(100.5, doubleVal);

    valuesBucket.GetObject("graduated", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_BOOL, valueObject.GetType());
    bool boolVal = false;
    valueObject.GetBool(boolVal);
    EXPECT_EQ(true, boolVal);

    valuesBucket.GetObject("codes", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_BLOB, valueObject.GetType());
    std::vector<uint8_t> blobVal;
    valueObject.GetBlob(blobVal);
    EXPECT_EQ((uint32_t)3, blobVal.size());
    EXPECT_EQ(1, blobVal.at(0));
    EXPECT_EQ(2, blobVal.at(1));
    EXPECT_EQ(3, blobVal.at(2));

    valuesBucket.GetObject("mark", valueObject);
    EXPECT_EQ(ValueObjectType::TYPE_NULL, valueObject.GetType());
}

/**
 * @tc.name: Values_Bucket_004
 * @tc.desc: test Values Bucket Marshalling
 * @tc.type: FUNC
 */
HWTEST_F(RdbTypesUtilTest, Values_Bucket_004, TestSize.Level1)
{
    MessageParcel parcel;
    ValuesBucket values;
    values.PutInt("id", 1);
    values.PutString("name", std::string("zhangsan"));
    values.PutLong("No.", 9223372036854775807L);
    values.PutDouble("salary", 100.5);
    values.PutBool("graduated", true);
    values.PutBlob("codes", std::vector<uint8_t>{ 1, 2, 3 });
    values.PutNull("mark");

    EXPECT_EQ(true, ITypesUtil::Marshalling(values, parcel));
    ValuesBucket valuesBucket;
    ITypesUtil::Unmarshalling(valuesBucket, parcel);
    EXPECT_EQ(7, valuesBucket.Size());
    valuesBucket.Clear();
    ITypesUtil::Unmarshalling(valuesBucket, parcel);
    EXPECT_EQ(true, valuesBucket.IsEmpty());
}
} // namespace Test
