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
#include "value_object.h"
#include "grd_type_export.h"
#include "big_integer.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class ValueObjectTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};

void ValueObjectTest::SetUpTestCase(void)
{
}

void ValueObjectTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: ValueObject_Test_001
 * @tc.desc: Normal testCase of value_object for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(ValueObjectTest, ValueObject_Test_001, TestSize.Level1)
{
    int32_t intValue = 1234;
    ValueObject obj(intValue);
    ValueObject &ref = obj;
    ref = std::move(obj);
    int sign;
    EXPECT_EQ(ref.GetInt(sign), intValue);
}

HWTEST_F(ValueObjectTest, ValueObject_Test_002, TestSize.Level1)
{
    int32_t intValue = 1234;
    ValueObject obj(intValue);
    ValueObject &ref = obj;
    EXPECT_EQ(&ref, &(ref = ref));
    int sign;
    EXPECT_EQ(ref.GetInt(sign), obj.GetInt(sign));
}

HWTEST_F(ValueObjectTest, ValueObject_Test_003, TestSize.Level1)
{
    int32_t intValue = 1234;
    ValueObject obj(intValue);
    BigInteger bigInt(intValue);
    ValueObject obj1;
    EXPECT_TRUE(static_cast<BigInteger>(obj) == bigInt);
}
