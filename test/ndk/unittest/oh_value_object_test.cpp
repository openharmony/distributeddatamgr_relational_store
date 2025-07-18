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
#include <sys/stat.h>
#include <sys/types.h>
#include <string>
#include "relational_store_error_code.h"
#include "common.h"
#include "oh_value_object.h"
#include "oh_data_define.h"
#include "relational_store.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class OhValueObjectTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static void InitRdbConfig()
    {
    }
};

void OhValueObjectTest::SetUpTestCase(void)
{
}

void OhValueObjectTest::TearDownTestCase(void)
{
}

void OhValueObjectTest::SetUp(void)
{
}

void OhValueObjectTest::TearDown(void)
{
}

/**
 * @tc.name: Value_Object_PutInt64_test_001
 * @tc.desc: Normal testCase for putInt64 of OH_VObject.
 * @tc.type: FUNC
 */
HWTEST_F(OhValueObjectTest, Value_Object_PutInt64_test_001, TestSize.Level1)
{
    OH_VObject *value = OH_Rdb_CreateValueObject();
    ASSERT_NE(value, nullptr);
    int64_t arrayNum[] = {0, 0};
    uint32_t count = 4294967295;
    auto ret = value->putInt64(value, arrayNum, count);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    value->destroy(value);
}

/**
 * @tc.name: Value_Object_PutDouble_test_001
 * @tc.desc: Normal testCase for putDouble of OH_VObject.
 * @tc.type: FUNC
 */
HWTEST_F(OhValueObjectTest, Value_Object_PutDouble_test_001, TestSize.Level1)
{
    OH_VObject *value = OH_Rdb_CreateValueObject();
    ASSERT_NE(value, nullptr);
    double arrayNum[] = {0, 0};
    uint32_t count = 4294967295;
    auto ret = value->putDouble(value, arrayNum, count);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    value->destroy(value);
}

/**
 * @tc.name: Value_Object_PutTexts_test_001
 * @tc.desc: Normal testCase for putDouble of OH_VObject.
 * @tc.type: FUNC
 */
HWTEST_F(OhValueObjectTest, Value_Object_PutTexts_test_001, TestSize.Level1)
{
    OH_VObject *value = OH_Rdb_CreateValueObject();
    ASSERT_NE(value, nullptr);
    const char *para1 = "hello";
    const char *para2 = "world";
    const char *texts[] = {para1, para2};
    uint32_t count = 4294967295;
    auto ret = value->putTexts(value, texts, count);
    EXPECT_EQ(ret, OH_Rdb_ErrCode::RDB_E_INVALID_ARGS);
    value->destroy(value);
}