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
#include "big_integer.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class BigIntegerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};

void BigIntegerTest::SetUpTestCase(void)
{
}

void BigIntegerTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: RdbStore_SqliteUtils_001
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(BigIntegerTest, Big_Integer_001, TestSize.Level1)
{
    int64_t number = 100;
    BigInteger bigInt1 = BigInteger(number);

    std::vector<uint64_t> intVec;
    intVec.push_back(number);
    BigInteger bigInt2 = BigInteger(1, std::move(intVec));
    bool isEqual = (bigInt1 == bigInt2);
    EXPECT_TRUE(isEqual);
}

