/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "sqlite_utils.h"
#include "string_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};

void RdbUtilsTest::SetUpTestCase(void)
{
}

void RdbUtilsTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: RdbStore_SqliteUtils_001
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(RdbUtilsTest, RdbStore_SqliteUtils_001, TestSize.Level1)
{
    EXPECT_EQ(true, SqliteUtils::IsSpecial(5));
    EXPECT_EQ(true, SqliteUtils::IsSpecial(6));
    EXPECT_EQ(true, SqliteUtils::IsSpecial(7));
}

/**
 * @tc.name: RdbStore_SqliteUtils_002
 * @tc.desc: Abnormal testCase of sqlite_utils for Anonymous, if len(srcFile) < HEAD_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(RdbUtilsTest, RdbStore_SqliteUtils_002, TestSize.Level2)
{
    EXPECT_EQ("******", SqliteUtils::Anonymous("ac"));
}

/**
 * @tc.name: RdbStore_SqliteUtils_003
 * @tc.desc: Abnormal testCase of sqlite_utils for Anonymous, if len(srcFile) < MIN_SIZE
 * @tc.type: FUNC
 */
HWTEST_F(RdbUtilsTest, RdbStore_SqliteUtils_003, TestSize.Level2)
{
    EXPECT_EQ("abc***", SqliteUtils::Anonymous("abc/def"));
}

/**
 * @tc.name: RdbStore_SqliteUtils_004
 * @tc.desc: Abnormal testCase of string_utils for SurroundWithQuote, if value is ""
 * @tc.type: FUNC
 */
HWTEST_F(RdbUtilsTest, RdbStore_SqliteUtils_004, TestSize.Level2)
{
    EXPECT_EQ("", StringUtils::SurroundWithQuote("", "\""));
}

/**
 * @tc.name: RdbStore_SqliteUtils_005
 * @tc.desc: Normal testCase of string_utils for SurroundWithQuote
 * @tc.type: FUNC
 */
HWTEST_F(RdbUtilsTest, RdbStore_SqliteUtils_005, TestSize.Level1)
{
    EXPECT_EQ("\"AND\"", StringUtils::SurroundWithQuote("AND", "\""));
}
