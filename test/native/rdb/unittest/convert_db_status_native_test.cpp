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

#include <gtest/gtest.h>

#include "rdb_errno.h"
#include "sqlite_utils.h"
#include "store_types.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using DBStatus = DistributedDB::DBStatus;

class ConvertDBStatusNativeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(){};
    void TearDown(){};
};

void ConvertDBStatusNativeTest::SetUpTestCase(void)
{
}

void ConvertDBStatusNativeTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: ConvertDBStatusNative_All_Statuses_001
 * @tc.desc: Test ConvertDBStatusNative with all known status values to ensure correct mapping
 * @tc.type: FUNC
 */
HWTEST_F(ConvertDBStatusNativeTest, ConvertDBStatusNative_All_Statuses_001, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::ConvertDBStatusNative(DBStatus::OK), E_OK);
    EXPECT_EQ(SqliteUtils::ConvertDBStatusNative(DBStatus::BUSY), E_SQLITE_BUSY);
    EXPECT_EQ(SqliteUtils::ConvertDBStatusNative(DBStatus::INVALID_ARGS), E_INVALID_ARGS);
    EXPECT_EQ(SqliteUtils::ConvertDBStatusNative(DBStatus::INVALID_PASSWD_OR_CORRUPTED_DB), E_SQLITE_CORRUPT);
    EXPECT_EQ(SqliteUtils::ConvertDBStatusNative(DBStatus::DB_ERROR), E_SQLITE_ERROR);
    EXPECT_EQ(SqliteUtils::ConvertDBStatusNative(DBStatus::NOT_SUPPORT), E_NOT_SUPPORT_NEW);
    EXPECT_EQ(SqliteUtils::ConvertDBStatusNative(static_cast<DBStatus>(-1)), E_ERROR);
}
