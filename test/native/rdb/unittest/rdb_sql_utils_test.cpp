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

#include "rdb_sql_utils.h"

#include <gtest/gtest.h>

#include <climits>
#include <string>

#include "grd_type_export.h"
#include "rd_utils.h"
#include "sqlite_sql_builder.h"
#include "values_buckets.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class RdbSqlUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};

void RdbSqlUtilsTest::SetUpTestCase(void)
{
}

void RdbSqlUtilsTest::TearDownTestCase(void)
{
}

/**
 * @tc.name: RdbStore_SqliteUtils_001
 * @tc.desc: Normal testCase of sqlite_utils for IsSpecial, if sqlType is special
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_Test_001, TestSize.Level1)
{
    auto [dataBasePath, errCode] = RdbSqlUtils::GetDefaultDatabasePath("/data/test", "RdbTest.db");
    EXPECT_EQ(dataBasePath, "/data/test/rdb/RdbTest.db");
    EXPECT_EQ(errCode, E_OK);

    auto [dataBasePath1, errCode1] = RdbSqlUtils::GetDefaultDatabasePath("/data/test", "RdbTest.db", "myself");
    EXPECT_EQ(dataBasePath1, "/data/test/rdb/myself/RdbTest.db");
    EXPECT_EQ(errCode1, E_OK);
}

/**
 * @tc.name: RdbStore_UpdateSqlBuilder_001
 * @tc.desc: test RdbStore UpdateSqlBuilder
 * @tc.type: FUNC
 */
HWTEST_F(RdbSqlUtilsTest, RdbSqlUtils_UpdateSqlBuilder_001, TestSize.Level1)
{
    ValuesBucket values;
    values.PutString("name", std::string("zhangsan"));
    values.PutInt("age", 20);
    values.PutDouble("salary", 300.5);

    std::vector<ValueObject> bindArgs;
    std::string updateSql = SqliteSqlBuilder::BuildUpdateString(values, "test", std::vector<std::string>{ "19" }, "",
        "age = ?", "", "", INT_MIN, INT_MIN, bindArgs, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(updateSql, "UPDATE test SET age=?,name=?,salary=? WHERE age = ?");

    updateSql = SqliteSqlBuilder::BuildUpdateString(values, "test", std::vector<std::string>{}, "", "", "", "",
        INT_MIN, INT_MIN, bindArgs, ConflictResolution::ON_CONFLICT_NONE);
    EXPECT_EQ(updateSql, "UPDATE test SET age=?,name=?,salary=?");
}
