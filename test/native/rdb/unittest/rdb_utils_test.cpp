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

#include <climits>
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

/**
 * @tc.name: RdbStore_SqliteUtils_006
 * @tc.desc: Normal testCase of string_utils, if fileName is ""
 * @tc.type: FUNC
 */
HWTEST_F(RdbUtilsTest, RdbStore_SqliteUtils_006, TestSize.Level1)
{
    // fileName size is 0
    EXPECT_EQ(0, SqliteUtils::GetFileSize(""));
}

/**
 * @tc.name: RdbStore_SqliteUtils_007
 * @tc.desc: AbNormal testCase of string_utils, if fileName is ""
 * @tc.type: FUNC
 */
HWTEST_F(RdbUtilsTest, RdbStore_SqliteUtils_007, TestSize.Level1)
{
    EXPECT_EQ(0, SqliteUtils::GetFileSize("act.txt"));
}

/**
 * @tc.name: GetSqlStatementType_001
 * @tc.desc: Normal testCase of GetSqlStatementType
 * @tc.type: FUNC
 */
HWTEST_F(RdbUtilsTest, GetSqlStatementType_001, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::STATEMENT_SELECT, SqliteUtils::GetSqlStatementType("select * from text"));
    EXPECT_EQ(SqliteUtils::STATEMENT_UPDATE, SqliteUtils::GetSqlStatementType("update test set id = ?"));
    EXPECT_EQ(SqliteUtils::STATEMENT_UPDATE, SqliteUtils::GetSqlStatementType("delete from test where id = ?"));
    EXPECT_EQ(SqliteUtils::STATEMENT_UPDATE, SqliteUtils::GetSqlStatementType("Replace INTO test"));
    EXPECT_EQ(SqliteUtils::STATEMENT_ATTACH, SqliteUtils::GetSqlStatementType("attach database ? as ?"));
    EXPECT_EQ(SqliteUtils::STATEMENT_DETACH, SqliteUtils::GetSqlStatementType("detach database ?"));
    EXPECT_EQ(SqliteUtils::STATEMENT_BEGIN, SqliteUtils::GetSqlStatementType("BEGIN TRANSACTION"));
    EXPECT_EQ(SqliteUtils::STATEMENT_BEGIN, SqliteUtils::GetSqlStatementType("SAVEPOINT 1"));
    EXPECT_EQ(SqliteUtils::STATEMENT_COMMIT, SqliteUtils::GetSqlStatementType("END TRANSACTION"));
    EXPECT_EQ(SqliteUtils::STATEMENT_COMMIT, SqliteUtils::GetSqlStatementType("COMMIT"));
    EXPECT_EQ(SqliteUtils::STATEMENT_ROLLBACK, SqliteUtils::GetSqlStatementType("ROLLBACK"));
    EXPECT_EQ(SqliteUtils::STATEMENT_PRAGMA, SqliteUtils::GetSqlStatementType("PRAGMA user_version"));
    EXPECT_EQ(SqliteUtils::STATEMENT_DDL, SqliteUtils::GetSqlStatementType("CREATE TABLE"));
    EXPECT_EQ(SqliteUtils::STATEMENT_DDL, SqliteUtils::GetSqlStatementType("CREATE TRIGGER"));
    EXPECT_EQ(SqliteUtils::STATEMENT_DDL, SqliteUtils::GetSqlStatementType("DROP TABLE"));
    EXPECT_EQ(SqliteUtils::STATEMENT_DDL, SqliteUtils::GetSqlStatementType("ALTER TABLE"));
    EXPECT_EQ(SqliteUtils::STATEMENT_INSERT, SqliteUtils::GetSqlStatementType("INSERT INTO test"));
    EXPECT_EQ(SqliteUtils::STATEMENT_OTHER, SqliteUtils::GetSqlStatementType("EXPLAIN SELECT * FROM test"));
    EXPECT_EQ(SqliteUtils::STATEMENT_OTHER, SqliteUtils::GetSqlStatementType("SAZZZZZZZ"));
    EXPECT_EQ(SqliteUtils::STATEMENT_OTHER, SqliteUtils::GetSqlStatementType("SAAAAAAAA"));
    EXPECT_EQ(SqliteUtils::STATEMENT_OTHER, SqliteUtils::GetSqlStatementType("PROCESS"));
}

/**
 * @tc.name: GetSqlStatementType_002
 * @tc.desc: Normal testCase of GetSqlStatementType
 *           1.Spaces before the sql
 *           2.Enter before the sql
 *           3.Non-alphanumeric and non-numeric before the sql
 * @tc.type: FUNC
 */
HWTEST_F(RdbUtilsTest, GetSqlStatementType_002, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::STATEMENT_SELECT, SqliteUtils::GetSqlStatementType("   select * from text"));
    EXPECT_EQ(SqliteUtils::STATEMENT_UPDATE, SqliteUtils::GetSqlStatementType("\r\nupdate test set id = ?"));
    EXPECT_EQ(SqliteUtils::STATEMENT_OTHER, SqliteUtils::GetSqlStatementType("~!@# attach database ? as ?"));
}