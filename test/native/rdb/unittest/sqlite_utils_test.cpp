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

#include "sqlite_utils.h"

#include <gtest/gtest.h>

#include <climits>
#include <string>

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class SqliteUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void){};
    void TearDown(void){};
};

void SqliteUtilsTest::SetUpTestCase(void)
{
}

void SqliteUtilsTest::TearDownTestCase(void)
{
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_001, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("30005245854585524412855412_rdb_test.db"), "***5412_rdb_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_002, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("rdb_test_30005245854585524412855412.db"), "rdb_test_***5412.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_003, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("rdb_30005245854585524412855412_test.db"), "rdb_***5412_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_004, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("rdb_300052_test.db"), "rdb_***052_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_005, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("rdb_30005_test.db"), "rdb_30005_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_006, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("rdb_3000523_test.db"), "rdb_***0523_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_007, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous(
                  "file /data/stage/el2/database/rdb/ddddddd/30005245854585524412855412_rdb_test.db"),
        "file /***/el2/***/***5412_rdb_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_008, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::Anonymous("file /data/stage/database/rdb/ddddddd/30005245854585524412855412_rdb_test.db"),
        "file /***/***5412_rdb_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_009, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous(
                  "file /data/stage/el2/database/rdb/ddddddd/3E00mnj5H54efg5G4K1ABC5412_rdb_test.db"),
        "file /***/el2/***/3E00mnj5H54efg5G4K***5412_rdb_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_010, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("/data/stage/el2/database/rdb/ddddddd/3E00mnj5H54efg5G4K1ABC5412_rdb_test.db"),
        "/***/el2/***/3E00mnj5H54efg5G4K***5412_rdb_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0011, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("30005245854585524412855412.db"), "***5412.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0012, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("thequickbrownfoxjumpoverthelazydog.db"), "thequickbrownfoxjumpoverthelazydog.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0013, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("123edf4.db"), "***edf4.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0014, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("K123edfK.db"), "K***edfK.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0015, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("K23edfK.db"), "K23edfK.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0016, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("__23edf__.db"), "__23edf__.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0017, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("K3edfK.db"), "K3edfK.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0018, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("K23564edfK.db"), "K***4edfK.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0019, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("K235648edfK.db"), "K***8edfK.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0020, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("K2356489edfK.db"), "K***9edfK.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0021, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("linker_reborn.db-wal"), "linker_reborn.db-wal");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0022, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("linker_grow.db-wal"), "linker_grow.db-wal");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0023, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("file /data/stage/el2/database/rdb/ddddddd/linker_reborn.db-wal"),
        "file /***/el2/***/linker_reborn.db-wal");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0024, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("select value1, value2 from bigint_table WHERE case = 1."),
        "SELECT v***e*, v***e* FROM big*******le WHERE c*** = *.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0025, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::AnonySql("select value1, value2 from bigint_table."), "SELECT v***e*, v***e* FROM big*******le.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0026, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("SELECT * FROM test."), "SELECT * FROM t***.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0027, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);"),
        "INSERT INTO t*** (d****, d****, d****, d****) VALUES (?, ?, ?, ?);");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0028, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::AnonySql("UPDATE test SET age = 18 WHERE id = 1."), "UPDATE t*** *ET *ge = ** W***E *d = *.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0029, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DELETE FROM test;"), "DELETE FROM t***;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0030, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DELETE FROM test WHERE time = 30;"), "DELETE FROM t*** W***E t*** = **;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0031, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("CREATE DATABASE DBtest.db;"), "CREATE DATABASE D***st.*b;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0032, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::AnonySql(
            "CREATE TABLE IF NOT EXISTS TEST (id INT PRIMARY KEY, name TEXT, extend BLOB, code REAL, years UNLIMITED INT, attachment ASSET, attachments ASSETS)."),
        "CREATE TABLE *F *OT E***TS T*** (*d *NT P***ARY *EY, n*** T***, e***nd B***, c*** R***, y***s UN*****ED *NT, at*****ent A***T, at*****ents A***TS).");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0033, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::AnonySql(
            "CREATE TABLE TEST (id INT PRIMARY KEY, name TEXT, extend BLOB, code REAL, years UNLIMITED INT, attachment ASSET, attachments ASSETS)."),
        "CREATE TABLE T*** (*d *NT P***ARY *EY, n*** T***, e***nd B***, c*** R***, y***s UN*****ED *NT, at*****ent A***T, at*****ents A***TS).");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0034, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DROP TABLE IF EXISTS bigint_table;"), "DROP TABLE IF EXISTS big*******le;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0035, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DROP TABLE bigint_table;"), "DROP TABLE big*******le;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0036, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::AnonySql("DROP DATABASE IF EXISTS database_name;"), "DROP DATABASE IF EXISTS dat*******ame;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0037, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DROP DATABASE database_name;"), "DROP DATABASE dat*******ame;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0038, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("PRAGMA user_version = 3"), "PRAGMA use*******on = *");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0039, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("ALTER TABLE test ADD COLUMN address TEXT;"),
        "ALTER TABLE t*** *DD C***MN a***ess T***;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0040, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::AnonySql(
            "CREATE                        TABLE       TEST (id INT PRIMARY KEY, name TEXT, extend BLOB, code REAL, years UNLIMITED INT, attachment ASSET, attachments ASSETS)."),
        "CREATE TABLE T*** (*d *NT P***ARY *EY, n*** T***, e***nd B***, c*** R***, y***s UN*****ED *NT, at*****ent A***T, at*****ents A***TS).");
}