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
    EXPECT_EQ(SqliteUtils::AnonySql("select value1, value2 from table1 WHERE case = 1."),
        "select ***ue1, ***ue2 from ***le1 WHERE *ase = *.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0025, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("select district value1, value2 from table1 "
                                    "WHERE case = 1 groupby value1 limit 1."),
        "select district ***ue1, ***ue2 from ***le1 "
        "WHERE *ase = * groupby ***ue1 limit *.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0026, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("select value1, value2 from table1."), "select ***ue1, ***ue2 from ***le1.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0027, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("select table1.value1, table2.value2 from table1, table2."),
        "select ***le1.***ue1, ***le2.***ue2 from ***le1, ***le2.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0028, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::AnonySql("select ***le1.***ue1 as *d, ***le2.***ue2 as **lue from ***le1 as A, ***le2 as B."),
        "select ***le1.***ue1 as *d, ***le2.***ue2 as **lue from ***le1 as A, ***le2 as B.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0029, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("SELECT * FROM test."), "SELECT * FROM *est.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0030, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("SELECT count(*) FROM test."), "SELECT count(*) FROM *est.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0031, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("SELECT average(*) FROM test."), "SELECT average(*) FROM *est.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0032, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?);"),
        "INSERT INTO *est (**ta1, **ta2, **ta3, **ta4) VALUES (?, ?, ?, ?);");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0033, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql(
                  "INSERT INTO test (data1, data2, data3, data4) VALUES (?, ?, ?, ?),(?,?,?,?),(?,?,?,?),(?,?,?,?);"),
        "INSERT INTO *est (**ta1, **ta2, **ta3, **ta4) VALUES (?, ?, ?, ?),(?,?,?,?),(?,?,?,?),(?,?,?,?);");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0034, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("UPDATE test SET age = 8 WHERE id = 1."), "UPDATE *est SET *ge = * WHERE *d = *.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0035, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("UPDATE test SET age = 8 WHERE id = 1 and id = 1 or id = 1."),
        "UPDATE *est SET *ge = * WHERE *d = * and *d = * or *d = *.");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0036, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DELETE FROM test;"), "DELETE FROM *est;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0037, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DELETE FROM test WHERE time = 3;"), "DELETE FROM *est WHERE *ime = *;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0038, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("CREATE DATABASE DBtest.db;"), "CREATE DATABASE ***est.*b;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0039, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("CREATE TABLE IF NOT EXISTS TEST (id INT PRIMARY KEY, name TEXT, extend BLOB, "
                                    "code REAL, years UNLIMITED INT, ment ASSET, ments ASSETS)."),
        "CREATE TABLE IF NOT EXISTS *EST (*d INT PRIMARY KEY, *ame TEXT, "
        "***end BLOB, *ode REAL, **ars UNLIMITED INT, *ent ASSET, **nts ASSETS).");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0040, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("CREATE TABLE TEST (id INT PRIMARY KEY, name TEXT, "
                                    "extend BLOB, code REAL, years UNLIMITED INT, ment ASSET, ments ASSETS)."),
        "CREATE TABLE *EST (*d INT PRIMARY KEY, *ame TEXT, "
        "***end BLOB, *ode REAL, **ars UNLIMITED INT, *ent ASSET, **nts ASSETS).");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0041, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DROP TABLE IF EXISTS table1;"), "DROP TABLE IF EXISTS ***le1;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0042, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DROP TABLE table1;"), "DROP TABLE ***le1;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0043, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DROP DATABASE IF EXISTS name1;"), "DROP DATABASE IF EXISTS **me1;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0044, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("DROP DATABASE name2;"), "DROP DATABASE **me2;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0045, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("PRAGMA version = 3"), "PRAGMA ****ion = *");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0046, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::AnonySql("ALTER TABLE test ADD COLUMN name TEXT;"), "ALTER TABLE *est ADD COLUMN *ame TEXT;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0047, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("CREATE                        TABLE       TEST (id INT PRIMARY KEY, name TEXT,"
                                    " extend BLOB, code REAL, years UNLIMITED INT, ment ASSET, ments ASSETS)."),
        "CREATE TABLE *EST (*d INT PRIMARY KEY, *ame TEXT, "
        "***end BLOB, *ode REAL, **ars UNLIMITED INT, *ent ASSET, **nts ASSETS).");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0048, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("ALTER TABLE test DROP COLUMN name;"), "ALTER TABLE *est DROP COLUMN *ame;");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0049, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::AnonySql("CREATE TABLE IF NOT EXISTS name AS SELECT order AS old, "
                                    "order AS new UNION SELECT shot AS old, shot AS new ;"),
        "CREATE TABLE IF NOT EXISTS *ame AS ***ECT **der AS *ld, "
        "**der AS *ew UNION ***ECT *hot AS *ld, *hot AS *ew ;");
}