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
#include <fstream>
#include <string>

using namespace testing::ext;
using namespace OHOS::NativeRdb;

class SqliteUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void) {};
    void TearDown(void) {};
};

void SqliteUtilsTest::SetUpTestCase(void)
{
}

void SqliteUtilsTest::TearDownTestCase(void)
{
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_001, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("30005245854585524412855412_rdb_test.db"), "300***.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_007, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::Anonymous("file /data/stage/el2/database/rdb/ddddddd/30005245854585524412855412_rdb_test.db"),
        "file /***/el2/***/300***.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_009, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::Anonymous("file /data/stage/el2/database/rdb/ddddddd/3E00mnj5H54efg5G4K1ABC5412_rdb_test.db"),
        "file /***/el2/***/3E0***.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0011, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("30005245854585524412855412.db"), "300***.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0013, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("123edf4.db"), "123***.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0016, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("__23edf__.db"), "__2***.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0021, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("linker_reborn.db-wal"), "lin***wal");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0022, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("linker_grow.db-wal"), "lin***wal");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0023, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("file /data/stage/el2/database/rdb/ddddddd/linker_reborn.db-wal"),
        "file /***/el2/***/lin***wal");
}

HWTEST_F(SqliteUtilsTest, Anonymous_001, TestSize.Level0)
{
    EXPECT_EQ(SqliteUtils::Anonymous(""), "");
    EXPECT_EQ(SqliteUtils::Anonymous("x"), "x**");
    EXPECT_EQ(SqliteUtils::Anonymous("xx"), "x**");
    EXPECT_EQ(SqliteUtils::Anonymous("xxx"), "x**");
    EXPECT_EQ(SqliteUtils::Anonymous("xxxx"), "xxx***");
    EXPECT_EQ(SqliteUtils::Anonymous("xxxxx"), "xxx***");
    EXPECT_EQ(SqliteUtils::Anonymous("xxxxxx"), "xxx***");
    EXPECT_EQ(SqliteUtils::Anonymous("xxxxxxx"), "xxx***");
    EXPECT_EQ(SqliteUtils::Anonymous("xxxxxxxx"), "xxx***");
    EXPECT_EQ(SqliteUtils::Anonymous("xxxxxxxxx"), "xxx***xxx");
    EXPECT_EQ(SqliteUtils::Anonymous("xxxxxxxxxx"), "xxx***xxx");
}

HWTEST_F(SqliteUtilsTest, SqlAnonymous_001, TestSize.Level0)
{
    EXPECT_EQ(SqliteUtils::SqlAnonymous("SELECT * FROM users WHERE id = 1"), "SELECT * FROM use*** WHERE i** = 1");
    EXPECT_EQ(SqliteUtils::SqlAnonymous(
                  "statement abort at 11: [ SELECT COUNT(1) AS count FROM Photos WHERE type = 'screenshot'"),
        "statement abort at 11: [ SELECT COUNT(1) AS count FROM Pho*** WHERE type = 'scr***hot'");
    EXPECT_EQ(SqliteUtils::SqlAnonymous("errno is:25 ambiguous column name:"
                                        " name in \"SELECT name FROM tableA JOIN tableB ON tableA.id = tableB.a_id;\""),
        "errno is:25 ambiguous column name:"
        " name in \"SELECT name FROM tab*** JOIN tab*** ON tab***.i** = tab***.a_i***;\"");
    EXPECT_EQ(
        SqliteUtils::SqlAnonymous("errno is:25 ambiguous column name:"
                                  " story in \"SELECT story FROM tableA JOIN tableB ON tableA.id = tableB.a_id;\""),
        "errno is:25 ambiguous column name:"
        " sto*** in \"SELECT sto*** FROM tab*** JOIN tab*** ON tab***.i** = tab***.a_i***;\"");
    EXPECT_EQ(SqliteUtils::SqlAnonymous(
                  "errno is:25 2 values for 1 columns in \"INSERT INTO tableA(story) Values(1, '你好中文字符')\"."),
        "errno is:25 2 values for 1 col*** in \"INSERT INTO tab***(sto***) Values(1, '***')\".");
    EXPECT_EQ(
        SqliteUtils::SqlAnonymous("errno is:0 no such table: CommonAddressModel in"
                                  " \"SELECT * FROM CommonAddressModel WHERE addressType IN (? , ?)AND uid = ? \""),
        "errno is:0 no such table: Com***del in \"SELECT * FROM Com***del WHERE add***ype IN (? , ?)AND u** = ? \"");
    EXPECT_EQ(SqliteUtils::SqlAnonymous("abort at 14 in [INSERT INTO SETTINGSDATA(KEYWORD,VALUE) VALUES (?,?)]: "
                                        "UNIQUE constraint failed: SETTINGSDATA.KEYWORD"),
        "abort at 14 in [INSERT INTO SET***ATA(KEY***,VAL***) VALUES (?,?)]: "
        "UNIQUE constraint failed: SET***ATA.KEY***");
    EXPECT_EQ(SqliteUtils::SqlAnonymous("error is:2 misuse at line 57f4b3 if [6cd587f]"),
        "error is:2 misuse at line ***4b3 if [***587f]");

    EXPECT_EQ(SqliteUtils::SqlAnonymous("[SQLite]BusyLine:63706, idx:0, type:4, fileLock:0, len:1, handleLocks:none"),
        "[SQLite]BusyLine:63706, idx:0, type:4, fileLock:0, len:1, handleLocks:none");
    EXPECT_EQ(SqliteUtils::SqlAnonymous("[SQLite]acqLock:1, dbRef:2, lockCnt:2, curLock:1, processLock:0"),
        "[SQLite]acqLock:1, dbRef:2, lockCnt:2, curLock:1, processLock:0");
    EXPECT_EQ(SqliteUtils::SqlAnonymous("[SQLite]Trx locks: <shared_first, pid:1030, F_RDLCK>"),
        "[SQLite]Trx locks: <shared_first, pid:1030, F_RDLCK>");
    EXPECT_EQ(SqliteUtils::SqlAnonymous("hello 简体中文 world"), "hel*** *** wor***");
    EXPECT_EQ(SqliteUtils::SqlAnonymous("hello简体cplus中文world"), "hel******cpl******wor***");
}

HWTEST_F(SqliteUtilsTest, SqlAnonymous_002, TestSize.Level0)
{
    EXPECT_EQ(SqliteUtils::SqlAnonymous(
                  "[SQLite]Wal locks: <write, -1, tid:3325><write, pid:3226, F_WRLCK><read1, 1, tid:3325>"
                  "<read1, pid:3226, F_RDLCK><wal_dms, pid:1030, F_RDLCK>"),
        "[SQLite]Wal locks: <write, -1, tid:3325><write, pid:3226, F_WRLCK><rea***, 1, tid:3325>"
        "<rea***, pid:3226, F_RDLCK><wal_dms, pid:1030, F_RDLCK>");
    EXPECT_EQ(SqliteUtils::SqlAnonymous(
                  "statement aborts at 32: [UPDATE SETTINGSDATA SET KEYWORD=?,VALUE=? WHERE KEYWORD = ? ]"
                  " database schema has changed"),
        "statement aborts at 32: [UPDATE SET***ATA SET KEY***=?,VAL***=? WHERE KEY*** = ? ]"
        " database schema has changed");
    EXPECT_EQ(
        SqliteUtils::SqlAnonymous("abort at 14 in [INSERT INTO USER_SETTINGSDATA_100(KEYWORD,VALUE) VALUES (?,?)]: "
                                  "UNIQUE constraint failed: USER_SETTINGSDATA_100.KEYWORD"),
        "abort at 14 in [INSERT INTO USE***100(KEY***,VAL***) VALUES (?,?)]: "
        "UNIQUE constraint failed: USE***100.KEY***");
    EXPECT_EQ(SqliteUtils::SqlAnonymous(
                  "errno is:2 near \"IF\": syntax error in \"CREATE TRIGGER IF NOT EXISTS [update_contact_data_version]"
                  " AFTER UPDATE ON [contact_data] BEGIN IF UPDATE [version] RETURN; UPDATE [contact_data] "
                  "SET [version] = [OLD].[version] + 1 WHERE [id] = [OLD].[id]; END\"."),
        "errno is:2 near \"IF\": syntax error in \"CREATE TRIGGER IF NOT EXISTS [upd***ion]"
        " AFTER UPDATE ON [con***ata] BEGIN IF UPDATE [ver***] RET***; UPDATE [con***ata] "
        "SET [ver***] = [O**].[ver***] + 1 WHERE [i**] = [O**].[i**]; END\".");
    EXPECT_EQ(SqliteUtils::SqlAnonymous("Fd 7 enable del monitor go wrong, errno = 13"),
        "Fd 7 enable del monitor go wrong, errno = 13");
    EXPECT_EQ(SqliteUtils::SqlAnonymous(
                  "errno is:95 duplicate column name: Timestamp in \"ALTER TABLE BSD ADD COLUMN Timestamp TE."),
        "errno is:95 duplicate column name: Tim***amp in \"ALTER TABLE B** ADD COLUMN Tim***amp T**.");
    EXPECT_EQ(
        SqliteUtils::SqlAnonymous("recovered 9 frames from WAL file /data/storage/el1/database/entry/hello.db-wal"),
        "recovered 9 frames from WAL file /dat***/sto***/e**/database/ent***/hel***.db-wal");
}

HWTEST_F(SqliteUtilsTest, SqlAnonymous_003, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::SqlAnonymous("30005245854585524412855412 123edf4 30005 300052"),
        "***5412 ***edf4 30005 ***052");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0024, TestSize.Level1)
{
    EXPECT_EQ(0, SqliteUtils::DeleteFolder("non_exist_folder/random123"));
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0025, TestSize.Level1)
{
    EXPECT_NE(0, SqliteUtils::SetSlaveRestoring("non_exist_folder/non_exist_file"));
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0026, TestSize.Level1)
{
    EXPECT_EQ(0, SqliteUtils::GetFileCount("non_exist_folder"));
    std::string filePath = "/data/test/SqliteUtils_Test_0026";
    std::ofstream src(filePath.c_str(), std::ios::binary);
    ASSERT_TRUE(src.is_open());
    src.close();
    EXPECT_EQ(0, SqliteUtils::GetFileCount(filePath));
    std::remove(filePath.c_str());
}

HWTEST_F(SqliteUtilsTest, HandleNormalPath, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::GetParentModes("/data/service/el1/public/database/distributeddata/meta", 3),
        "pub***:mode:d711 <- dat***:mode:d711 <- dis***:mode:d770");
}

HWTEST_F(SqliteUtilsTest, ExceedPathDepth, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::GetParentModes("a/backup/c", 5), "a:access_fail <- bac***:access_fail");
}

HWTEST_F(SqliteUtilsTest, UnixRootPath, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::GetParentModes("/", 1), "no_parent");
}

HWTEST_F(SqliteUtilsTest, AccessFailureCase, TestSize.Level1)
{
    EXPECT_NE(SqliteUtils::GetParentModes("a/non_existing_path", 1).find("access_fail"), std::string::npos);
}

HWTEST_F(SqliteUtilsTest, LongDirectoryName, TestSize.Level1)
{
    std::string longName(20, 'a');
    EXPECT_NE(SqliteUtils::GetParentModes(longName + "/b", 1).find("aaa***"), std::string::npos);
}
