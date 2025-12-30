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
#include <dlfcn.h>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <iostream>
#include <sys/stat.h>
#include "acl.h"
#include "rdb_platform.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DATABASE_UTILS;

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
        "errno is:25 *** values for 1 col*** in \"INSERT INTO tab***(sto***) Values(1, '***')\".");
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
        "***5412 ***edf4 *** ***052");
}

HWTEST_F(SqliteUtilsTest, SqlAnonymous_004, TestSize.Level0)
{
    EXPECT_EQ(SqliteUtils::SqlAnonymous(
                  "INSERT INTO test (mac, address) VALUES ('48:b2:d3:bd:74:33', 'EEC2B4EE-D8EB-4743-AA58-BBA471E7')"),
        "INSERT INTO tes*** (m**, add***) VALUES ('48:***:***:***:***:***', '***B4EE-***-***-***-***71E7')");
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

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0027, TestSize.Level1)
{
    std::string filePath = "/data/test/SqliteUtils_Test_0027";
    std::string subPath = filePath + "/bin001";
    std::error_code ec;
    std::filesystem::create_directories(filePath, ec);
    std::ofstream src(subPath.c_str(), std::ios::binary);
    ASSERT_TRUE(src.is_open());
    src.close();
    EXPECT_EQ(1, SqliteUtils::GetFileCount(filePath)); // 1 is file count
    EXPECT_EQ(1, SqliteUtils::DeleteFolder(filePath, false)); // 1 is removed counbt
    EXPECT_EQ(0, SqliteUtils::GetFileCount(filePath));
    EXPECT_EQ(1, SqliteUtils::DeleteFolder(filePath)); // 1 is removed counbt
    EXPECT_EQ(0, SqliteUtils::GetFileCount(filePath));
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

/**
 * @tc.name: HasPermit001
 * @tc.desc: file has S_IXOTH and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, HasPermit001, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    bool res = SqliteUtils::HasPermit(fileDir, S_IXOTH);
    EXPECT_EQ(res, true);
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: HasPermit002
 * @tc.desc: file no S_IXOTH and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, HasPermit002, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    bool res = SqliteUtils::HasPermit(fileDir, S_IXOTH);
    EXPECT_EQ(res, false);
    std::remove(fileDir.c_str());
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: HasPermit003
 * @tc.desc: file not exist and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, HasPermit003, TestSize.Level1)
{
    std::string fileDir = "/data/test/database/hapname/rdb";
    bool res = SqliteUtils::HasPermit(fileDir, S_IXOTH);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: HasAccessAcl001
 * @tc.desc: file set acl and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, HasAccessAcl001, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string filename = "/data/test/database/hapname/rdb/test.db";
    int fd = open(filename.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd, -1) << "open file failed." << std::strerror(errno);

    uint16_t mode = Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT;
    auto result = Acl(filename, Acl::ACL_XATTR_ACCESS).SetAccessGroup(3012, mode);
    EXPECT_EQ(result, Acl::E_OK);
    bool res = SqliteUtils::HasAccessAcl(filename, 3012);
    EXPECT_EQ(res, true);
    std::remove(filename.c_str());
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: HasAccessAcl002
 * @tc.desc: file not set acl and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, HasAccessAcl002, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    bool res = SqliteUtils::HasAccessAcl(fileDir, 3012);
    EXPECT_EQ(res, false);
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: HasAccessAcl002
 * @tc.desc: file not exist and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, HasAccessAcl003, TestSize.Level1)
{
    std::string fileDir = "/data/test/database/hapname/rdb";
    bool res = SqliteUtils::HasAccessAcl(fileDir, 3012);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: HasDefaultAcl001
 * @tc.desc: file set default and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, HasDefaultAcl001, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);

    uint16_t mode = Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT;
    auto result = Acl(fileDir, Acl::ACL_XATTR_ACCESS).SetAccessGroup(3012, mode);
    EXPECT_EQ(result, Acl::E_OK);
    result = Acl(fileDir, Acl::ACL_XATTR_DEFAULT).SetDefaultGroup(3012, mode);
    EXPECT_EQ(result, Acl::E_OK);
    bool res = SqliteUtils::HasAccessAcl(fileDir, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasDefaultAcl(fileDir, 3012);
    EXPECT_EQ(res, true);
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: HasDefaultAcl002
 * @tc.desc: file not set default and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, HasDefaultAcl002, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    bool res = SqliteUtils::HasDefaultAcl(fileDir, 3012);
    EXPECT_EQ(res, false);
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: HasDefaultAcl003
 * @tc.desc: file not exist and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, HasDefaultAcl003, TestSize.Level1)
{
    std::string fileDir = "/data/test/database/hapname/rdb";
    bool res = SqliteUtils::HasDefaultAcl(fileDir, 3012);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetDbDirGid001
 * @tc.desc: file dir setacl and has S_IXOTH and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDbDirGid001, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string filename = "/data/test/database/hapname/rdb/test.db";
    int fd = open(filename.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd, -1) << "open file failed." << std::strerror(errno);

    bool res = SqliteUtils::SetDbDirGid(filename, 3012, false);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(fileDir, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(hapDir, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(filename, 3012);
    EXPECT_EQ(res, false);
    std::remove(filename.c_str());
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: SetDbDirGid002
 * @tc.desc: file dir setacl and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDbDirGid002, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string filename = "/data/test/database/hapname/rdb/test.db";
    int fd = open(filename.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd, -1) << "open file failed." << std::strerror(errno);

    bool res = SqliteUtils::SetDbDirGid(filename, 3012, false);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(fileDir, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(hapDir, 3012);
    EXPECT_EQ(res, true);
    std::remove(filename.c_str());
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: SetDbDirGid003
 * @tc.desc: file dir setacl and has coustomdir and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDbDirGid003, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string filename = "/data/test/database/hapname/rdb/../../../../../data/test/database/hapname/rdb/test.db";
    int fd = open(filename.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd, -1) << "open file failed." << std::strerror(errno);

    bool res = SqliteUtils::SetDbDirGid(filename, 3012, false);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(fileDir, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(hapDir, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl("/data/test", 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl("/data", 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl("/", 3012);
    EXPECT_EQ(res, false);
    std::remove(filename.c_str());
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: SetDbDirGid004
 * @tc.desc: file dir not exist and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDbDirGid004, TestSize.Level1)
{
    std::string fileDir = "/data/test/database/hapname/rdb";
    std::string hapDir = "/data/test/database/hapname";
    std::string filename = "/data/test/database/hapname/rdb/test.db";

    bool res = SqliteUtils::SetDbDirGid(filename, 3012, false);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(fileDir, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(hapDir, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(filename, 3012);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetDbDirGid005
 * @tc.desc: path is empty and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDbDirGid005, TestSize.Level1)
{
    bool res = SqliteUtils::SetDbDirGid("", 3012, false);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetDefaultGid001
 * @tc.desc: file set default acl and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDefaultGid001, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string binlogDir = "/data/test/database/hapname/rdb/binlog/";
    ret = MkDir(binlogDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string filename = "/data/test/database/hapname/rdb/binlog/test.db";
    int fd = open(filename.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd, -1) << "open file failed." << std::strerror(errno);
    std::string filename1 = "/data/test/database/hapname/rdb/binlog/test.wal";
    int fd1 = open(filename1.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd1, -1) << "open file failed." << std::strerror(errno);

    bool res = SqliteUtils::SetDbDirGid(binlogDir, 3012, true);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(binlogDir, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasDefaultAcl(binlogDir, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(filename, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(filename1, 3012);
    EXPECT_EQ(res, true);
    std::remove(filename.c_str());
    std::remove(filename1.c_str());
    std::remove(binlogDir.c_str());
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: SetDefaultGid002
 * @tc.desc: file not exist set default acl and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDefaultGid002, TestSize.Level1)
{
    std::string fileDir = "/data/test/database/hapname/rdb/binlog";
    std::string filename = "/data/test/database/hapname/rdb/binlog/test.db";
    std::string filename1 = "/data/test/database/hapname/rdb/binlog/test.wal";

    bool res = SqliteUtils::SetDefaultGid(filename, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(fileDir, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasDefaultAcl(fileDir, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(filename, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(filename1, 3012);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetDefaultGid003
 * @tc.desc: path is empty and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDefaultGid003, TestSize.Level1)
{
    bool res = SqliteUtils::SetDefaultGid("", 3012);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetDbFileGid001
 * @tc.desc: file set acl and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDbFileGid001, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string filename = "/data/test/database/hapname/rdb/test.db";
    int fd = open(filename.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd, -1) << "open file failed." << std::strerror(errno);
    std::string filename1 = "/data/test/database/hapname/rdb/test.db-wal";
    int fd1 = open(filename1.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd1, -1) << "open file failed." << std::strerror(errno);
    std::vector<std::string> files;
    files.push_back("test.db");
    files.push_back("test.db-wal");

    bool res = SqliteUtils::SetDbFileGid(filename, files, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(filename, 3012);
    EXPECT_EQ(res, true);
    res = SqliteUtils::HasAccessAcl(filename1, 3012);
    EXPECT_EQ(res, true);
    std::remove(filename.c_str());
    std::remove(filename1.c_str());
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: SetDbFileGid002
 * @tc.desc: files is empty and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDbFileGid002, TestSize.Level1)
{
    std::string databaseDir = "/data/test/database";
    auto ret = MkDir(databaseDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string hapDir = "/data/test/database/hapname";
    ret = MkDir(hapDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string fileDir = "/data/test/database/hapname/rdb";
    ret = MkDir(fileDir, (S_IRWXU | S_IRWXG | S_IROTH));
    EXPECT_EQ(ret, 0) << "directory creation failed." << std::strerror(errno);
    std::string filename = "/data/test/database/hapname/rdb/test.db";
    int fd = open(filename.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd, -1) << "open file failed." << std::strerror(errno);
    std::string filename1 = "/data/test/database/hapname/rdb/test.db-wal";
    int fd1 = open(filename1.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    EXPECT_NE(fd1, -1) << "open file failed." << std::strerror(errno);
    std::vector<std::string> files;

    bool res = SqliteUtils::SetDbFileGid(filename, files, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(fileDir, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(filename, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(filename1, 3012);
    EXPECT_EQ(res, false);
    std::remove(filename.c_str());
    std::remove(filename1.c_str());
    std::remove(fileDir.c_str());
    std::remove(hapDir.c_str());
    std::remove(databaseDir.c_str());
}

/**
 * @tc.name: SetDbFileGid003
 * @tc.desc: path is empty and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDbFileGid003, TestSize.Level1)
{
    std::vector<std::string> files;
    files.push_back("test.db");
    files.push_back("test.db-wal");

    bool res = SqliteUtils::SetDbFileGid("", files, 3012);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetDbFileGid004
 * @tc.desc: path is not exist and check
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, SetDbFileGid004, TestSize.Level1)
{
    std::string filename = "/data/test/database/hapname/rdb/test.db";
    std::vector<std::string> files;
    files.push_back("test.db");
    files.push_back("test.db-wal");

    bool res = SqliteUtils::SetDbFileGid(filename, files, 3012);
    EXPECT_EQ(res, false);
    res = SqliteUtils::HasAccessAcl(filename, 3012);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: CopyFile001
 * @tc.desc: copy to read-only file
 * @tc.type: FUNC
 */
HWTEST_F(SqliteUtilsTest, CopyFile001, TestSize.Level1)
{
    std::string srcFilename = "/data/test/srcTest.db";
    int srcFd = open(srcFilename.c_str(), O_RDONLY | O_CREAT, S_IRUSR);
    EXPECT_NE(srcFd, -1) << "open src file failed." << std::strerror(errno);
    close(srcFd);

    std::string desFilename = "/data/test/desTest.db";
    int desFd = open(desFilename.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    EXPECT_NE(desFd, -1) << "open des file failed." << std::strerror(errno);
    close(desFd);

    bool res = SqliteUtils::CopyFile(srcFilename, desFilename);
    EXPECT_EQ(res, true);

    std::remove(srcFilename.c_str());
    std::remove(desFilename.c_str());
}