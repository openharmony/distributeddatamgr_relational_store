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
#include "acl.h"
#include "rdb_platform.h"
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DATABASE_UTILS;
constexpr int32_t SERVICE_GID = 3012;

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
HWTEST_F(SqliteUtilsTest, CheckFilePermissionsTest_001, TestSize.Level2)
{
    mode_t mode = S_IRWXU | S_IRWXG | S_IXOTH;
    mkdir("/data/test/abc", mode);
    SqliteUtils::SetFilePermissions("/data/test/abc");
    auto ret = SqliteUtils::CheckFilePermissions("/data/test/abc");
    EXPECT_EQ(ret, true);
    remove("/data/test/abc");
}

HWTEST_F(SqliteUtilsTest, CheckFilePermissionsTest_002, TestSize.Level2)
{
    mode_t mode = S_IRWXU | S_IRWXG | S_IXOTH;
    mkdir("/data/test/abc", mode);
    AclXattrEntry group = {ACL_TAG::GROUP, SERVICE_GID, Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT};
    AclXattrEntry user = {ACL_TAG::USER, GetUid(), Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT};
    Acl aclDefault("/data/test/abc", Acl::ACL_XATTR_DEFAULT);
    aclDefault.SetAcl(group);
    aclDefault.SetAcl(user);
    Acl aclAccess("/data/test/abc", Acl::ACL_XATTR_ACCESS);
    aclAccess.SetAcl(group);
    aclAccess.SetAcl(user);
    auto ret = SqliteUtils::CheckFilePermissions("/data/test/abc");
    EXPECT_EQ(ret, true);
    remove("/data/test/abc");
}

HWTEST_F(SqliteUtilsTest, CheckFilePermissionsTest_003, TestSize.Level2)
{
    mode_t mode = S_IRWXU | S_IRWXG | S_IXOTH;
    mkdir("/data/test/abc", mode);
    AclXattrEntry group = {ACL_TAG::GROUP, SERVICE_GID, Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT};
    Acl aclDefault("/data/test/abc", Acl::ACL_XATTR_DEFAULT);
    aclDefault.SetAcl(group);
    Acl aclAccess("/data/test/abc", Acl::ACL_XATTR_ACCESS);
    aclAccess.SetAcl(group);
    auto ret = SqliteUtils::CheckFilePermissions("/data/test/abc");
    EXPECT_EQ(ret, true);
    remove("/data/test/abc");
}

HWTEST_F(SqliteUtilsTest, CheckFilePermissionsTest_004, TestSize.Level2)
{
    mode_t mode = S_IRWXU | S_IRWXG | S_IXOTH;
    mkdir("/data/test/abc", mode);
    AclXattrEntry user = {ACL_TAG::USER, GetUid(), Acl::R_RIGHT | Acl::W_RIGHT | Acl::E_RIGHT};
    Acl aclDefault("/data/test/abc", Acl::ACL_XATTR_DEFAULT);
    aclDefault.SetAcl(user);
    Acl aclAccess("/data/test/abc", Acl::ACL_XATTR_ACCESS);
    aclAccess.SetAcl(user);
    auto ret = SqliteUtils::CheckFilePermissions("/data/test/abc");
    EXPECT_EQ(ret, true);
    remove("/data/test/abc");
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
    EXPECT_EQ(
        SqliteUtils::Anonymous("file /data/stage/el2/database/rdb/ddddddd/30005245854585524412855412_rdb_test.db"),
        "file /***/el2/***/***5412_rdb_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_008, TestSize.Level1)
{
    EXPECT_EQ(SqliteUtils::Anonymous("file /data/stage/database/rdb/ddddddd/30005245854585524412855412_rdb_test.db"),
        "file /***/***5412_rdb_test.db");
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_009, TestSize.Level1)
{
    EXPECT_EQ(
        SqliteUtils::Anonymous("file /data/stage/el2/database/rdb/ddddddd/3E00mnj5H54efg5G4K1ABC5412_rdb_test.db"),
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
    EXPECT_EQ(0, SqliteUtils::DeleteFolder("non_exist_folder/random123"));
}

HWTEST_F(SqliteUtilsTest, SqliteUtils_Test_0025, TestSize.Level1)
{
    EXPECT_NE(0, SqliteUtils::SetSlaveRestoring("non_exist_folder/non_exist_file"));
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
