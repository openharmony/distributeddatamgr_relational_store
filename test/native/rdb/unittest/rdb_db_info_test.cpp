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

#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <string>

#include "rdb_db_info_manager.h"
#include "rdb_db_info_record.h"
#include "serializable.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::NativeRdb;
namespace {
constexpr const char *TEST_DB_PATH = "/data/test/rdbdfx_test.db";
constexpr const char *DFX_SUFFIX = ".rdbdfx.json";
constexpr const char *LOCK_SUFFIX = ".rdbdfx.lock";
static constexpr int WRITE_LEN = 4;

std::string DfxPath()
{
    return std::string(TEST_DB_PATH) + DFX_SUFFIX;
}

void CreateTestFile(const std::string &path)
{
    int fd = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd >= 0) {
        write(fd, "test", WRITE_LEN);
        close(fd);
    }
}
} // namespace

class RdbDbInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RdbDbInfoTest::SetUpTestCase(void)
{
}

void RdbDbInfoTest::TearDownTestCase(void)
{
}

void RdbDbInfoTest::SetUp()
{
    (void)remove(DfxPath().c_str());
    (void)remove((std::string(TEST_DB_PATH) + LOCK_SUFFIX).c_str());
    (void)remove(TEST_DB_PATH);
    CreateTestFile(TEST_DB_PATH);
}

void RdbDbInfoTest::TearDown()
{
    (void)remove(DfxPath().c_str());
    (void)remove((std::string(TEST_DB_PATH) + LOCK_SUFFIX).c_str());
    (void)remove(TEST_DB_PATH);
}

/**
 * @tc.name: RdbDbInfoRecord_MarshalUnmarshal_001
 * @tc.desc: Test RdbDbInfoRecord Marshal/Unmarshal round-trip.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoRecord_MarshalUnmarshal_001, TestSize.Level1)
{
    RdbDbInfoRecord rec;
    rec.lastOpenDbInfo.config.name = "test.db";
    rec.lastOpenDbInfo.config.path = "/data/test/test.db";
    rec.lastOpenDbInfo.config.isEncrypted = true;
    rec.lastOpenDbInfo.config.securityLevel = 3;
    rec.lastOpenDbInfo.config.journalMode = "WAL";
    rec.lastOpenDbInfo.config.sync = "FULL";
    rec.lastOpenDbInfo.config.walAutoCheckpoint = 1000;
    rec.lastOpenDbInfo.created = true;
    rec.lastOpenDbInfo.keyPresent = false;
    rec.lastOpenDbInfo.integrityResult = 0;
    rec.lastOpenDbInfo.callerInfo.pid = 1234;
    rec.lastOpenDbInfo.callerInfo.uid = 5678;
    rec.lastOpenDbInfo.time = "2025-01-01 00:00:00.000";

    std::string json = Serializable::Marshall(rec);
    EXPECT_FALSE(json.empty());

    RdbDbInfoRecord restored;
    EXPECT_TRUE(Serializable::Unmarshall(json, restored));
    EXPECT_EQ(restored.lastOpenDbInfo.config.name, "test.db");
    EXPECT_EQ(restored.lastOpenDbInfo.config.path, "/data/test/test.db");
    EXPECT_TRUE(restored.lastOpenDbInfo.config.isEncrypted);
    EXPECT_EQ(restored.lastOpenDbInfo.config.securityLevel, 3);
    EXPECT_EQ(restored.lastOpenDbInfo.config.journalMode, "WAL");
    EXPECT_EQ(restored.lastOpenDbInfo.config.sync, "FULL");
    EXPECT_EQ(restored.lastOpenDbInfo.config.walAutoCheckpoint, 1000);
    EXPECT_TRUE(restored.lastOpenDbInfo.created);
    EXPECT_FALSE(restored.lastOpenDbInfo.keyPresent);
    EXPECT_EQ(restored.lastOpenDbInfo.callerInfo.pid, 1234);
    EXPECT_EQ(restored.lastOpenDbInfo.callerInfo.uid, 5678);
    EXPECT_EQ(restored.lastOpenDbInfo.time, "2025-01-01 00:00:00.000");
}

/**
 * @tc.name: DiffDbFileInfo_001
 * @tc.desc: DiffDbFileInfo returns empty for identical snapshots.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, DiffDbFileInfo_001, TestSize.Level1)
{
    DbFileInfo a;
    a.db.node = 1;
    a.db.size = 100;
    a.wal.node = 2;
    a.shm.node = 3;

    DbFileInfo b = a;
    auto diff = DiffDbFileInfo("main", a, b);
    EXPECT_TRUE(diff.empty());
}

/**
 * @tc.name: DiffDbFileInfo_002
 * @tc.desc: DiffDbFileInfo returns changed field names for different snapshots.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, DiffDbFileInfo_002, TestSize.Level1)
{
    DbFileInfo a;
    a.db.node = 1;
    a.db.size = 100;
    a.wal.node = 2;

    DbFileInfo b;
    b.db.node = 1;
    b.db.size = 200;
    b.wal.node = 99;

    auto diff = DiffDbFileInfo("main", a, b);
    EXPECT_EQ(diff.size(), 2u);
    bool hasDbSize = false;
    bool hasWalNode = false;
    for (const auto &f : diff) {
        if (f == "main.db.size") {
            hasDbSize = true;
        }
        if (f == "main.wal.node") {
            hasWalNode = true;
        }
    }
    EXPECT_TRUE(hasDbSize);
    EXPECT_TRUE(hasWalNode);
}

/**
 * @tc.name: DiffDbFileInfo_003
 * @tc.desc: DiffDbFileInfo detects permission and time changes.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, DiffDbFileInfo_003, TestSize.Level1)
{
    DbFileInfo a;
    a.db.permission.mode = 0644;
    a.db.permission.acl = "user::rwx";
    a.db.time.ctime = 1000;

    DbFileInfo b;
    b.db.permission.mode = 0755;
    b.db.permission.acl = "user::rwx\ngroup::rwx";
    b.db.time.ctime = 2000;

    auto diff = DiffDbFileInfo("main", a, b);
    EXPECT_GE(diff.size(), 3u);
    bool hasMode = false;
    bool hasAcl = false;
    bool hasCtime = false;
    for (const auto &f : diff) {
        if (f == "main.db.mode") {
            hasMode = true;
        }
        if (f == "main.db.acl") {
            hasAcl = true;
        }
        if (f == "main.db.ctime") {
            hasCtime = true;
        }
    }
    EXPECT_TRUE(hasMode);
    EXPECT_TRUE(hasAcl);
    EXPECT_TRUE(hasCtime);
}

/**
 * @tc.name: RdbDbInfoManager_GetInstance_001
 * @tc.desc: GetInstance returns the same singleton reference.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoManager_GetInstance_001, TestSize.Level1)
{
    auto &a = RdbDbInfoManager::GetInstance();
    auto &b = RdbDbInfoManager::GetInstance();
    EXPECT_EQ(&a, &b);
}

/**
 * @tc.name: RdbDbInfoManager_CollectDbFileInfo_001
 * @tc.desc: CollectDbFileInfo returns empty info for non-existent path.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoManager_CollectDbFileInfo_001, TestSize.Level1)
{
    DbFileInfo info = RdbDbInfoManager::GetInstance().CollectDbFileInfo("/data/test/nonexistent_db_12345.db");
    EXPECT_TRUE(info.IsEmpty());
}

/**
 * @tc.name: RdbDbInfoManager_CollectDbFileInfo_002
 * @tc.desc: CollectDbFileInfo returns valid info for an existing file.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoManager_CollectDbFileInfo_002, TestSize.Level1)
{
    DbFileInfo info = RdbDbInfoManager::GetInstance().CollectDbFileInfo(TEST_DB_PATH);
    EXPECT_NE(info.db.node, 0);
    EXPECT_GT(info.db.size, 0);
    EXPECT_NE(info.db.permission.mode, 0u);
}

/**
 * @tc.name: RdbDbInfoManager_CollectCaller_001
 * @tc.desc: CollectCaller returns caller pid and uid.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoManager_CollectCaller_001, TestSize.Level1)
{
    CallerInfo info = RdbDbInfoManager::GetInstance().CollectCaller();
    EXPECT_GE(info.pid, 0);
    EXPECT_GE(info.uid, 0u);
}

/**
 * @tc.name: DbFileInfo_IsEmpty_001
 * @tc.desc: DbFileInfo IsEmpty returns true when all nodes are zero.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, DbFileInfo_IsEmpty_001, TestSize.Level1)
{
    DbFileInfo info;
    EXPECT_TRUE(info.IsEmpty());
    info.db.node = 1;
    EXPECT_FALSE(info.IsEmpty());
    info.db.node = 0;
    info.wal.node = 1;
    EXPECT_FALSE(info.IsEmpty());
}
