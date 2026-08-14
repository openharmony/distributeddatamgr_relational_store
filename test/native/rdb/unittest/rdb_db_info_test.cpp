/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <fstream>
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

std::string DfxPath()
{
    return std::string(TEST_DB_PATH) + DFX_SUFFIX;
}

bool ReadFile(const std::string &path, std::string &out)
{
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        return false;
    }
    std::streamsize size = ifs.tellg();
    if (size < 0) {
        return false;
    }
    ifs.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (size > 0 && !ifs.read(&out[0], size)) {
        return false;
    }
    return true;
}

void CreateTestFile(const std::string &path)
{
    int fd = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd >= 0) {
        write(fd, "test", 4);
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
 * @tc.name: RdbDbInfoRecord_MarshalUnmarshal_002
 * @tc.desc: Test DeleteRecord Marshal/Unmarshal round-trip.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoRecord_MarshalUnmarshal_002, TestSize.Level1)
{
    DeleteRecord rec;
    rec.startTime = 1000;
    rec.endTime = 2000;
    rec.dbInfo.db.node = 12345;
    rec.dbInfo.db.size = 67890;
    rec.dbInfo.db.permission.mode = 0644;
    rec.dbInfo.db.permission.acl = "user::rwx\ngroup::rwx";
    rec.callerInfo.pid = 100;
    rec.callerInfo.uid = 200;

    std::string json = Serializable::Marshall(rec);
    EXPECT_FALSE(json.empty());

    DeleteRecord restored;
    EXPECT_TRUE(Serializable::Unmarshall(json, restored));
    EXPECT_EQ(restored.startTime, 1000);
    EXPECT_EQ(restored.endTime, 2000);
    EXPECT_EQ(restored.dbInfo.db.node, 12345);
    EXPECT_EQ(restored.dbInfo.db.size, 67890);
    EXPECT_EQ(restored.dbInfo.db.permission.mode, 0644u);
    EXPECT_EQ(restored.dbInfo.db.permission.acl, "user::rwx\ngroup::rwx");
    EXPECT_EQ(restored.callerInfo.pid, 100);
    EXPECT_EQ(restored.callerInfo.uid, 200u);
}

/**
 * @tc.name: RdbDbInfoRecord_MarshalUnmarshal_003
 * @tc.desc: Test BackupRecord and RebuildRecord Marshal/Unmarshal round-trip.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoRecord_MarshalUnmarshal_003, TestSize.Level1)
{
    BackupRecord brec;
    brec.startTime = 100;
    brec.endTime = 200;
    brec.result = 0;
    brec.callerInfo.pid = 10;
    brec.beforeDbInfo.mainDbInfo.db.node = 1;
    brec.afterDbInfo.mainDbInfo.db.node = 2;

    std::string bjson = Serializable::Marshall(brec);
    EXPECT_FALSE(bjson.empty());
    BackupRecord brestored;
    EXPECT_TRUE(Serializable::Unmarshall(bjson, brestored));
    EXPECT_EQ(brestored.startTime, 100);
    EXPECT_EQ(brestored.endTime, 200);
    EXPECT_EQ(brestored.beforeDbInfo.mainDbInfo.db.node, 1);
    EXPECT_EQ(brestored.afterDbInfo.mainDbInfo.db.node, 2);

    RebuildRecord rrec;
    rrec.startTime = 300;
    rrec.endTime = 400;
    rrec.result = 1;
    rrec.oldDbInfo.db.node = 5;
    rrec.newDbInfo.db.node = 6;

    std::string rjson = Serializable::Marshall(rrec);
    EXPECT_FALSE(rjson.empty());
    RebuildRecord rrestored;
    EXPECT_TRUE(Serializable::Unmarshall(rjson, rrestored));
    EXPECT_EQ(rrestored.startTime, 300);
    EXPECT_EQ(rrestored.endTime, 400);
    EXPECT_EQ(rrestored.result, 1);
    EXPECT_EQ(rrestored.oldDbInfo.db.node, 5);
    EXPECT_EQ(rrestored.newDbInfo.db.node, 6);
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
 * @tc.name: NowMs_001
 * @tc.desc: NowMs returns a positive epoch millisecond value.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, NowMs_001, TestSize.Level1)
{
    int64_t t1 = NowMs();
    EXPECT_GT(t1, 0);
    int64_t t2 = NowMs();
    EXPECT_GE(t2, t1);
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
 * @tc.name: RdbDbInfoManager_CommitDelete_001
 * @tc.desc: CommitDelete writes delete record to dfx json.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoManager_CommitDelete_001, TestSize.Level1)
{
    DeleteRecord rec;
    rec.startTime = 1000;
    rec.endTime = 2000;
    rec.dbInfo = RdbDbInfoManager::GetInstance().CollectDbFileInfo(TEST_DB_PATH);
    rec.callerInfo.pid = 42;

    RdbDbInfoManager::GetInstance().CommitDelete(TEST_DB_PATH, rec);

    std::string content;
    EXPECT_TRUE(ReadFile(DfxPath(), content));
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("deleteStore") != std::string::npos);
    EXPECT_TRUE(content.find("\"pid\":42") != std::string::npos);
}

/**
 * @tc.name: RdbDbInfoManager_CommitBackup_001
 * @tc.desc: CommitBackup writes backup record to dfx json.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoManager_CommitBackup_001, TestSize.Level1)
{
    BackupRecord rec;
    rec.startTime = 100;
    rec.endTime = 200;
    rec.result = 0;
    rec.callerInfo.pid = 7;

    RdbDbInfoManager::GetInstance().CommitBackup(TEST_DB_PATH, rec);

    std::string content;
    EXPECT_TRUE(ReadFile(DfxPath(), content));
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("backup") != std::string::npos);
    EXPECT_TRUE(content.find("\"pid\":7") != std::string::npos);
}

/**
 * @tc.name: RdbDbInfoManager_CommitRestore_001
 * @tc.desc: CommitRestore writes restore record to dfx json.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoManager_CommitRestore_001, TestSize.Level1)
{
    BackupRecord rec;
    rec.startTime = 300;
    rec.endTime = 400;
    rec.result = 0;
    rec.callerInfo.pid = 9;

    RdbDbInfoManager::GetInstance().CommitRestore(TEST_DB_PATH, rec);

    std::string content;
    EXPECT_TRUE(ReadFile(DfxPath(), content));
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("restore") != std::string::npos);
    EXPECT_TRUE(content.find("\"pid\":9") != std::string::npos);
}

/**
 * @tc.name: RdbDbInfoManager_CommitRebuild_001
 * @tc.desc: CommitRebuild writes rebuild record to dfx json.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDbInfoManager_CommitRebuild_001, TestSize.Level1)
{
    RebuildRecord rec;
    rec.startTime = 500;
    rec.endTime = 600;
    rec.result = 1;
    rec.callerInfo.pid = 11;

    RdbDbInfoManager::GetInstance().CommitRebuild(TEST_DB_PATH, rec);

    std::string content;
    EXPECT_TRUE(ReadFile(DfxPath(), content));
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("rebuild") != std::string::npos);
    EXPECT_TRUE(content.find("\"pid\":11") != std::string::npos);
}

/**
 * @tc.name: RdbDfxTrace_Delete_001
 * @tc.desc: RdbDfxTrace RAII guard commits delete record on destruction.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDfxTrace_Delete_001, TestSize.Level1)
{
    {
        RdbDfxTrace trace(DfxOp::DELETE, TEST_DB_PATH);
    }
    std::string content;
    EXPECT_TRUE(ReadFile(DfxPath(), content));
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("deleteStore") != std::string::npos);
}

/**
 * @tc.name: RdbDfxTrace_Rebuild_001
 * @tc.desc: RdbDfxTrace RAII guard commits rebuild record on destruction.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDfxTrace_Rebuild_001, TestSize.Level1)
{
    {
        int result = 0;
        RdbDfxTrace trace(DfxOp::REBUILD, TEST_DB_PATH, "", &result);
    }
    std::string content;
    EXPECT_TRUE(ReadFile(DfxPath(), content));
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("rebuild") != std::string::npos);
}

/**
 * @tc.name: RdbDfxTrace_Backup_001
 * @tc.desc: RdbDfxTrace RAII guard commits backup record on destruction.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDfxTrace_Backup_001, TestSize.Level1)
{
    {
        int result = 0;
        RdbDfxTrace trace(DfxOp::BACKUP, TEST_DB_PATH, "", &result);
    }
    std::string content;
    EXPECT_TRUE(ReadFile(DfxPath(), content));
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("backup") != std::string::npos);
}

/**
 * @tc.name: RdbDfxTrace_Restore_001
 * @tc.desc: RdbDfxTrace RAII guard commits restore record on destruction.
 * @tc.type: FUNC
 */
HWTEST_F(RdbDbInfoTest, RdbDfxTrace_Restore_001, TestSize.Level1)
{
    {
        int result = 0;
        RdbDfxTrace trace(DfxOp::RESTORE, TEST_DB_PATH, "", &result);
    }
    std::string content;
    EXPECT_TRUE(ReadFile(DfxPath(), content));
    EXPECT_FALSE(content.empty());
    EXPECT_TRUE(content.find("restore") != std::string::npos);
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
