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

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>

#include "rdb_audit_logger.h"
#include "rdb_audit_logger_manager.h"
#include "rdb_audit_utils.h"
#include "rdb_db_info_manager.h"
#include "rdb_db_logger_manager.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "sqlite_utils.h"
#include "values_bucket.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace {
constexpr const char *TEST_BASE_DIR = "/data/test/rdb_audit";
constexpr size_t READ_BUF_SIZE = 4096;
constexpr int TEST_ERR_CODE = 14;
constexpr int TEST_OS_ERRNO = 13;
constexpr int TEST_IO_ERR_CODE = 10;
constexpr int TEST_IO_OS_ERRNO = 5;
constexpr int64_t TEST_DELETE_ROWS = 5;
constexpr int64_t TEST_INSERT_ROWS = 100;
constexpr int POLL_INTERVAL_MS = 1000;
const std::string::size_type NPOS = std::string::npos;

// Async-drain / wait timeouts (ms).
constexpr int DRAIN_TIMEOUT_MS = 1000;
constexpr int DRAIN_POLL_MS = 200;
constexpr int WAIT_TIMEOUT_MS = 3000;

// Return codes used in On* calls.
constexpr int RC_OK = 0;
constexpr int TEST_CORRUPT_RC = 11; // SQLITE_CORRUPT

// InodeChange test snapshots.
constexpr int64_t INODE_BEFORE = 100;
constexpr int64_t INODE_AFTER = 200;
constexpr int64_t SIZE_BEFORE = 1024;
constexpr int64_t SIZE_AFTER = 2048;

// Expected events.log line counts.
// EVENT_LINES_OPEN: real DB open writes PRG (integrity check) + OPEN.
// EVENT_LINES_OPEN_PLUS_OP: open (2 lines) + one SQL/PRAGMA op.
// EVENT_LINES_TWO_OPS: two direct On* calls (e.g. DROP + TRUNCATE).
constexpr size_t EVENT_LINES_OPEN = 2;
constexpr size_t EVENT_LINES_OPEN_PLUS_OP = 3;
constexpr size_t EVENT_LINES_TWO_OPS = 2;

bool MakeDirRecursive(const std::string &path, mode_t mode)
{
    if (path.empty()) {
        return false;
    }
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        return true;
    }
    size_t pos = 1;
    while ((pos = path.find('/', pos)) != std::string::npos) {
        std::string sub = path.substr(0, pos);
        if (stat(sub.c_str(), &st) != 0) {
            mkdir(sub.c_str(), mode);
        }
        pos++;
    }
    if (stat(path.c_str(), &st) != 0) {
        return mkdir(path.c_str(), mode) == 0 || errno == EEXIST;
    }
    return true;
}

std::string ReadFileContent(const std::string &path)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return "";
    }
    std::string content;
    char buf[READ_BUF_SIZE];
    ssize_t n = 0;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        content.append(buf, static_cast<size_t>(n));
    }
    close(fd);
    return content;
}

size_t CountLines(const std::string &content)
{
    if (content.empty()) {
        return 0;
    }
    size_t count = 0;
    for (char c : content) {
        if (c == '\n') {
            count++;
        }
    }
    return count;
}

bool FileExists(const std::string &path)
{
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

std::string AuditDir()
{
    return std::string(TEST_BASE_DIR) + "/.audit/";
}

// dbPath must contain an "/el" segment so SqliteUtils::GetArea returns non-empty
// (e.g. "el2"); otherwise RdbDbLoggerManager::BuildAuditPath returns "" and
// audit.json is never written.
std::string DbPath()
{
    return std::string(TEST_BASE_DIR) + "/el2/database/test.db";
}

std::string DbDir()
{
    std::string path = DbPath();
    size_t pos = path.rfind('/');
    return (pos == std::string::npos) ? TEST_BASE_DIR : path.substr(0, pos);
}

std::string EventsLogPath()
{
    return AuditDir() + "events.log";
}

// Mirrors RdbDbLoggerManager::BuildAuditPath naming: {el}{dbName}_audit.json.
// Reuse SqliteUtils parsers (R10) so the path tracks DbPath() changes.
std::string AuditJsonPath()
{
    return AuditDir() + SqliteUtils::GetArea(DbPath()) + SqliteUtils::GetDbName(DbPath()) + "_audit.json";
}

// Initialize both singleton managers via the public idempotent Init() (no private
// access, no friend). First call opens events.log fd + sets auditDir; later
// calls are no-ops. Truncate events.log in place so the singleton's O_APPEND fd
// stays valid (truncate does not change the inode) while clearing prior output.
// DrainAsyncAudit waits for prior cases' async tasks to land (events.log line
// Wait for prior cases' async audit tasks to drain on the executor before
// truncating events.log. A fixed sleep is used instead of a "line count
// stable" poll because queued (not-yet-running) tasks don't change the line
// count, which would falsely break early and let them append old content back
// after the truncate (cross-case line accumulation).
void DrainAsyncAudit()
{
    std::this_thread::sleep_for(std::chrono::milliseconds(DRAIN_TIMEOUT_MS));
}

void SetupAudit()
{
    MakeDirRecursive(AuditDir(), AUDIT_DIR_MODE);
    RdbAuditLoggerManager::GetInstance().Init(AuditDir(), true);
    RdbDbLoggerManager::GetInstance().Init(AuditDir(), true);
    DrainAsyncAudit();
    truncate(EventsLogPath().c_str(), 0);
    unlink(AuditJsonPath().c_str());
}

size_t WaitEventLines(size_t expected, int timeoutMs = WAIT_TIMEOUT_MS)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (CountLines(ReadFileContent(EventsLogPath())) >= expected) {
            return CountLines(ReadFileContent(EventsLogPath()));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(POLL_INTERVAL_MS));
    }
    return CountLines(ReadFileContent(EventsLogPath()));
}

bool WaitFileExists(const std::string &path, int timeoutMs = WAIT_TIMEOUT_MS)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (FileExists(path)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(POLL_INTERVAL_MS));
    }
    return FileExists(path);
}

// Poll until audit.json contains `key` (async Write*Sync lands), or timeout.
bool WaitJsonContains(const std::string &key, int timeoutMs = WAIT_TIMEOUT_MS)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (ReadFileContent(AuditJsonPath()).find(key) != NPOS) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(POLL_INTERVAL_MS));
    }
    return ReadFileContent(AuditJsonPath()).find(key) != NPOS;
}

RdbStoreConfig MakeAuditConfig()
{
    RdbStoreConfig config(DbPath());
    config.SetBundleName("audit_test_app");
    config.SetAuditEnabled(true);
    return config;
}
} // namespace

class AuditOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return store.ExecuteSql("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)");
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

class RdbAuditTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        RdbHelper::DeleteRdbStore(DbPath());
    }
    static void TearDownTestCase(void)
    {
        RdbHelper::DeleteRdbStore(DbPath());
    }

    void SetUp() override
    {
        RdbHelper::DeleteRdbStore(DbPath());
        MakeDirRecursive(TEST_BASE_DIR, AUDIT_DIR_MODE);
        MakeDirRecursive(DbDir(), AUDIT_DIR_MODE);
        SetupAudit();
    }

    void TearDown() override
    {
        RdbHelper::DeleteRdbStore(DbPath());
    }
};

// ===== Part 1: RdbAuditUtils pure logic (no I/O, no singleton) =====

/**
 * @tc.name: RdbAudit_ParseDropTruncate_001
 * @tc.desc: ParseDropTruncateOp classifies DROP/TRUNCATE TABLE; ParseDropTruncateTable extracts the name
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, ParseDropTruncate_001, TestSize.Level0)
{
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("DROP TABLE foo"), "DROP");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("DROP TABLE IF EXISTS foo"), "DROP");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("TRUNCATE TABLE bar"), "TRUNCATE");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("DROP INDEX idx"), "");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("DROP VIEW v1"), "");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateTable("DROP TABLE foo"), "foo");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateTable("DROP TABLE IF EXISTS foo"), "foo");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateTable("TRUNCATE TABLE bar"), "bar");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateTable("DROP TABLE"), "");
}

// ===== Part 2: AuditLogger On* direct API -> events.log / audit.json =====

/**
 * @tc.name: RdbAudit_OnOpenOk_003
 * @tc.desc: OnOpenOk writes OPEN event + lastOpen block
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, OnOpenOk_003, TestSize.Level0)
{
    RdbAuditLoggerImpl logger;
    logger.OnOpenOk(DbPath(), false);
    EXPECT_EQ(WaitEventLines(1), 1);
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("OPEN:"), NPOS);
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
    EXPECT_NE(ReadFileContent(AuditJsonPath()).find("lastOpen"), NPOS);
}

/**
 * @tc.name: RdbAudit_OnOpenFail_004
 * @tc.desc: OnOpenFail writes OFAIL event with error context
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, OnOpenFail_004, TestSize.Level0)
{
    RdbAuditLoggerImpl logger;
    logger.OnOpenFail(DbPath(), TEST_ERR_CODE, TEST_OS_ERRNO);
    EXPECT_EQ(WaitEventLines(1), 1);
    auto content = ReadFileContent(EventsLogPath());
    EXPECT_NE(content.find("OFAIL:"), NPOS);
    EXPECT_NE(content.find("rc=14"), NPOS);
    EXPECT_NE(content.find("os_errno=13"), NPOS);
}

/**
 * @tc.name: RdbAudit_OnSqlDelete_005
 * @tc.desc: DELETE with rows>0 writes SQL event immediately (no throttle)
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, OnSqlDelete_005, TestSize.Level0)
{
    RdbAuditLoggerImpl logger;
    logger.OnSqlAudit(DbPath(), "DELETE", "users", TEST_DELETE_ROWS);
    EXPECT_EQ(WaitEventLines(1), 1);
    auto content = ReadFileContent(EventsLogPath());
    EXPECT_NE(content.find("SQL:"), NPOS);
    EXPECT_NE(content.find("op=DELETE"), NPOS);
    EXPECT_NE(content.find("rows=5"), NPOS);
}

/**
 * @tc.name: RdbAudit_OnPragma_006
 * @tc.desc: OnPragma writes PRG event with sql + rc + result
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, OnPragma_006, TestSize.Level0)
{
    RdbAuditLoggerImpl logger;
    logger.OnPragma(DbPath(), "PRAGMA integrity_check", RC_OK, "ok");
    EXPECT_EQ(WaitEventLines(1), 1);
    auto content = ReadFileContent(EventsLogPath());
    EXPECT_NE(content.find("PRG:"), NPOS);
    EXPECT_NE(content.find("rc=0"), NPOS);
    EXPECT_NE(content.find("result=ok"), NPOS);
}

/**
 * @tc.name: RdbAudit_OnCorrupt_007
 * @tc.desc: OnCorrupt writes corrupt block to audit.json
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, OnCorrupt_007, TestSize.Level0)
{
    RdbAuditLoggerImpl logger;
    logger.OnCorrupt(DbPath(), TEST_CORRUPT_RC, RC_OK, "row missing from index");
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
    auto json = ReadFileContent(AuditJsonPath());
    EXPECT_NE(json.find("corrupt"), NPOS);
    EXPECT_NE(json.find("row missing from index"), NPOS);
}

/**
 * @tc.name: RdbAudit_OnIoErrorAndDbDelete_008
 * @tc.desc: OnIoError writes ioError block and OnDbDelete writes dbDelete block to audit.json (async)
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, OnIoErrorAndDbDelete_008, TestSize.Level0)
{
    RdbAuditLoggerImpl logger;
    logger.OnIoError("execute", DbPath(), TEST_IO_ERR_CODE, TEST_IO_OS_ERRNO);
    EXPECT_TRUE(WaitJsonContains("ioError"));
    logger.OnDbDelete(DbPath(), "delete_store");
    EXPECT_TRUE(WaitJsonContains("dbDelete"));
}

/**
 * @tc.name: RdbAudit_AuditDisabled_010
 * @tc.desc: auditEnabled=false: base RdbAuditLogger On* are no-ops, nothing written
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, AuditDisabled_010, TestSize.Level0)
{
    size_t linesBefore = CountLines(ReadFileContent(EventsLogPath()));
    std::string jsonBefore = ReadFileContent(AuditJsonPath());
    RdbAuditLogger logger; // no-op base instance (audit disabled)
    logger.OnOpenOk(DbPath(), false);
    logger.OnOpenFail(DbPath(), TEST_ERR_CODE, TEST_OS_ERRNO);
    logger.OnSqlAudit(DbPath(), "DELETE", "t", 1);
    logger.OnPragma(DbPath(), "PRAGMA integrity_check", RC_OK, "ok");
    logger.OnCorrupt(DbPath(), TEST_CORRUPT_RC, RC_OK, "detail");
    logger.OnIoError("execute", DbPath(), TEST_IO_ERR_CODE, TEST_IO_OS_ERRNO);
    logger.OnDbDelete(DbPath(), "delete_store");
    EXPECT_EQ(CountLines(ReadFileContent(EventsLogPath())), linesBefore);
    EXPECT_EQ(ReadFileContent(AuditJsonPath()), jsonBefore);
}

// ===== Part 3: real DB integration (RdbHelper::GetRdbStore triggers audit) =====

/**
 * @tc.name: RdbAudit_RealDbOpen_011
 * @tc.desc: Real DB open writes OPEN event + lastOpen block
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbOpen_011, TestSize.Level0)
{
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(WaitEventLines(EVENT_LINES_OPEN), EVENT_LINES_OPEN);
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
    EXPECT_NE(ReadFileContent(AuditJsonPath()).find("lastOpen"), NPOS);
}

/**
 * @tc.name: RdbAudit_RealDbDelete_012
 * @tc.desc: Real DB INSERT+DELETE writes SQL event
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbDelete_012, TestSize.Level0)
{
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
    ASSERT_NE(store, nullptr);
    ValuesBucket b;
    b.Put("id", 1);
    b.Put("name", "a");
    store->Insert("users", b);
    RdbPredicates p("users");
    p.EqualTo("id", 1);
    store->Delete(p);
    EXPECT_EQ(WaitEventLines(EVENT_LINES_OPEN_PLUS_OP), EVENT_LINES_OPEN_PLUS_OP);
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("op=DELETE"), NPOS);
}

/**
 * @tc.name: RdbAudit_RealDbDropTable_013
 * @tc.desc: Real DB DROP TABLE writes SQL event with op=DROP
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbDropTable_013, TestSize.Level0)
{
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
    ASSERT_NE(store, nullptr);
    store->ExecuteSql("DROP TABLE IF EXISTS users");
    EXPECT_EQ(WaitEventLines(EVENT_LINES_OPEN_PLUS_OP), EVENT_LINES_OPEN_PLUS_OP);
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("op=DROP"), NPOS);
}

/**
 * @tc.name: RdbAudit_RealDbPragma_014
 * @tc.desc: Real DB PRAGMA integrity_check writes PRG event (open-time result=ok)
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbPragma_014, TestSize.Level0)
{
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
    ASSERT_NE(store, nullptr);
    store->ExecuteSql("PRAGMA integrity_check");
    EXPECT_EQ(WaitEventLines(EVENT_LINES_OPEN_PLUS_OP), EVENT_LINES_OPEN_PLUS_OP);
    auto content = ReadFileContent(EventsLogPath());
    EXPECT_NE(content.find("PRG:"), NPOS);
    EXPECT_NE(content.find("result=ok"), NPOS);
}

/**
 * @tc.name: RdbAudit_RealDbDeleteStore_015
 * @tc.desc: DeleteRdbStore writes dbDelete block to audit.json
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbDeleteStore_015, TestSize.Level0)
{
    {
        AuditOpenCallback cb;
        int err = E_OK;
        auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
        ASSERT_NE(store, nullptr);
    }
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
    RdbHelper::DeleteRdbStore(MakeAuditConfig());
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
    EXPECT_NE(ReadFileContent(AuditJsonPath()).find("dbDelete"), NPOS);
}

/**
 * @tc.name: RdbAudit_RealDbAuditDisabled_016
 * @tc.desc: audit disabled: real DB open/insert/pragma produce no audit output
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbAuditDisabled_016, TestSize.Level0)
{
    RdbStoreConfig config(DbPath());
    config.SetBundleName("audit_test_app");
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, cb, err);
    ASSERT_NE(store, nullptr);
    size_t linesBefore = CountLines(ReadFileContent(EventsLogPath()));
    std::string jsonBefore = ReadFileContent(AuditJsonPath());
    ValuesBucket b;
    b.Put("id", 1);
    b.Put("name", "a");
    store->Insert("users", b);
    store->ExecuteSql("PRAGMA integrity_check");
    EXPECT_EQ(CountLines(ReadFileContent(EventsLogPath())), linesBefore);
    EXPECT_EQ(ReadFileContent(AuditJsonPath()), jsonBefore);
}

// ===== Part 4: singletons, DbInfoManager collectors, inodeChange block =====

/**
 * @tc.name: RdbAudit_OnSqlDropTruncate_017
 * @tc.desc: DROP/TRUNCATE are always logged regardless of rows
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, OnSqlDropTruncate_017, TestSize.Level0)
{
    RdbAuditLoggerImpl logger;
    logger.OnSqlAudit(DbPath(), "DROP", "temp", RC_OK);
    logger.OnSqlAudit(DbPath(), "TRUNCATE", "temp2", RC_OK);
    EXPECT_EQ(WaitEventLines(EVENT_LINES_TWO_OPS), EVENT_LINES_TWO_OPS);
    auto content = ReadFileContent(EventsLogPath());
    EXPECT_NE(content.find("op=DROP"), NPOS);
    EXPECT_NE(content.find("op=TRUNCATE"), NPOS);
}

/**
 * @tc.name: RdbAudit_InodeChange_018
 * @tc.desc: RecordOpenSync writes inodeChange block when main file changes
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, InodeChange_018, TestSize.Level0)
{
    LastOpenDbInfo info1;
    info1.main.db.node = INODE_BEFORE;
    info1.main.db.size = SIZE_BEFORE;
    info1.time = "2026-09-23 10:00:00.000";
    info1.callerInfo = RdbDbInfoManager::GetInstance().CollectCaller();
    RdbDbLoggerManager::GetInstance().RecordOpenSync(DbPath(), info1);
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
    LastOpenDbInfo info2;
    info2.main.db.node = INODE_AFTER;
    info2.main.db.size = SIZE_AFTER;
    info2.time = "2026-09-23 11:00:00.000";
    info2.callerInfo = RdbDbInfoManager::GetInstance().CollectCaller();
    RdbDbLoggerManager::GetInstance().RecordOpenSync(DbPath(), info2);
    auto json = ReadFileContent(AuditJsonPath());
    EXPECT_NE(json.find("inodeChange"), NPOS);
    EXPECT_NE(json.find("before"), NPOS);
    EXPECT_NE(json.find("after"), NPOS);
    EXPECT_NE(json.find("changedFields"), NPOS);
}

/**
 * @tc.name: RdbAudit_DbInfoManager_019
 * @tc.desc: BuildLastOpen/CollectDbFileInfo/CollectCaller collect for a path
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, DbInfoManager_019, TestSize.Level0)
{
    // DbPath does not exist yet -> collected file info is empty but valid.
    auto lastOpen = RdbDbInfoManager::GetInstance().BuildLastOpen(DbPath(), true);
    EXPECT_TRUE(lastOpen.main.IsEmpty());
    auto files = RdbDbInfoManager::GetInstance().CollectDbFileInfo(DbPath());
    EXPECT_TRUE(files.IsEmpty());
    auto caller = RdbDbInfoManager::GetInstance().CollectCaller();
    EXPECT_GE(caller.pid, 0);
}

/**
 * @tc.name: RdbAudit_ManagerState_020
 * @tc.desc: Manager IsInitialized + AppendEventSync sync write + INSERT throttle
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, ManagerState_020, TestSize.Level0)
{
    EXPECT_TRUE(RdbAuditLoggerManager::GetInstance().IsInitialized());
    EXPECT_TRUE(RdbDbLoggerManager::GetInstance().IsInitialized());
    // AppendEventSync: synchronous write to events.log
    RdbAuditLoggerManager::GetInstance().AppendEventSync("{\"evt\":\"TEST\",\"v\":1}");
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("\"evt\":\"TEST\""), NPOS);
    // OnSqlInsertThrottle: INSERT accumulated within 60s window, no events.log write (still 1 line)
    RdbAuditLoggerImpl logger;
    logger.OnSqlAudit(DbPath(), "INSERT", "logs", TEST_INSERT_ROWS);
    EXPECT_EQ(CountLines(ReadFileContent(EventsLogPath())), 1);
}

// ===== Part 5: coverage supplements (Create / BatchInsert / Update / Execute / ExecuteExt) =====

/**
 * @tc.name: RdbAudit_Create_021
 * @tc.desc: Create(true) returns Impl (writes events); Create(false) returns no-op base
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, Create_021, TestSize.Level0)
{
    auto enabled = RdbAuditLogger::Create(true);
    enabled->OnOpenOk(DbPath(), false);
    EXPECT_EQ(WaitEventLines(1), 1);
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("OPEN:"), NPOS);
    size_t before = CountLines(ReadFileContent(EventsLogPath()));
    auto disabled = RdbAuditLogger::Create(false);
    disabled->OnOpenOk(DbPath(), false);
    disabled->OnSqlAudit(DbPath(), "DELETE", "t", 1);
    disabled->OnPragma(DbPath(), "PRAGMA integrity_check", RC_OK, "ok");
    EXPECT_EQ(CountLines(ReadFileContent(EventsLogPath())), before);
}

/**
 * @tc.name: RdbAudit_RealDbBatchInsert_022
 * @tc.desc: Real DB BatchInsert writes SQL event with op=BatchInsert
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbBatchInsert_022, TestSize.Level0)
{
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
    ASSERT_NE(store, nullptr);
    std::vector<ValuesBucket> vbs;
    ValuesBucket b;
    b.Put("id", 1);
    b.Put("name", "a");
    vbs.push_back(std::move(b));
    store->BatchInsert("users", vbs);
    EXPECT_EQ(WaitEventLines(EVENT_LINES_OPEN_PLUS_OP), EVENT_LINES_OPEN_PLUS_OP);
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("op=BatchInsert"), NPOS);
}

/**
 * @tc.name: RdbAudit_RealDbUpdate_023
 * @tc.desc: Real DB Update writes SQL event with op=UPDATE
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbUpdate_023, TestSize.Level0)
{
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
    ASSERT_NE(store, nullptr);
    ValuesBucket b;
    b.Put("id", 1);
    b.Put("name", "a");
    store->Insert("users", b);
    ValuesBucket upd;
    upd.Put("name", "b");
    RdbPredicates p("users");
    p.EqualTo("id", 1);
    store->Update(upd, p, ReturningConfig{});
    EXPECT_EQ(WaitEventLines(EVENT_LINES_OPEN_PLUS_OP), EVENT_LINES_OPEN_PLUS_OP);
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("op=UPDATE"), NPOS);
}

/**
 * @tc.name: RdbAudit_RealDbExecutePragma_024
 * @tc.desc: Real DB Execute(PRAGMA) writes PRG event (via Execute path)
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbExecutePragma_024, TestSize.Level0)
{
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
    ASSERT_NE(store, nullptr);
    auto [code, value] = store->Execute("PRAGMA integrity_check");
    EXPECT_EQ(code, E_OK);
    EXPECT_EQ(WaitEventLines(EVENT_LINES_OPEN_PLUS_OP), EVENT_LINES_OPEN_PLUS_OP);
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("PRG:"), NPOS);
}

/**
 * @tc.name: RdbAudit_RealDbExecuteDropTable_025
 * @tc.desc: Real DB Execute(DROP TABLE) writes SQL event with op=DROP (HandleDifferentSqlTypes)
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbExecuteDropTable_025, TestSize.Level0)
{
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
    ASSERT_NE(store, nullptr);
    auto [code, value] = store->Execute("DROP TABLE IF EXISTS users");
    EXPECT_EQ(WaitEventLines(EVENT_LINES_OPEN_PLUS_OP), EVENT_LINES_OPEN_PLUS_OP);
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("op=DROP"), NPOS);
}

/**
 * @tc.name: RdbAudit_RealDbExecuteExtDropTable_026
 * @tc.desc: Real DB ExecuteExt(DROP TABLE) writes SQL event with op=DROP (ExecuteExt path)
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditTest, RealDbExecuteExtDropTable_026, TestSize.Level0)
{
    AuditOpenCallback cb;
    int err = E_OK;
    auto store = RdbHelper::GetRdbStore(MakeAuditConfig(), 1, cb, err);
    ASSERT_NE(store, nullptr);
    auto [code, result] = store->ExecuteExt("DROP TABLE IF EXISTS users");
    EXPECT_EQ(WaitEventLines(EVENT_LINES_OPEN_PLUS_OP), EVENT_LINES_OPEN_PLUS_OP);
    EXPECT_NE(ReadFileContent(EventsLogPath()).find("op=DROP"), NPOS);
}
