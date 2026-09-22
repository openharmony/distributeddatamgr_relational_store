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

#include <cstdint>
#include <cstring>
#include <chrono>
#include <dirent.h>
#include <string>
#include <thread>

#include "rdb_audit_event.h"
#include "rdb_audit_logger.h"
#include "rdb_audit_logger_manager.h"
#include "rdb_db_logger_manager.h"
#include "rdb_audit_utils.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_config.h"
#include "rdb_predicates.h"
#include "sqlite_utils.h"
#include "values_bucket.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace {
constexpr const char *TEST_BASE_DIR = "/data/test/rdb_audit_scenario";
constexpr size_t READ_BUF_SIZE = 4096;
constexpr int TEST_ERR_CODE = 14;
constexpr int TEST_OS_ERRNO = 13;
constexpr int POLL_INTERVAL_MS = 10;

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

std::string AuditJsonPath()
{
    // Mirrors RdbDbLoggerManager::BuildAuditPath naming: {el}{dbName}_audit.json.
    // Reuse SqliteUtils parsers (R10) instead of hardcoding so the path tracks
    // DbPath() changes automatically.
    return AuditDir() + SqliteUtils::GetArea(DbPath()) + SqliteUtils::GetDbName(DbPath()) + "_audit.json";
}

std::string DbPath()
{
    // Path must contain an "/el" segment so SqliteUtils::GetArea returns a
    // non-empty area (e.g. "el2"); otherwise RdbDbLoggerManager::BuildAuditPath
    // returns "" and audit.json is never written.
    return std::string(TEST_BASE_DIR) + "/el2/database/test.db";
}

std::string DbDir()
{
    std::string path = DbPath();
    size_t pos = path.rfind('/');
    return (pos == std::string::npos) ? TEST_BASE_DIR : path.substr(0, pos);
}

size_t WaitEventLines(size_t expected, int timeoutMs = 3000)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        size_t lines = CountLines(ReadFileContent(AuditDir() + "events.log"));
        if (lines >= expected) {
            return lines;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(POLL_INTERVAL_MS));
    }
    return CountLines(ReadFileContent(AuditDir() + "events.log"));
}

bool WaitFileExists(const std::string &path, int timeoutMs = 3000)
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

RdbStoreConfig MakeAuditConfig()
{
    RdbStoreConfig config(DbPath());
    config.SetBundleName("scenario_test_app");
    config.SetAuditEnabled(true);
    return config;
}
} // namespace

class ScenarioOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &store) override
    {
        return store.ExecuteSql(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)");
    }
    int OnUpgrade(RdbStore &store, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

class RdbAuditScenarioTest : public testing::Test {
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
        MakeDirRecursive(AuditDir(), AUDIT_DIR_MODE);
        // Idempotent Init via the public interface: first call opens events.log fd
        // and sets auditDir_; later calls are no-ops. The singleton stays
        // initialized across tests, pointing at AuditDir(). No private access.
        RdbAuditLoggerManager::GetInstance().Init(AuditDir(), true);
        RdbDbLoggerManager::GetInstance().Init(AuditDir(), true);
        // Clean per-test artifacts without invalidating the singleton's events.log
        // fd: truncating the path keeps the fd valid (O_APPEND writes resume at 0).
        truncate((AuditDir() + "events.log").c_str(), 0);
        unlink(AuditJsonPath().c_str());
    }

    void TearDown() override
    {
        RdbHelper::DeleteRdbStore(DbPath());
    }
};

// ============================================================================
// Real DB: open / insert / delete / drop / integrity
// ============================================================================

/**
 * @tc.name: RdbAuditScenario_OpenAndInsert_001
 * @tc.desc: Real DB: open writes OPEN_OK + lastOpen; INSERT is throttled (no event)
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, OpenAndInsert_001, TestSize.Level0)
{
    RdbStoreConfig config = MakeAuditConfig();
    ScenarioOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(errCode, E_OK);

    ValuesBucket bucket;
    bucket.Put("id", 1).Put("name", "Alice");
    auto [insertErr, rowId] = store->Insert("users", bucket);
    EXPECT_EQ(insertErr, E_OK);
    EXPECT_GT(rowId, 0);

    EXPECT_EQ(WaitEventLines(1), static_cast<size_t>(1));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"evt\":\"OPEN\""), std::string::npos);
    EXPECT_EQ(content.find("\"evt\":\"SQL\""), std::string::npos);
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
    std::string json = ReadFileContent(AuditJsonPath());
    EXPECT_NE(json.find("lastOpen"), std::string::npos);
}

/**
 * @tc.name: RdbAuditScenario_Delete_002
 * @tc.desc: Real DB: DELETE with rows > 0 writes SQL_AUDIT immediately (no throttle)
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, Delete_002, TestSize.Level0)
{
    RdbStoreConfig config = MakeAuditConfig();
    ScenarioOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    ValuesBucket bucket;
    bucket.Put("id", 1).Put("name", "Bob");
    store->Insert("users", bucket);

    RdbPredicates predicates("users");
    predicates.EqualTo("id", 1);
    auto [delErr, count] = store->Delete(predicates);
    EXPECT_EQ(delErr, E_OK);
    EXPECT_GT(count, 0);

    EXPECT_EQ(WaitEventLines(2), static_cast<size_t>(2));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"evt\":\"OPEN\""), std::string::npos);
    EXPECT_NE(content.find("\"op\":\"DELETE\""), std::string::npos);
}

/**
 * @tc.name: RdbAuditScenario_DropTable_003
 * @tc.desc: Real DB: DROP TABLE is always logged
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, DropTable_003, TestSize.Level0)
{
    RdbStoreConfig config = MakeAuditConfig();
    ScenarioOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    store->ExecuteSql("DROP TABLE IF EXISTS users");

    EXPECT_EQ(WaitEventLines(2), static_cast<size_t>(2));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"evt\":\"OPEN\""), std::string::npos);
    EXPECT_NE(content.find("\"op\":\"DROP\""), std::string::npos);
}

/**
 * @tc.name: RdbAuditScenario_PragmaIntegrity_004
 * @tc.desc: Real DB: PRAGMA integrity_check writes INTEGRITY event
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, PragmaIntegrity_004, TestSize.Level0)
{
    RdbStoreConfig config = MakeAuditConfig();
    ScenarioOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    store->ExecuteSql("PRAGMA integrity_check");

    EXPECT_EQ(WaitEventLines(2), static_cast<size_t>(2));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"evt\":\"OPEN\""), std::string::npos);
    EXPECT_NE(content.find("\"evt\":\"IGR\""), std::string::npos);
    EXPECT_NE(content.find("\"trigger\":\"active\""), std::string::npos);
    EXPECT_NE(content.find("\"mode\":\"full\""), std::string::npos);
}

/**
 * @tc.name: RdbAuditScenario_PragmaQuickCheck_005
 * @tc.desc: Real DB: PRAGMA quick_check writes INTEGRITY event with quick mode
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, PragmaQuickCheck_005, TestSize.Level0)
{
    RdbStoreConfig config = MakeAuditConfig();
    ScenarioOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    store->ExecuteSql("PRAGMA quick_check");

    EXPECT_EQ(WaitEventLines(2), static_cast<size_t>(2));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"mode\":\"quick\""), std::string::npos);
}

// ============================================================================
// Real DB: full lifecycle
// ============================================================================

/**
 * @tc.name: RdbAuditScenario_FullLifecycle_006
 * @tc.desc: Real DB: open → insert → delete → drop → integrity, verify all events
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, FullLifecycle_006, TestSize.Level0)
{
    RdbStoreConfig config = MakeAuditConfig();
    ScenarioOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    ValuesBucket bucket;
    bucket.Put("id", 1).Put("name", "Charlie");
    store->Insert("users", bucket);

    RdbPredicates predicates("users");
    predicates.EqualTo("id", 1);
    store->Delete(predicates);

    store->ExecuteSql("DROP TABLE IF EXISTS users");
    store->ExecuteSql("PRAGMA integrity_check");

    // Expected events: OPEN_OK + SQL_AUDIT(DELETE) + SQL_AUDIT(DROP) + INTEGRITY = 4
    // INSERT is throttled, not in events.log
    EXPECT_EQ(WaitEventLines(4), static_cast<size_t>(4));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"evt\":\"OPEN\""), std::string::npos);
    EXPECT_NE(content.find("\"op\":\"DELETE\""), std::string::npos);
    EXPECT_NE(content.find("\"op\":\"DROP\""), std::string::npos);
    EXPECT_NE(content.find("\"evt\":\"IGR\""), std::string::npos);
    EXPECT_EQ(content.find("\"op\":\"INSERT\""), std::string::npos);
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
}

// ============================================================================
// Real DB: delete store
// ============================================================================

/**
 * @tc.name: RdbAuditScenario_DeleteStore_007
 * @tc.desc: Real DB: DeleteRdbStore writes dbDelete block to audit.json, not events.log
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, DeleteStore_007, TestSize.Level0)
{
    {
        RdbStoreConfig config = MakeAuditConfig();
        ScenarioOpenCallback helper;
        int errCode = E_OK;
        auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
        ASSERT_NE(store, nullptr);
    }
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));

    RdbStoreConfig config = MakeAuditConfig();
    RdbHelper::DeleteRdbStore(config);

    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
    std::string json = ReadFileContent(AuditJsonPath());
    EXPECT_NE(json.find("dbDelete"), std::string::npos);
    EXPECT_NE(json.find("delete_store"), std::string::npos);
}

// ============================================================================
// Real DB: audit disabled
// ============================================================================

/**
 * @tc.name: RdbAuditScenario_AuditDisabled_008
 * @tc.desc: Real DB: audit disabled produces no events.log and no audit.json
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, AuditDisabled_008, TestSize.Level0)
{
    // SetUp already initialized the singleton and created events.log. With
    // SetAuditEnabled not called (defaults false), every On* entry returns
    // before EnsureInit, so no new events are written and audit.json is unchanged.
    size_t linesBefore = CountLines(ReadFileContent(AuditDir() + "events.log"));
    std::string jsonBefore = ReadFileContent(AuditJsonPath());
    RdbStoreConfig config(DbPath());
    config.SetBundleName("scenario_test_app");
    // SetAuditEnabled not called — defaults to false
    ScenarioOpenCallback helper;
    int errCode = E_OK;
    auto store = RdbHelper::GetRdbStore(config, 1, helper, errCode);
    ASSERT_NE(store, nullptr);

    ValuesBucket bucket;
    bucket.Put("id", 1).Put("name", "Dave");
    store->Insert("users", bucket);
    store->ExecuteSql("PRAGMA integrity_check");

    EXPECT_EQ(CountLines(ReadFileContent(AuditDir() + "events.log")), linesBefore);
    EXPECT_EQ(ReadFileContent(AuditJsonPath()), jsonBefore);
}

// ============================================================================
// Direct API: open fail / corrupt (no real DB needed)
// ============================================================================

/**
 * @tc.name: RdbAuditScenario_OpenFail_009
 * @tc.desc: Open fail writes OPEN_FAIL to events.log
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, OpenFail_009, TestSize.Level0)
{
    RdbAuditLogger logger;
    logger.OnOpenFail(DbPath(), TEST_ERR_CODE, TEST_OS_ERRNO, true);
    EXPECT_EQ(WaitEventLines(1), static_cast<size_t>(1));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"evt\":\"OFAIL\""), std::string::npos);
    EXPECT_NE(content.find("\"rc\":14"), std::string::npos);
}

/**
 * @tc.name: RdbAuditScenario_Corrupt_010
 * @tc.desc: OnCorrupt writes corrupt block to audit.json
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, Corrupt_010, TestSize.Level0)
{
    RdbAuditLogger logger;
    logger.OnCorrupt(DbPath(), 0, 0, "row 1 missing from index idx_test");
    EXPECT_TRUE(WaitFileExists(AuditJsonPath()));
    std::string json = ReadFileContent(AuditJsonPath());
    EXPECT_NE(json.find("corrupt"), std::string::npos);
    EXPECT_NE(json.find("row 1 missing from index idx_test"), std::string::npos);
}

// ============================================================================
// PRAGMA / DDL parsing (pure logic, no DB)
// ============================================================================

/**
 * @tc.name: RdbAuditScenario_PragmaParsing_011
 * @tc.desc: PRAGMA integrity_check / quick_check are correctly identified and parsed
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, PragmaParsing_011, TestSize.Level0)
{
    EXPECT_TRUE(RdbAuditUtils::IsPragmaIntegrityCheck("PRAGMA integrity_check"));
    EXPECT_TRUE(RdbAuditUtils::IsPragmaIntegrityCheck("PRAGMA quick_check"));
    EXPECT_TRUE(RdbAuditUtils::IsPragmaIntegrityCheck("  PRAGMA  integrity_check  ;"));
    EXPECT_FALSE(RdbAuditUtils::IsPragmaIntegrityCheck("PRAGMA journal_mode"));
    EXPECT_FALSE(RdbAuditUtils::IsPragmaIntegrityCheck("SELECT * FROM foo"));
    EXPECT_EQ(RdbAuditUtils::ParsePragmaMode("PRAGMA integrity_check"), IntegrityMode::FULL);
    EXPECT_EQ(RdbAuditUtils::ParsePragmaMode("PRAGMA quick_check"), IntegrityMode::QUICK);
}

/**
 * @tc.name: RdbAuditScenario_DdlParsing_012
 * @tc.desc: DROP TABLE / TRUNCATE TABLE op and table name are correctly parsed
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditScenarioTest, DdlParsing_012, TestSize.Level0)
{
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("DROP TABLE foo"), "DROP");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("DROP TABLE IF EXISTS foo"), "DROP");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("TRUNCATE TABLE bar"), "TRUNCATE");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("DROP INDEX idx"), "");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateOp("DROP VIEW v1"), "");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateTable("DROP TABLE foo"), "foo");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateTable("DROP TABLE IF EXISTS foo"), "foo");
    EXPECT_EQ(RdbAuditUtils::ParseDropTruncateTable("TRUNCATE TABLE bar"), "bar");
}
