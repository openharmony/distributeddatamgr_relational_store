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
#include "rdb_store_config.h"
#include "sqlite_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace {
constexpr const char *TEST_BASE_DIR = "/data/test/rdb_audit_e2e";
constexpr size_t READ_BUF_SIZE = 4096;
constexpr int TEST_ERR_CODE = 14;
constexpr int TEST_OS_ERRNO = 13;
constexpr int TEST_IO_ERR_CODE = 10;
constexpr int TEST_IO_OS_ERRNO = 5;
constexpr int64_t TEST_DELETE_ROWS = 5;
constexpr int64_t TEST_LARGE_INSERT_ROWS = 5000;
constexpr int64_t THROTTLE_EXPIRE_OFFSET_MS = 61 * 1000;
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

void RemoveDirRecursive(const std::string &path)
{
    if (path.empty()) {
        return;
    }
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        unlink(path.c_str());
        return;
    }
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        std::string full = path + "/" + entry->d_name;
        struct stat st;
        if (stat(full.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
            RemoveDirRecursive(full);
        } else {
            unlink(full.c_str());
        }
    }
    closedir(dir);
    rmdir(path.c_str());
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

RdbStoreConfig MakeConfig()
{
    RdbStoreConfig config(std::string(TEST_BASE_DIR) + "/e2e_test.db");
    config.SetBundleName("e2e_test_app");
    config.SetAuditEnabled(true);
    return config;
}

std::string AuditDir()
{
    return std::string(TEST_BASE_DIR) + "/.audit/";
}

// Manually set up both singleton managers for testing: the real audit roots
// (/data/log/hiaudit/rdb, /data/storage/el2/log) are not available in the unit
// test environment, so we inject the audit directory + fds directly. The managers
// dispatch writes via TaskExecutor (async); tests poll with sleep+retry to wait.
void SetupManager()
{
    std::string auditDir = AuditDir();
    MakeDirRecursive(auditDir, AUDIT_DIR_MODE);
    auto &amgr = RdbAuditLoggerManager::GetInstance();
    if (amgr.lockFd_ >= 0) {
        close(amgr.lockFd_);
        amgr.lockFd_ = -1;
    }
    if (amgr.writeFd_ >= 0) {
        close(amgr.writeFd_);
        amgr.writeFd_ = -1;
    }
    amgr.auditDir_ = auditDir;
    amgr.writeFd_ =
        open((auditDir + "events.log").c_str(), O_CREAT | O_APPEND | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    amgr.lockFd_ =
        open((auditDir + "events.lock").c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    amgr.initialized_ = true;
    auto &dbmgr = RdbDbLoggerManager::GetInstance();
    dbmgr.auditDir_ = auditDir;
    dbmgr.initialized_ = true;
}

void ResetManager()
{
    auto &amgr = RdbAuditLoggerManager::GetInstance();
    if (amgr.lockFd_ >= 0) {
        close(amgr.lockFd_);
        amgr.lockFd_ = -1;
    }
    if (amgr.writeFd_ >= 0) {
        close(amgr.writeFd_);
        amgr.writeFd_ = -1;
    }
    amgr.initialized_ = false;
    amgr.auditDir_.clear();
    auto &dbmgr = RdbDbLoggerManager::GetInstance();
    dbmgr.initialized_ = false;
    dbmgr.auditDir_.clear();
}

// Poll events.log until it has at least `expected` lines, or timeout. Audit
// writes are async (TaskExecutor), so callers retry until the write lands.
size_t WaitEventLines(size_t expected, int timeoutMs = 2000)
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    size_t lines = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        lines = CountLines(ReadFileContent(AuditDir() + "events.log"));
        if (lines >= expected) {
            return lines;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(POLL_INTERVAL_MS));
    }
    return CountLines(ReadFileContent(AuditDir() + "events.log"));
}

// Poll until a file exists, or timeout.
bool WaitFileExists(const std::string &path, int timeoutMs = 2000)
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
} // namespace

class RdbAuditE2ETest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}

    void SetUp() override
    {
        ResetManager();
        logger_.enabled_ = false;
        logger_.enableSqlAudit_ = true;
        logger_.throttleMap_.clear();
    }

    void TearDown() override
    {
        ResetManager();
        RemoveDirRecursive(TEST_BASE_DIR);
    }

protected:
    RdbAuditLogger logger_;
};

// ============================================================================
// End-to-end scenarios
// ============================================================================

/**
 * @tc.name: RdbAuditE2E_OpenAndDelete_112
 * @tc.desc: E2E: Open event followed by DELETE audit
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, OpenAndDelete_112, TestSize.Level0)
{
    SetupManager();
    RdbStoreConfig config = MakeConfig();
    logger_.OnOpenOk(config.GetPath(), false, config.IsAuditEnabled());
    logger_.OnSqlAudit(config.GetPath(), "DELETE", "users", TEST_DELETE_ROWS, true);
    EXPECT_EQ(WaitEventLines(2), static_cast<size_t>(2));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("OPEN_OK"), std::string::npos);
    EXPECT_NE(content.find("SQL_AUDIT"), std::string::npos);
    // audit.json block 1 (lastOpen) should be written.
    EXPECT_TRUE(WaitFileExists(AuditDir() + "e2e_test_audit.json"));
}

/**
 * @tc.name: RdbAuditE2E_DropTable_113
 * @tc.desc: E2E: DROP TABLE audit is always logged
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, DropTable_113, TestSize.Level0)
{
    SetupManager();
    std::string dbPath = std::string(TEST_BASE_DIR) + "/e2e_test.db";
    logger_.OnSqlAudit(dbPath, "DROP", "temp_table", 0, true);
    logger_.OnSqlAudit(dbPath, "DROP", "temp_table", 0, true);
    EXPECT_EQ(WaitEventLines(2), static_cast<size_t>(2));
}

/**
 * @tc.name: RdbAuditE2E_LargeInsert_114
 * @tc.desc: E2E: Large INSERT (rows > 0) is accumulated and flushed on window expiry
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, LargeInsert_114, TestSize.Level0)
{
    SetupManager();
    std::string dbPath = std::string(TEST_BASE_DIR) + "/e2e_test.db";
    logger_.OnSqlAudit(dbPath, "INSERT", "logs", TEST_LARGE_INSERT_ROWS, true);
    // Accumulated within window, no write yet (no async task dispatched).
    EXPECT_EQ(CountLines(ReadFileContent(AuditDir() + "events.log")), static_cast<size_t>(0));
    // Expire window and flush.
    logger_.throttleMap_["SQL_AUDIT:INSERT:logs"].timestamp -= THROTTLE_EXPIRE_OFFSET_MS;
    logger_.OnSqlAudit(dbPath, "INSERT", "logs", 1, true);
    EXPECT_EQ(WaitEventLines(1), static_cast<size_t>(1));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"rows\":5000"), std::string::npos);
}

/**
 * @tc.name: RdbAuditE2E_PragmaIntegrity_115
 * @tc.desc: E2E: PRAGMA integrity_check triggers integrity event
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, PragmaIntegrity_115, TestSize.Level0)
{
    SetupManager();
    std::string sql = "PRAGMA integrity_check";
    EXPECT_TRUE(RdbAuditUtils::IsPragmaIntegrityCheck(sql));
    IntegrityMode mode = RdbAuditUtils::ParsePragmaMode(sql);
    EXPECT_EQ(mode, IntegrityMode::FULL);
    logger_.OnIntegrity(std::string(TEST_BASE_DIR) + "/e2e_test.db", IntegrityTrigger::ACTIVE, mode, 0, "ok");
    WaitEventLines(1);
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"evt\":\"INTEGRITY\""), std::string::npos);
    EXPECT_NE(content.find("\"trigger\":\"active\""), std::string::npos);
    EXPECT_NE(content.find("\"mode\":\"full\""), std::string::npos);
}

/**
 * @tc.name: RdbAuditE2E_PragmaQuickCheck_116
 * @tc.desc: E2E: PRAGMA quick_check triggers integrity event with QUICK mode
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, PragmaQuickCheck_116, TestSize.Level0)
{
    SetupManager();
    std::string sql = "PRAGMA quick_check";
    EXPECT_TRUE(RdbAuditUtils::IsPragmaIntegrityCheck(sql));
    IntegrityMode mode = RdbAuditUtils::ParsePragmaMode(sql);
    EXPECT_EQ(mode, IntegrityMode::QUICK);
    logger_.OnIntegrity(std::string(TEST_BASE_DIR) + "/e2e_test.db", IntegrityTrigger::ACTIVE, mode, 0, "ok");
    WaitEventLines(1);
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"mode\":\"quick\""), std::string::npos);
}

/**
 * @tc.name: RdbAuditE2E_OpenFail_117
 * @tc.desc: E2E: Open failure records OPEN_FAIL event with error context
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, OpenFail_117, TestSize.Level0)
{
    SetupManager();
    RdbStoreConfig config = MakeConfig();
    logger_.OnOpenFail(config.GetPath(), TEST_ERR_CODE, TEST_OS_ERRNO, true);
    WaitEventLines(1);
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"evt\":\"OPEN_FAIL\""), std::string::npos);
    EXPECT_NE(content.find("\"rc\":14"), std::string::npos);
    EXPECT_NE(content.find("\"os_errno\":13"), std::string::npos);
}

/**
 * @tc.name: RdbAuditE2E_AuditDisabled_119
 * @tc.desc: E2E: Audit disabled (IsAuditEnabled=false) is not audited
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, AuditDisabled_119, TestSize.Level0)
{
    // Do NOT call SetupManager(); config has SetAuditEnabled=false, so OnOpenOk
    // returns before EnsureInit — no audit directory is probed or created.
    MakeDirRecursive(TEST_BASE_DIR, AUDIT_DIR_MODE);
    RdbStoreConfig config(std::string(TEST_BASE_DIR) + "/e2e_test.db");
    config.SetBundleName("e2e_test_app");
    logger_.OnOpenOk(config.GetPath(), false, config.IsAuditEnabled());
    EXPECT_FALSE(logger_.enabled_);
    EXPECT_FALSE(RdbAuditLoggerManager::GetInstance().initialized_);
    EXPECT_TRUE(RdbAuditLoggerManager::GetInstance().auditDir_.empty());
    EXPECT_FALSE(FileExists(std::string(TEST_BASE_DIR) + "/.audit/events.log"));
}

/**
 * @tc.name: RdbAuditE2E_IoErrorNoThrottle_122
 * @tc.desc: E2E: IO_ERR is always logged without throttle and writes audit.json block 2
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, IoErrorNoThrottle_122, TestSize.Level0)
{
    SetupManager();
    logger_.OnIoError("execute", "/data/test/el2/database/f.db", TEST_IO_ERR_CODE, TEST_IO_OS_ERRNO, true);
    logger_.OnIoError("execute", "/data/test/el2/database/f.db", TEST_IO_ERR_CODE, TEST_IO_OS_ERRNO, true);
    logger_.OnIoError("execute", "/data/test/el2/database/f.db", TEST_IO_ERR_CODE, TEST_IO_OS_ERRNO, true);
    EXPECT_EQ(WaitEventLines(3), static_cast<size_t>(3));
    // audit.json block 2 (firstLoss) should be written.
    // dbPath "/data/test/el2/database/f.db" -> el="el2", dbName="f" -> "el2f_audit.json"
    EXPECT_TRUE(WaitFileExists(AuditDir() + "el2f_audit.json"));
    std::string json = ReadFileContent(AuditDir() + "el2f_audit.json");
    EXPECT_NE(json.find("firstLoss"), std::string::npos);
}

/**
 * @tc.name: RdbAuditE2E_OpenFailThenOk_125
 * @tc.desc: E2E: Open fail followed by open ok — both events recorded
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, OpenFailThenOk_125, TestSize.Level0)
{
    SetupManager();
    RdbStoreConfig config = MakeConfig();
    logger_.OnOpenFail(config.GetPath(), TEST_ERR_CODE, TEST_OS_ERRNO, true);
    logger_.OnOpenOk(config.GetPath(), false, config.IsAuditEnabled());
    EXPECT_EQ(WaitEventLines(2), static_cast<size_t>(2));
    std::string content = ReadFileContent(AuditDir() + "events.log");
    size_t firstNewline = content.find('\n');
    ASSERT_NE(firstNewline, std::string::npos);
    std::string firstLine = content.substr(0, firstNewline);
    EXPECT_NE(firstLine.find("OPEN_FAIL"), std::string::npos);
    std::string secondLine = content.substr(firstNewline + 1);
    EXPECT_NE(secondLine.find("OPEN_OK"), std::string::npos);
    // audit.json block 1 (lastOpen) should exist after OnOpenOk.
    EXPECT_TRUE(WaitFileExists(AuditDir() + "e2e_test_audit.json"));
}
