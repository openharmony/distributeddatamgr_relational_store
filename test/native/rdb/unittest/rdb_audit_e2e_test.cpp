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

#include <dirent.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <thread>

#include "rdb_audit_event.h"
#include "rdb_audit_logger.h"
#include "rdb_audit_utils.h"
#include "rdb_store_config.h"
#include "sqlite_utils.h"

using namespace testing::ext;
using namespace OHOS::NativeRdb;

namespace {
constexpr const char *TEST_BASE_DIR = "/data/test/rdb_audit_e2e";

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
    char buf[4096];
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

void ResetSingleton()
{
    auto &logger = RdbAuditLogger::GetInstance();
    if (logger.lockFd_ >= 0) {
        close(logger.lockFd_);
        logger.lockFd_ = -1;
    }
    if (logger.writeFd_ >= 0) {
        close(logger.writeFd_);
        logger.writeFd_ = -1;
    }
    logger.initialized_ = false;
    logger.enableSqlAudit_ = true;
    logger.auditDir_.clear();
    logger.writeLogSize_ = 0;
    logger.throttleMap_.clear();
}

RdbStoreConfig MakeConfig()
{
    RdbStoreConfig config(std::string(TEST_BASE_DIR) + "/e2e_test.db");
    config.SetBundleName("e2e_test_app");
    config.SetAuditEnabled(true);
    return config;
}

void InitLogger()
{
    MakeDirRecursive(TEST_BASE_DIR, AUDIT_DIR_MODE);
    auto &logger = RdbAuditLogger::GetInstance();
    RdbStoreConfig config = MakeConfig();
    logger.Init(config);
    // Init() probes /data/log/hiaudit/rdb and /data/storage/el2/log which are not
    // available in the test environment. For E2E testing, manually set up the audit
    // directory and fd.
    if (!logger.initialized_) {
        std::string auditDir = std::string(TEST_BASE_DIR) + "/.audit/";
        MakeDirRecursive(auditDir, AUDIT_DIR_MODE);
        logger.auditDir_ = auditDir;
        std::string logPath = auditDir + "events.log";
        logger.writeFd_ = open(logPath.c_str(), O_CREAT | O_APPEND | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        std::string lockPath = auditDir + "events.lock";
        logger.lockFd_ = open(lockPath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        logger.enableSqlAudit_ = true;
        logger.initialized_ = true;
    }
}

std::string AuditDir()
{
    return std::string(TEST_BASE_DIR) + "/.audit/";
}
} // namespace

class RdbAuditE2ETest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
    }
    static void TearDownTestCase(void)
    {
    }

    void SetUp() override
    {
        ResetSingleton();
        RemoveDirRecursive(TEST_BASE_DIR);
        MakeDirRecursive(TEST_BASE_DIR, AUDIT_DIR_MODE);
    }

    void TearDown() override
    {
        ResetSingleton();
        RemoveDirRecursive(TEST_BASE_DIR);
    }
};

// ============================================================================
// 15.14 End-to-end scenarios
// ============================================================================

/**
 * @tc.name: RdbAuditE2E_OpenAndDelete_112
 * @tc.desc: E2E: Open event followed by DELETE audit
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, OpenAndDelete_112, TestSize.Level0)
{
    InitLogger();
    auto &logger = RdbAuditLogger::GetInstance();
    RdbStoreConfig config = MakeConfig();
    logger.OnOpenOk(config);
    logger.OnSqlAudit(config.GetPath(), "DELETE", "users", 5);
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_EQ(CountLines(content), static_cast<size_t>(2));
    EXPECT_NE(content.find("OPEN_OK"), std::string::npos);
    EXPECT_NE(content.find("SQL_AUDIT"), std::string::npos);
    EXPECT_TRUE(FileExists(AuditDir() + "last_open.bin"));
}

/**
 * @tc.name: RdbAuditE2E_DropTable_113
 * @tc.desc: E2E: DROP TABLE audit is always logged
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, DropTable_113, TestSize.Level0)
{
    InitLogger();
    auto &logger = RdbAuditLogger::GetInstance();
    logger.OnSqlAudit(std::string(TEST_BASE_DIR) + "/e2e_test.db", "DROP", "temp_table", 0);
    logger.OnSqlAudit(std::string(TEST_BASE_DIR) + "/e2e_test.db", "DROP", "temp_table", 0);
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_EQ(CountLines(content), static_cast<size_t>(2));
}

/**
 * @tc.name: RdbAuditE2E_LargeInsert_114
 * @tc.desc: E2E: Large INSERT (rows > 0) is accumulated and flushed on window expiry
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, LargeInsert_114, TestSize.Level0)
{
    InitLogger();
    auto &logger = RdbAuditLogger::GetInstance();
    logger.OnSqlAudit(std::string(TEST_BASE_DIR) + "/e2e_test.db", "INSERT", "logs", 5000);
    // Accumulated within window, no write yet.
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_EQ(CountLines(content), static_cast<size_t>(0));
    // Expire window and flush.
    logger.throttleMap_["SQL_AUDIT:INSERT:logs"].timestamp -= 61000;
    logger.OnSqlAudit(std::string(TEST_BASE_DIR) + "/e2e_test.db", "INSERT", "logs", 1);
    content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_EQ(CountLines(content), static_cast<size_t>(1));
    EXPECT_NE(content.find("\"rows\":5000"), std::string::npos);
}

/**
 * @tc.name: RdbAuditE2E_PragmaIntegrity_115
 * @tc.desc: E2E: PRAGMA integrity_check triggers integrity event
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, PragmaIntegrity_115, TestSize.Level0)
{
    InitLogger();
    auto &logger = RdbAuditLogger::GetInstance();
    std::string sql = "PRAGMA integrity_check";
    EXPECT_TRUE(RdbAuditUtils::IsPragmaIntegrityCheck(sql));
    IntegrityMode mode = RdbAuditUtils::ParsePragmaMode(sql);
    EXPECT_EQ(mode, IntegrityMode::FULL);
    logger.OnIntegrity(std::string(TEST_BASE_DIR) + "/e2e_test.db", IntegrityTrigger::ACTIVE, mode, 0, "ok");
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
    InitLogger();
    auto &logger = RdbAuditLogger::GetInstance();
    std::string sql = "PRAGMA quick_check";
    EXPECT_TRUE(RdbAuditUtils::IsPragmaIntegrityCheck(sql));
    IntegrityMode mode = RdbAuditUtils::ParsePragmaMode(sql);
    EXPECT_EQ(mode, IntegrityMode::QUICK);
    logger.OnIntegrity(std::string(TEST_BASE_DIR) + "/e2e_test.db", IntegrityTrigger::ACTIVE, mode, 0, "ok");
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
    InitLogger();
    auto &logger = RdbAuditLogger::GetInstance();
    RdbStoreConfig config = MakeConfig();
    logger.OnOpenFail(config, 14, 13);
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_NE(content.find("\"evt\":\"OPEN_FAIL\""), std::string::npos);
    EXPECT_NE(content.find("\"rc\":14"), std::string::npos);
    EXPECT_NE(content.find("\"os_errno\":13"), std::string::npos);
    // last_open.bin should NOT exist (open failed).
    EXPECT_FALSE(FileExists(AuditDir() + "last_open.bin"));
}

/**
 * @tc.name: RdbAuditE2E_AuditDisabled_119
 * @tc.desc: E2E: Audit disabled (IsAuditEnabled=false) is not audited (no directory, no events)
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, AuditDisabled_119, TestSize.Level0)
{
    // Audit not enabled: Init() should be a no-op.
    // Do NOT call InitLogger() which manually sets up the logger for testing.
    MakeDirRecursive(TEST_BASE_DIR, AUDIT_DIR_MODE);
    auto &logger = RdbAuditLogger::GetInstance();
    RdbStoreConfig config(std::string(TEST_BASE_DIR) + "/e2e_test.db");
    config.SetBundleName("e2e_test_app");
    // Audit not enabled — Init should be a no-op.
    logger.Init(config);
    EXPECT_FALSE(logger.initialized_);
    EXPECT_TRUE(logger.auditDir_.empty());
    // OnOpenOk should be a no-op (initialized_ = false).
    logger.OnOpenOk(config);
    EXPECT_FALSE(FileExists(std::string(TEST_BASE_DIR) + "/.audit/events.log"));
}

/**
 * @tc.name: RdbAuditE2E_Throttle_122
 * @tc.desc: E2E: Throttle prevents duplicate IO_ERR events within 60s
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, Throttle_122, TestSize.Level0)
{
    InitLogger();
    auto &logger = RdbAuditLogger::GetInstance();
    logger.OnIoError("execute", "/data/test/f.db", 10, 5);
    logger.OnIoError("execute", "/data/test/f.db", 10, 5);
    logger.OnIoError("execute", "/data/test/f.db", 10, 5);
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_EQ(CountLines(content), static_cast<size_t>(1));
}

/**
 * @tc.name: RdbAuditE2E_OpenFailThenOk_125
 * @tc.desc: E2E: Open fail followed by open ok — both events recorded
 * @tc.type: FUNC
 */
HWTEST_F(RdbAuditE2ETest, OpenFailThenOk_125, TestSize.Level0)
{
    InitLogger();
    auto &logger = RdbAuditLogger::GetInstance();
    RdbStoreConfig config = MakeConfig();
    logger.OnOpenFail(config, 14, 13);
    logger.OnOpenOk(config);
    std::string content = ReadFileContent(AuditDir() + "events.log");
    EXPECT_EQ(CountLines(content), static_cast<size_t>(2));
    // First line should be OPEN_FAIL, second should be OPEN_OK.
    size_t firstNewline = content.find('\n');
    ASSERT_NE(firstNewline, std::string::npos);
    std::string firstLine = content.substr(0, firstNewline);
    EXPECT_NE(firstLine.find("OPEN_FAIL"), std::string::npos);
    std::string secondLine = content.substr(firstNewline + 1);
    EXPECT_NE(secondLine.find("OPEN_OK"), std::string::npos);
    // last_open.bin should exist (from OnOpenOk).
    EXPECT_TRUE(FileExists(AuditDir() + "last_open.bin"));
}
