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

#define LOG_TAG "RdbAuditLoggerManager"
#include "rdb_audit_logger_manager.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <sstream>

#include "logger.h"
#include "rdb_db_info_manager.h"
#include "rdb_time_utils.h"
#include "sqlite_utils.h"
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

namespace {
constexpr size_t MAX_LOG_SIZE = 256 * 1024; // 256 KB per log file
constexpr const char *EVENTS_LOG = "events.log";
constexpr const char *EVENTS_LOG_1 = "events.1.log";
constexpr const char *EVENTS_LOCK = "events.lock";
// Length of the "YYYY-" year prefix in "YYYY-MM-DD HH:MM:SS.mmm" (stripped by TsLog).
constexpr size_t YEAR_PREFIX_LEN = 5;

constexpr uint64_t AUDIT_FD_TAG_ID = 0xD001650;
const uint64_t AUDIT_FD_TAG = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, AUDIT_FD_TAG_ID);

// hilog-style timestamp: "MM-DD HH:MM:SS.mmm" (strip the year prefix).
std::string TsLog()
{
    std::string ts = RdbTimeUtils::GetCurSysTimeWithMs();
    return ts.size() > YEAR_PREFIX_LEN ? ts.substr(YEAR_PREFIX_LEN) : ts;
}

std::string BuildPragmaLine(
    const std::string &dbPath, const std::string &sql, int rc, const std::string &result)
{
    std::string ts = TsLog();
    auto caller = RdbDbInfoManager::GetInstance().CollectCaller();
    std::string dbName = SqliteUtils::Anonymous(SqliteUtils::GetDbName(dbPath));
    std::ostringstream os;
    os << ts << " " << caller.pid << " " << caller.tid << " PRG:"
       << " db=" << dbName << " sql=" << SqliteUtils::SqlAnonymous(sql)
       << " rc=" << rc << " result=" << result;
    return os.str();
}
} // namespace

RdbAuditLoggerManager &RdbAuditLoggerManager::GetInstance()
{
    static RdbAuditLoggerManager instance;
    return instance;
}

RdbAuditLoggerManager::RdbAuditLoggerManager() {}

RdbAuditLoggerManager::~RdbAuditLoggerManager()
{
    if (lockFd_ >= 0) {
        fdsan_close_with_tag(lockFd_, AUDIT_FD_TAG);
        lockFd_ = -1;
    }
    if (writeFd_ >= 0) {
        fdsan_close_with_tag(writeFd_, AUDIT_FD_TAG);
        writeFd_ = -1;
    }
}

void RdbAuditLoggerManager::Init(const std::string &auditDir, bool auditEnabled)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        return;
    }
    if (!auditEnabled || auditDir.empty()) {
        return;
    }
    auditDir_ = auditDir;
    std::string logPath = auditDir_ + EVENTS_LOG;
    writeFd_ = open(logPath.c_str(), O_CREAT | O_APPEND | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (writeFd_ < 0) {
        LOG_ERROR("Init: failed to open audit log, path=%{public}s, errno=%{public}d", logPath.c_str(), errno);
        auditDir_.clear();
        return;
    }
    fdsan_exchange_owner_tag(writeFd_, 0, AUDIT_FD_TAG);
    lockFd_ = open((auditDir_ + EVENTS_LOCK).c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (lockFd_ >= 0) {
        fdsan_exchange_owner_tag(lockFd_, 0, AUDIT_FD_TAG);
    }
    initialized_ = true;
}

void RdbAuditLoggerManager::AppendEventSync(const std::string &jsonLine)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_ || writeFd_ < 0 || jsonLine.empty()) {
        return;
    }
    if (lockFd_ >= 0 && flock(lockFd_, LOCK_EX) != 0) {
        LOG_WARN("AppendEventSync: flock LOCK_EX failed, errno=%{public}d", errno);
    }
    MaybeRotateLog();
    std::string line = jsonLine + "\n";
    size_t total = 0;
    while (total < line.size()) {
        ssize_t n = write(writeFd_, line.data() + total, line.size() - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("AppendEventSync: write failed, fd=%{public}d, errno=%{public}d", writeFd_, errno);
            break;
        }
        total += static_cast<size_t>(n);
    }
    if (lockFd_ >= 0) {
        flock(lockFd_, LOCK_UN);
    }
}

void RdbAuditLoggerManager::OnPragma(
    const std::string &dbPath, const std::string &sql, int rc, const std::string &result)
{
    auto executor = TaskExecutor::GetInstance().GetExecutor();
    if (executor == nullptr) {
        return;
    }
    executor->Execute([dbPath, sql, rc, result, this]() {
        AppendEventSync(BuildPragmaLine(dbPath, sql, rc, result));
    });
}

void RdbAuditLoggerManager::MaybeRotateLog()
{
    struct stat st;
    if (fstat(writeFd_, &st) != 0 || static_cast<size_t>(st.st_size) < MAX_LOG_SIZE) {
        return;
    }
    fdsan_close_with_tag(writeFd_, AUDIT_FD_TAG);
    writeFd_ = -1;
    std::string logPath = auditDir_ + EVENTS_LOG;
    std::string log1Path = auditDir_ + EVENTS_LOG_1;
    if (remove(log1Path.c_str()) != 0 && errno != ENOENT) {
        LOG_ERROR("MaybeRotateLog: remove old events.1.log failed, errno=%{public}d", errno);
    }
    bool rotated = (rename(logPath.c_str(), log1Path.c_str()) == 0);
    if (!rotated) {
        LOG_ERROR("MaybeRotateLog: rename failed, errno=%{public}d", errno);
    }
    int openFlags = rotated ? (O_CREAT | O_TRUNC | O_RDWR) : (O_CREAT | O_APPEND | O_RDWR);
    writeFd_ = open(logPath.c_str(), openFlags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (writeFd_ < 0) {
        LOG_ERROR("MaybeRotateLog: reopen events.log failed, errno=%{public}d", errno);
        return;
    }
    fdsan_exchange_owner_tag(writeFd_, 0, AUDIT_FD_TAG);
}

} // namespace NativeRdb
} // namespace OHOS
