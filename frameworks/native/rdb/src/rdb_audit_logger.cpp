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

#define LOG_TAG "RdbAuditLogger"
#include "rdb_audit_logger.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#include "logger.h"
#include "rdb_db_info_manager.h"
#include "rdb_platform.h"
#include "rdb_time_utils.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

namespace {
constexpr size_t MAX_LOG_SIZE = 256 * 1024; // 256 KB per log file
// Audit directory roots probed by Init(). The SA root is checked first;
// if it exists, a per-uid sub-directory is used. Otherwise the app log root
// is checked; if it exists, an "rdb" sub-directory is created under it.
constexpr const char *AUDIT_DIR_SA_ROOT = "/data/log/hiaudit/rdb";
constexpr const char *AUDIT_DIR_APP_ROOT = "/data/storage/el2/log";
constexpr const char *AUDIT_DIR_APP_SUB = "rdb";
constexpr const char *EVENTS_LOG = "events.log";
constexpr const char *EVENTS_LOG_1 = "events.1.log";
constexpr const char *EVENTS_LOCK = "events.lock";
constexpr const char *LAST_OPEN_BIN = "last_open.bin";
constexpr const char *LAST_INTEGRITY_BIN = "last_integrity.bin";
constexpr int64_t THROTTLE_INTERVAL_MS = 60 * 1000; // 60 s
constexpr size_t THROTTLE_MAP_MAX_SIZE = 64;

// fdsan owner tag for all audit file descriptors. Matches the tag used by
// other RDB fd owners (see 798261b5) so fdsan can detect double-close or
// use-after-close across the component.
constexpr uint64_t AUDIT_FD_TAG_ID = 0xD001650;
const uint64_t AUDIT_FD_TAG = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, AUDIT_FD_TAG_ID);

int64_t NowMs()
{
    auto dur = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
}

bool IsUnderAuditRoot(const std::string &path)
{
    return path.rfind(AUDIT_DIR_SA_ROOT, 0) == 0 ||
        path.rfind(std::string(AUDIT_DIR_APP_ROOT) + "/" + AUDIT_DIR_APP_SUB, 0) == 0;
}

bool TryMkDir(const std::string &path)
{
    if (MkDir(path, AUDIT_DIR_MODE) != 0 && errno != EEXIST) {
        LOG_ERROR("MkDirP: mkdir failed, path=%{public}s, errno=%{public}d, err=%{public}s", path.c_str(),
            errno, strerror(errno));
        return false;
    }
    return true;
}

bool MkDirP(const std::string &path)
{
    if (path.empty()) {
        return false;
    }
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        return true;
    }
    size_t pos = 0;
    while ((pos = path.find('/', pos + 1)) != std::string::npos) {
        std::string sub = path.substr(0, pos);
        struct stat subSt;
        if (stat(sub.c_str(), &subSt) == 0 && S_ISDIR(subSt.st_mode)) {
            continue;
        }
        // Only create directories under known audit roots — skip system
        // directories (e.g. /data, /data/log) that we don't own.
        if (IsUnderAuditRoot(sub) && !TryMkDir(sub)) {
            return false;
        }
    }
    return TryMkDir(path);
}

std::string EscapeJson(const std::string &s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += c;
                break;
        }
    }
    return out;
}

// Write a single FileInfo as a JSON object fragment: "label":{inode,mtime,size,perm}
void WriteFileInfo(std::ostringstream &os, const char *label, const FileInfo &fi)
{
    os << "\"" << label << "\":{\"inode\":" << fi.node << ",\"mtime\":" << fi.time.mtime << ",\"size\":" << fi.size
       << ",\"perm\":{\"mode\":\"" << EscapeJson(fi.permission.mode) << "\",\"acl\":\""
       << EscapeJson(fi.permission.acl) << "\"}}";
}
} // namespace

RdbAuditLogger &RdbAuditLogger::GetInstance()
{
    static RdbAuditLogger instance;
    return instance;
}

RdbAuditLogger::~RdbAuditLogger()
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

void RdbAuditLogger::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (initialized_) {
        return; // dir/fd already set up by a previous Init
    }
    // Probe audit directory: SA root first (per-uid sub-directory), then app
    // log root (rdb sub-directory). If neither exists, audit is disabled.
    struct stat st;
    if (stat(AUDIT_DIR_SA_ROOT, &st) == 0 && S_ISDIR(st.st_mode)) {
        int32_t uid = static_cast<int32_t>(GetUid());
        auditDir_ = std::string(AUDIT_DIR_SA_ROOT) + "/" + std::to_string(uid) + "/";
    } else if (stat(AUDIT_DIR_APP_ROOT, &st) == 0 && S_ISDIR(st.st_mode)) {
        auditDir_ = std::string(AUDIT_DIR_APP_ROOT) + "/" + AUDIT_DIR_APP_SUB + "/";
    } else {
        LOG_INFO("Init: no audit directory available, audit disabled");
        return;
    }
    if (!MkDirP(auditDir_)) {
        LOG_ERROR("Init: failed to create audit directory %{public}s, errno=%{public}d, err=%{public}s",
            auditDir_.c_str(), errno, strerror(errno));
        auditDir_.clear();
        return;
    }
    // Open persistent fd for events.log (reference: hi_audit.cpp Init)
    std::string logPath = auditDir_ + EVENTS_LOG;
    writeFd_ = open(logPath.c_str(), O_CREAT | O_APPEND | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (writeFd_ < 0) {
        LOG_ERROR("Init: failed to open audit log, path=%{public}s, errno=%{public}d, err=%{public}s", logPath.c_str(),
            errno, strerror(errno));
        auditDir_.clear();
        return;
    }
    fdsan_exchange_owner_tag(writeFd_, 0, AUDIT_FD_TAG);
    if (stat(logPath.c_str(), &st) != 0) {
        LOG_WARN("Init: stat events.log failed, path=%{public}s, errno=%{public}d, err=%{public}s, reset size to 0",
            logPath.c_str(), errno, strerror(errno));
        writeLogSize_ = 0;
    } else {
        writeLogSize_ = static_cast<size_t>(st.st_size);
    }
    // Open inter-process lock file. flock is best-effort: if it fails, logging
    // continues without cross-process protection (single-process mutex still applies).
    std::string lockPath = auditDir_ + EVENTS_LOCK;
    lockFd_ = open(lockPath.c_str(), O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (lockFd_ < 0) {
        LOG_WARN("Init: failed to open lock file, path=%{public}s, errno=%{public}d, err=%{public}s", lockPath.c_str(),
            errno, strerror(errno));
    } else {
        fdsan_exchange_owner_tag(lockFd_, 0, AUDIT_FD_TAG);
    }
    initialized_ = true;
}

void RdbAuditLogger::OnOpenOk(const std::string &dbPath)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return;
    }
    std::string json = BuildOpenOkJson(dbPath);
    AppendEvent(json);
    WriteLastOpen(json);
}

void RdbAuditLogger::OnOpenFail(const std::string &dbPath, int rc, int osErrno)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return;
    }
    AppendEvent(BuildOpenFailJson(dbPath, rc, osErrno));
}

void RdbAuditLogger::OnIoError(const std::string &op, const std::string &file, int rc, int osErrno)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return;
    }
    // IO_ERR is always logged — no throttle.
    AppendEvent(BuildIoErrJson(op, file, rc, osErrno));
}

void RdbAuditLogger::OnSqlAudit(const std::string &dbPath, const std::string &op, const std::string &tbl, int64_t rows)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_ || !enableSqlAudit_) {
        return;
    }
    // DELETE/DROP/TRUNCATE are always logged (no throttle). rows <= 0 is not recorded
    // (DELETE with 0 rows has no data change; DROP/TRUNCATE always pass rows=0 but
    // are logged unconditionally).
    bool alwaysLog = (op == "DELETE" || op == "DROP" || op == "TRUNCATE");
    if (alwaysLog) {
        if (op == "DELETE" && rows <= 0) {
            return;
        }
        AppendEvent(BuildSqlAuditJson(dbPath, op, tbl, rows));
        return;
    }
    // INSERT/UPDATE: rows > 0 with 60s per-(op,tbl) accumulation.
    if (rows <= 0) {
        return;
    }
    std::string eventKey = "SQL_AUDIT:" + op + ":" + tbl;
    int64_t flushRows = 0;
    if (AccumulateOrFlush(eventKey, rows, flushRows)) {
        return; // accumulated within window, no write
    }
    if (flushRows > 0) {
        AppendEvent(BuildSqlAuditJson(dbPath, op, tbl, flushRows));
    }
}

void RdbAuditLogger::OnIntegrity(
    const std::string &dbPath, IntegrityTrigger trigger, IntegrityMode mode, int result, const std::string &err)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return;
    }
    std::string json = BuildIntegrityJson(dbPath, trigger, mode, result, err);
    AppendEvent(json);
    // Only persist the baseline snapshot when integrity check succeeded,
    // preserving the last successful state for anomaly localization.
    if (result == 0) {
        WriteLastIntegrity(json);
    }
}

void RdbAuditLogger::OnDbDelete(const std::string &dbPath, const std::string &op)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!initialized_) {
        return;
    }
    // DB_DELETE is always logged — no throttle.
    AppendEvent(BuildDbDeleteJson(dbPath, op));
}

// --- Private helpers ---

bool RdbAuditLogger::AccumulateOrFlush(const std::string &eventKey, int64_t rows, int64_t &flushRows)
{
    flushRows = 0;
    int64_t now = NowMs();
    auto it = throttleMap_.find(eventKey);
    if (it != throttleMap_.end() && (now - it->second.timestamp) < THROTTLE_INTERVAL_MS) {
        // Within window: accumulate rows, do not write.
        it->second.accumulatedRows += rows;
        return true;
    }
    // Window expired or first event: flush previous accumulated total.
    if (it != throttleMap_.end()) {
        flushRows = it->second.accumulatedRows;
    }
    // Start new window with current rows.
    throttleMap_[eventKey] = {now, rows};
    // Clean up expired entries to prevent unbounded growth.
    if (throttleMap_.size() > THROTTLE_MAP_MAX_SIZE) {
        for (auto mapIt = throttleMap_.begin(); mapIt != throttleMap_.end();) {
            if (mapIt->first != eventKey && (now - mapIt->second.timestamp) >= THROTTLE_INTERVAL_MS) {
                mapIt = throttleMap_.erase(mapIt);
            } else {
                ++mapIt;
            }
        }
    }
    return false;
}

void RdbAuditLogger::AppendEvent(const std::string &jsonLine)
{
    if (!initialized_ || writeFd_ < 0 || jsonLine.empty()) {
        return;
    }
    // Inter-process lock protects rotation + write from concurrent processes.
    if (lockFd_ >= 0 && flock(lockFd_, LOCK_EX) != 0) {
        LOG_WARN("AppendEvent: flock LOCK_EX failed, errno=%{public}d, err=%{public}s", errno, strerror(errno));
    }
    // Reference: hi_audit.cpp WriteToFile + GetWriteFilePath
    MaybeRotateLog();
    std::string line = jsonLine + "\n";
    // Loop to handle partial writes (EINTR / pipe buffer full). best-effort:
    // on persistent error we stop and discard the remainder rather than block.
    size_t total = 0;
    while (total < line.size()) {
        ssize_t n = write(writeFd_, line.data() + total, line.size() - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_ERROR("AppendEvent: write failed, fd=%{public}d, errno=%{public}d, err=%{public}s", writeFd_, errno,
                strerror(errno));
            break;
        }
        total += static_cast<size_t>(n);
    }
    writeLogSize_ += total;
    if (lockFd_ >= 0) {
        flock(lockFd_, LOCK_UN);
    }
}

void RdbAuditLogger::WriteLastOpen(const std::string &snapshot)
{
    WriteAtomicFile(auditDir_ + "/" + LAST_OPEN_BIN, snapshot);
}

void RdbAuditLogger::WriteLastIntegrity(const std::string &snapshot)
{
    WriteAtomicFile(auditDir_ + "/" + LAST_INTEGRITY_BIN, snapshot);
}

void RdbAuditLogger::WriteAtomicFile(const std::string &path, const std::string &content)
{
    // Atomic: write to tmp file, fsync, rename — flock prevents concurrent tmp overwrite.
    std::string tmpPath = path + ".tmp";
    if (lockFd_ >= 0 && flock(lockFd_, LOCK_EX) != 0) {
        LOG_WARN("WriteAtomicFile: flock LOCK_EX failed, errno=%{public}d, err=%{public}s", errno, strerror(errno));
    }
    int fd = open(tmpPath.c_str(), O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd < 0) {
        LOG_ERROR("WriteAtomicFile: failed to open tmp file, path=%{public}s, errno=%{public}d, err=%{public}s",
            tmpPath.c_str(), errno, strerror(errno));
        if (lockFd_ >= 0) {
            flock(lockFd_, LOCK_UN);
        }
        return;
    }
    fdsan_exchange_owner_tag(fd, 0, AUDIT_FD_TAG);
    if (write(fd, content.data(), content.size()) < 0) {
        LOG_ERROR("WriteAtomicFile: failed to write tmp file, path=%{public}s, errno=%{public}d, err=%{public}s",
            tmpPath.c_str(), errno, strerror(errno));
        fdsan_close_with_tag(fd, AUDIT_FD_TAG);
        if (lockFd_ >= 0) {
            flock(lockFd_, LOCK_UN);
        }
        return;
    }
    fdsan_close_with_tag(fd, AUDIT_FD_TAG);
    if (rename(tmpPath.c_str(), path.c_str()) != 0) {
        LOG_ERROR("WriteAtomicFile: rename failed, tmp=%{public}s, dst=%{public}s, errno=%{public}d, err=%{public}s",
            tmpPath.c_str(), path.c_str(), errno, strerror(errno));
    }
    if (lockFd_ >= 0) {
        flock(lockFd_, LOCK_UN);
    }
}

void RdbAuditLogger::MaybeRotateLog()
{
    if (writeLogSize_ < MAX_LOG_SIZE) {
        return;
    }
    // Reference: hi_audit.cpp GetWriteFilePath — close fd, rename, reopen
    fdsan_close_with_tag(writeFd_, AUDIT_FD_TAG);
    writeFd_ = -1;
    std::string logPath = auditDir_ + "/" + EVENTS_LOG;
    std::string log1Path = auditDir_ + "/" + EVENTS_LOG_1;
    if (remove(log1Path.c_str()) != 0 && errno != ENOENT) {
        LOG_ERROR("MaybeRotateLog: remove old events.1.log failed, path=%{public}s, errno=%{public}d, err=%{public}s",
            log1Path.c_str(), errno, strerror(errno));
    }
    bool rotated = (rename(logPath.c_str(), log1Path.c_str()) == 0);
    if (!rotated) {
        LOG_ERROR("MaybeRotateLog: rename failed, src=%{public}s, dst=%{public}s, errno=%{public}d, err=%{public}s",
            logPath.c_str(), log1Path.c_str(), errno, strerror(errno));
    }
    // On successful rotation: create new empty log. On failure: reopen with O_APPEND to preserve content.
    int openFlags = rotated ? (O_CREAT | O_TRUNC | O_RDWR) : (O_CREAT | O_APPEND | O_RDWR);
    writeFd_ = open(logPath.c_str(), openFlags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (writeFd_ < 0) {
        LOG_ERROR("MaybeRotateLog: reopen events.log failed, path=%{public}s, errno=%{public}d, err=%{public}s",
            logPath.c_str(), errno, strerror(errno));
        return;
    }
    fdsan_exchange_owner_tag(writeFd_, 0, AUDIT_FD_TAG);
    if (rotated) {
        writeLogSize_ = 0;
    } else {
        struct stat st;
        writeLogSize_ = (fstat(writeFd_, &st) == 0) ? static_cast<size_t>(st.st_size) : 0;
    }
}

std::string RdbAuditLogger::ExtractDbName(const std::string &dbPath) const
{
    size_t lastSlash = dbPath.rfind('/');
    std::string name = (lastSlash == std::string::npos) ? dbPath : dbPath.substr(lastSlash + 1);
    constexpr size_t DB_SUFFIX_LEN = 3; // length of ".db"
    if (name.size() > DB_SUFFIX_LEN && name.substr(name.size() - DB_SUFFIX_LEN) == ".db") {
        name = name.substr(0, name.size() - DB_SUFFIX_LEN);
    }
    return name;
}

std::string RdbAuditLogger::BuildOpenOkJson(const std::string &dbPath)
{
    std::string ts = RdbTimeUtils::GetCurSysTimeWithMs();
    auto caller = RdbDbInfoManager::GetInstance().CollectCaller();
    auto fileInfo = RdbDbInfoManager::GetInstance().CollectDbFileInfo(dbPath);
    auto slaveInfo = RdbDbInfoManager::GetInstance().CollectDbFileInfo(SqliteUtils::GetSlavePath(dbPath));
    std::string dbName = SqliteUtils::Anonymous(ExtractDbName(dbPath));

    std::ostringstream os;
    os << "{\"evt\":\"OPEN_OK\",\"ts\":\"" << EscapeJson(ts) << "\""
       << ",\"db_name\":\"" << EscapeJson(dbName) << "\""
       << ",\"proc\":\"pid:" << caller.pid << ":tid:" << caller.tid << "\""
       << ",\"files\":{";
    WriteFileInfo(os, "db", fileInfo.db);
    os << ",";
    WriteFileInfo(os, "wal", fileInfo.wal);
    os << ",";
    WriteFileInfo(os, "shm", fileInfo.shm);
    os << ",\"slave\":{";
    WriteFileInfo(os, "db", slaveInfo.db);
    os << ",";
    WriteFileInfo(os, "wal", slaveInfo.wal);
    os << ",";
    WriteFileInfo(os, "shm", slaveInfo.shm);
    os << "}},\"dir_perm\":{\"mode\":\"" << EscapeJson(fileInfo.parent.permission.mode) << "\",\"acl\":\""
       << EscapeJson(fileInfo.parent.permission.acl) << "\"}}";
    return os.str();
}

std::string RdbAuditLogger::BuildOpenFailJson(const std::string &dbPath, int rc, int osErrno)
{
    std::string ts = RdbTimeUtils::GetCurSysTimeWithMs();
    auto caller = RdbDbInfoManager::GetInstance().CollectCaller();
    std::string dbName = SqliteUtils::Anonymous(ExtractDbName(dbPath));
    std::ostringstream os;
    os << "{\"evt\":\"OPEN_FAIL\",\"ts\":\"" << EscapeJson(ts) << "\""
       << ",\"db_name\":\"" << EscapeJson(dbName) << "\""
       << ",\"proc\":\"pid:" << caller.pid << ":tid:" << caller.tid << "\""
       << ",\"rc\":" << rc << ",\"os_errno\":" << osErrno << ",\"path\":\""
       << EscapeJson(SqliteUtils::Anonymous(dbPath)) << "\"}";
    return os.str();
}

std::string RdbAuditLogger::BuildIoErrJson(const std::string &op, const std::string &file, int rc, int osErrno)
{
    std::string ts = RdbTimeUtils::GetCurSysTimeWithMs();
    std::string dbName = SqliteUtils::Anonymous(ExtractDbName(file));
    std::ostringstream os;
    os << "{\"evt\":\"IO_ERR\",\"ts\":\"" << EscapeJson(ts) << "\""
       << ",\"db_name\":\"" << EscapeJson(dbName) << "\""
       << ",\"rc\":" << rc << ",\"os_errno\":" << osErrno << ",\"op\":\"" << EscapeJson(op) << "\""
       << ",\"file\":\"" << EscapeJson(SqliteUtils::Anonymous(file)) << "\"}";
    return os.str();
}

std::string RdbAuditLogger::BuildSqlAuditJson(
    const std::string &dbPath, const std::string &op, const std::string &tbl, int64_t rows)
{
    std::string ts = RdbTimeUtils::GetCurSysTimeWithMs();
    auto caller = RdbDbInfoManager::GetInstance().CollectCaller();
    std::string dbName = SqliteUtils::Anonymous(ExtractDbName(dbPath));
    std::ostringstream os;
    os << "{\"evt\":\"SQL_AUDIT\",\"ts\":\"" << EscapeJson(ts) << "\""
       << ",\"db_name\":\"" << EscapeJson(dbName) << "\""
       << ",\"op\":\"" << EscapeJson(op) << "\""
       << ",\"tbl\":\"" << EscapeJson(SqliteUtils::Anonymous(tbl)) << "\""
       << ",\"rows\":" << rows << ",\"caller\":\"pid:" << caller.pid << ":tid:" << caller.tid << "\"}";
    return os.str();
}

std::string RdbAuditLogger::BuildIntegrityJson(
    const std::string &dbPath, IntegrityTrigger trigger, IntegrityMode mode, int result, const std::string &err)
{
    std::string ts = RdbTimeUtils::GetCurSysTimeWithMs();
    std::string dbName = SqliteUtils::Anonymous(ExtractDbName(dbPath));
    std::ostringstream os;
    os << "{\"evt\":\"INTEGRITY\",\"ts\":\"" << EscapeJson(ts) << "\""
       << ",\"db_name\":\"" << EscapeJson(dbName) << "\""
       << ",\"trigger\":\"" << TriggerToStr(trigger) << "\""
       << ",\"mode\":\"" << ModeToStr(mode) << "\""
       << ",\"result\":" << result << ",\"err\":\"" << EscapeJson(err) << "\""
       << ",\"path\":\"" << EscapeJson(SqliteUtils::Anonymous(dbPath)) << "\"}";
    return os.str();
}

std::string RdbAuditLogger::BuildDbDeleteJson(const std::string &dbPath, const std::string &op)
{
    std::string ts = RdbTimeUtils::GetCurSysTimeWithMs();
    auto caller = RdbDbInfoManager::GetInstance().CollectCaller();
    auto fileInfo = RdbDbInfoManager::GetInstance().CollectDbFileInfo(dbPath);
    std::string dbName = SqliteUtils::Anonymous(ExtractDbName(dbPath));
    std::ostringstream os;
    os << "{\"evt\":\"DB_DELETE\",\"ts\":\"" << EscapeJson(ts) << "\""
       << ",\"db_name\":\"" << EscapeJson(dbName) << "\""
       << ",\"op\":\"" << EscapeJson(op) << "\""
       << ",\"path\":\"" << EscapeJson(SqliteUtils::Anonymous(dbPath)) << "\""
       << ",\"files\":{";
    WriteFileInfo(os, "db", fileInfo.db);
    os << ",";
    WriteFileInfo(os, "wal", fileInfo.wal);
    os << ",";
    WriteFileInfo(os, "shm", fileInfo.shm);
    os << "},\"caller\":\"pid:" << caller.pid << ":tid:" << caller.tid << "\"}";
    return os.str();
}

const char *RdbAuditLogger::TriggerToStr(IntegrityTrigger trigger)
{
    switch (trigger) {
        case IntegrityTrigger::AUTO:
            return "auto";
        case IntegrityTrigger::ACTIVE:
            return "active";
        default:
            return "unknown";
    }
}

const char *RdbAuditLogger::ModeToStr(IntegrityMode mode)
{
    switch (mode) {
        case IntegrityMode::QUICK:
            return "quick";
        case IntegrityMode::FULL:
            return "full";
        default:
            return "unknown";
    }
}

} // namespace NativeRdb
} // namespace OHOS
