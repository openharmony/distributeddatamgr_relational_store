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

#include <sys/stat.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <sstream>

#include "logger.h"
#include "rdb_audit_logger_manager.h"
#include "rdb_db_info_manager.h"
#include "rdb_db_logger_manager.h"
#include "rdb_platform.h"
#include "rdb_time_utils.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

namespace {
constexpr const char *AUDIT_DIR_SA_ROOT = "/data/log/hiaudit/rdb";
constexpr const char *AUDIT_DIR_APP_ROOT = "/data/storage/el2/log";
constexpr const char *AUDIT_DIR_APP_SUB = "rdb";
constexpr int64_t THROTTLE_INTERVAL_MS = 60 * 1000; // 60 s
constexpr size_t THROTTLE_MAP_MAX_SIZE = 64;

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
        LOG_ERROR("ProbeAuditDir: mkdir failed, path=%{public}s, errno=%{public}d", path.c_str(), errno);
        return false;
    }
    return true;
}

// Create the full directory path, only creating segments under known audit roots
// (skipping system directories like /data, /data/log that this component does not own).
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
        if (IsUnderAuditRoot(sub) && !TryMkDir(sub)) {
            return false;
        }
    }
    return TryMkDir(path);
}

// Probe the shared audit root directory (SA root first, then app log root).
// Returns "" when neither root exists (audit disabled). Called once per façade
// Init; the result is passed to both singleton managers.
std::string ProbeAuditDir()
{
    struct stat st;
    if (stat(AUDIT_DIR_SA_ROOT, &st) == 0 && S_ISDIR(st.st_mode)) {
        int32_t uid = static_cast<int32_t>(GetUid());
        return std::string(AUDIT_DIR_SA_ROOT) + "/" + std::to_string(uid) + "/";
    }
    if (stat(AUDIT_DIR_APP_ROOT, &st) == 0 && S_ISDIR(st.st_mode)) {
        std::string dir = std::string(AUDIT_DIR_APP_ROOT) + "/" + AUDIT_DIR_APP_SUB + "/";
        if (MkDirP(dir)) {
            return dir;
        }
        return "";
    }
    LOG_INFO("ProbeAuditDir: no audit directory available, audit disabled");
    return "";
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

void WriteFileInfo(std::ostringstream &os, const char *label, const FileInfo &fi)
{
    os << "\"" << label << "\":{\"inode\":" << fi.node
       << ",\"atime\":\"" << EscapeJson(fi.time.atime) << "\""
       << ",\"mtime\":\"" << EscapeJson(fi.time.mtime) << "\""
       << ",\"ctime\":\"" << EscapeJson(fi.time.ctime) << "\""
       << ",\"size\":" << fi.size
       << ",\"perm\":{\"mode\":\"" << EscapeJson(fi.permission.mode) << "\",\"acl\":\""
       << EscapeJson(fi.permission.acl) << "\"}}";
}
} // namespace

void RdbAuditLogger::EnsureInit(const std::string &dbPath)
{
    dbPath_ = dbPath;
    if (RdbAuditLoggerManager::GetInstance().IsInitialized()) {
        enabled_ = true;
        return;
    }
    std::string auditDir = ProbeAuditDir();
    if (auditDir.empty()) {
        enabled_ = false;
        return;
    }
    RdbAuditLoggerManager::GetInstance().Init(auditDir, true);
    RdbDbLoggerManager::GetInstance().Init(auditDir, true);
    enabled_ = true;
}

void RdbAuditLogger::OnOpenOk(const std::string &dbPath, bool created, bool auditEnabled)
{
    if (!auditEnabled) {
        return;
    }
    EnsureInit(dbPath);
    if (!IsActive()) {
        return;
    }
    std::string path = dbPath;
    bool crt = created;
    RdbAuditLoggerManager::GetInstance().ExecuteAsync([path, crt]() {
        RdbAuditLoggerManager::GetInstance().AppendEventSync(BuildOpenOkJson(path));
        LastOpenDbInfo lastOpen = RdbDbInfoManager::GetInstance().BuildLastOpen(path, crt);
        RdbDbLoggerManager::GetInstance().RecordOpenSync(path, lastOpen);
    });
}

void RdbAuditLogger::OnOpenFail(const std::string &dbPath, int rc, int osErrno, bool auditEnabled)
{
    if (!auditEnabled) {
        return;
    }
    EnsureInit(dbPath);
    if (!IsActive()) {
        return;
    }
    std::string path = dbPath;
    int r = rc;
    int os = osErrno;
    RdbAuditLoggerManager::GetInstance().ExecuteAsync([path, r, os]() {
        RdbAuditLoggerManager::GetInstance().AppendEventSync(BuildOpenFailJson(path, r, os));
    });
}

void RdbAuditLogger::OnIoError(
    const std::string &op, const std::string &file, int rc, int osErrno, bool auditEnabled)
{
    if (!auditEnabled) {
        return;
    }
    EnsureInit(file);
    if (!IsActive()) {
        return;
    }
    std::string o = op;
    std::string f = file;
    int r = rc;
    int os = osErrno;
    RdbAuditLoggerManager::GetInstance().ExecuteAsync([o, f, r, os]() {
        IoErrorInfo ioError;
        ioError.op = o;
        ioError.rc = r;
        ioError.osErrno = os;
        ioError.callerInfo = RdbDbInfoManager::GetInstance().CollectCaller();
        ioError.time = RdbTimeUtils::GetCurSysTimeWithMs();
        RdbDbLoggerManager::GetInstance().WriteIoErrorSync(f, ioError);
    });
}

void RdbAuditLogger::OnSqlAudit(
    const std::string &dbPath, const std::string &op, const std::string &tbl, int64_t rows, bool auditEnabled)
{
    if (!auditEnabled) {
        return;
    }
    EnsureInit(dbPath);
    if (!IsActive() || !enableSqlAudit_) {
        return;
    }
    bool alwaysLog = (op == "DELETE" || op == "DROP" || op == "TRUNCATE");
    if (alwaysLog) {
        if (op == "DELETE" && rows <= 0) {
            return;
        }
        std::string path = dbPath;
        std::string o = op;
        std::string t = tbl;
        int64_t r = rows;
        RdbAuditLoggerManager::GetInstance().ExecuteAsync([path, o, t, r]() {
            RdbAuditLoggerManager::GetInstance().AppendEventSync(BuildSqlAuditJson(path, o, t, r));
        });
        return;
    }
    if (rows <= 0) {
        return;
    }
    // Throttle stays sync (uses per-instance throttleMap_); only the write is async.
    std::string eventKey = "SQL_AUDIT:" + op + ":" + tbl;
    int64_t flushRows = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (AccumulateOrFlush(eventKey, rows, flushRows)) {
            return;
        }
    }
    if (flushRows > 0) {
        std::string path = dbPath;
        std::string o = op;
        std::string t = tbl;
        RdbAuditLoggerManager::GetInstance().ExecuteAsync([path, o, t, flushRows]() {
            RdbAuditLoggerManager::GetInstance().AppendEventSync(BuildSqlAuditJson(path, o, t, flushRows));
        });
    }
}

void RdbAuditLogger::OnIntegrity(
    const std::string &dbPath, IntegrityTrigger trigger, IntegrityMode mode, int result, const std::string &err)
{
    EnsureInit(dbPath);
    if (!IsActive()) {
        return;
    }
    std::string path = dbPath;
    IntegrityTrigger tr = trigger;
    IntegrityMode m = mode;
    int r = result;
    std::string e = err;
    RdbAuditLoggerManager::GetInstance().ExecuteAsync([path, tr, m, r, e]() {
        RdbAuditLoggerManager::GetInstance().AppendEventSync(BuildIntegrityJson(path, tr, m, r, e));
    });
}

void RdbAuditLogger::OnCorrupt(
    const std::string &dbPath, int rc, int osErrno, const std::string &detail)
{
    EnsureInit(dbPath);
    if (!IsActive()) {
        return;
    }
    std::string path = dbPath;
    int r = rc;
    int os = osErrno;
    std::string d = detail;
    RdbAuditLoggerManager::GetInstance().ExecuteAsync([path, r, os, d]() {
        CorruptInfo corrupt;
        corrupt.rc = r;
        corrupt.osErrno = os;
        corrupt.detail = d;
        corrupt.files = RdbDbInfoManager::GetInstance().CollectDbFileInfo(path);
        corrupt.callerInfo = RdbDbInfoManager::GetInstance().CollectCaller();
        corrupt.time = RdbTimeUtils::GetCurSysTimeWithMs();
        RdbDbLoggerManager::GetInstance().WriteCorruptSync(path, corrupt);
    });
}

void RdbAuditLogger::OnDbDelete(const std::string &dbPath, const std::string &op, bool auditEnabled)
{
    if (!auditEnabled) {
        return;
    }
    EnsureInit(dbPath);
    if (!IsActive()) {
        return;
    }
    std::string path = dbPath;
    std::string o = op;
    RdbAuditLoggerManager::GetInstance().ExecuteAsync([path, o]() {
        DeleteInfo del;
        del.files = RdbDbInfoManager::GetInstance().CollectDbFileInfo(path);
        del.callerInfo = RdbDbInfoManager::GetInstance().CollectCaller();
        del.time = RdbTimeUtils::GetCurSysTimeWithMs();
        RdbDbLoggerManager::GetInstance().WriteDeleteSync(path, del);
    });
}

bool RdbAuditLogger::AccumulateOrFlush(const std::string &eventKey, int64_t rows, int64_t &flushRows)
{
    flushRows = 0;
    int64_t now = NowMs();
    auto it = throttleMap_.find(eventKey);
    if (it != throttleMap_.end() && (now - it->second.timestamp) < THROTTLE_INTERVAL_MS) {
        it->second.accumulatedRows += rows;
        return true;
    }
    if (it != throttleMap_.end()) {
        flushRows = it->second.accumulatedRows;
    }
    throttleMap_[eventKey] = {now, rows};
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

std::string RdbAuditLogger::BuildOpenOkJson(const std::string &dbPath)
{
    std::string ts = RdbTimeUtils::GetCurSysTimeWithMs();
    auto caller = RdbDbInfoManager::GetInstance().CollectCaller();
    auto fileInfo = RdbDbInfoManager::GetInstance().CollectDbFileInfo(dbPath);
    auto slaveInfo = RdbDbInfoManager::GetInstance().CollectDbFileInfo(SqliteUtils::GetSlavePath(dbPath));
    std::string dbName = SqliteUtils::Anonymous(SqliteUtils::GetDbName(dbPath));
    std::ostringstream os;
    os << "{\"evt\":\"OPEN\",\"ts\":\"" << EscapeJson(ts) << "\""
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
    std::string dbName = SqliteUtils::Anonymous(SqliteUtils::GetDbName(dbPath));
    std::ostringstream os;
    os << "{\"evt\":\"OFAIL\",\"ts\":\"" << EscapeJson(ts) << "\""
       << ",\"db_name\":\"" << EscapeJson(dbName) << "\""
       << ",\"proc\":\"pid:" << caller.pid << ":tid:" << caller.tid << "\""
       << ",\"rc\":" << rc << ",\"os_errno\":" << osErrno << ",\"path\":\""
       << EscapeJson(SqliteUtils::Anonymous(dbPath)) << "\"}";
    return os.str();
}

std::string RdbAuditLogger::BuildSqlAuditJson(
    const std::string &dbPath, const std::string &op, const std::string &tbl, int64_t rows)
{
    std::string ts = RdbTimeUtils::GetCurSysTimeWithMs();
    auto caller = RdbDbInfoManager::GetInstance().CollectCaller();
    std::string dbName = SqliteUtils::Anonymous(SqliteUtils::GetDbName(dbPath));
    std::ostringstream os;
    os << "{\"evt\":\"SQL\",\"ts\":\"" << EscapeJson(ts) << "\""
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
    std::string dbName = SqliteUtils::Anonymous(SqliteUtils::GetDbName(dbPath));
    std::ostringstream os;
    os << "{\"evt\":\"IGR\",\"ts\":\"" << EscapeJson(ts) << "\""
       << ",\"db_name\":\"" << EscapeJson(dbName) << "\""
       << ",\"trigger\":\"" << TriggerToStr(trigger) << "\""
       << ",\"mode\":\"" << ModeToStr(mode) << "\""
       << ",\"result\":" << result << ",\"err\":\"" << EscapeJson(err) << "\""
       << ",\"path\":\"" << EscapeJson(SqliteUtils::Anonymous(dbPath)) << "\"}";
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
